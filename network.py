import asyncio
import struct
import base64
import secrets
import json
import random
import time
import requests
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import config
from exceptions import StructParseError, MICError

MIC_LEN = 4
TOKEN_LEN = 2
PULLDATA_LEN = 12
JOINNONCE_LEN = 3
DEVADDR_LEN = 4
CFLIST_LEN = 16
AES_BLOCK = 16


# def http_post(url, content, state='register'):
#     '''
#     state in ['register', 'join', 'app']
#     '''
#     register_data = {
#         'deveui': config.deveui,
#         'appkey': config.appkey,
#         'nwkkey': config.nwkkey,
#     }
#     if state == 'register':
#         http_data = register_data
#     else:
#         http_data = content
#     http_data.update({'state': state})
#     print(f'\n\n***** HTTP {state.capitalize()} Process *****')
#     r = requests.post(url, json.dumps(http_data))
#     print(r.text)
#     print(f'***** HTTP {state.capitalize()} Process Done *****\n\n')

def http_post(url, content, max_round=50, state='register'):
    '''
    state in ['register', 'join', 'app']
    '''
    register_data = {
        'deveui': config.deveui,
        'appkey': config.appkey,
        'nwkkey': config.nwkkey,
    }
    # 注册过程
    if state == 'register':
        http_data = register_data
        http_data.update({'state': state})
        print(f'\n\n***** HTTP {state.capitalize()} Process *****')
        r = requests.post(url, json.dumps(http_data))
        print(r.text)
        print(f'***** HTTP {state.capitalize()} Process Done *****\n\n')
    # join 或 app过程(锴哥需求: 一直上发消息)
    else:
        http_data = content
        http_data.update({'state': state})
        print(f'\n\n***** HTTP {state.capitalize()} Process *****')
        for i in range(max_round):
            print("*** Sending {i} out of {max_round} message ***")
            r = requests.post(url, json.dumps(http_data))
            print(r.text)
            wait_time = randome(0, 2)
            print("Waiting time: {wait_time}s.")
            time.sleep(wait_time)
        print(f'***** HTTP {state.capitalize()} Process Done *****\n\n')

def parse_byte(data: bytes, name: list, offset: list, bitlength: list):
    """
    Parse one-byte data into several fields by bits
    Args:
        data: Original one-byte data
        name: List of names for each field
        offset: Offset number of each field
        bitlength: Bit length of each field

    Returns:
        A list of field values in integer
    """
    assert len(name) == len(offset) == len(bitlength)
    data = int.from_bytes(data, byteorder='little')  # 反序 小端字节
    res = [0 for _ in range(len(name))]
    for ind, value in enumerate(name):
        off, leng = offset[ind], bitlength[ind]
        binmask = '1'*leng + '0'*off
        mask = int(binmask, base=2)
        res[ind] = (data & mask) >> off
    return res


def parse_bytes(typ, fmt, data):
    """
    data in binary
    """
    try:
        return struct.unpack(fmt, data)
    except struct.error:
        raise StructParseError(typ, fmt, data) from None


def calcmic_app(self, msg, direction=0, fcnt=0):
    """
    Calculate the MIC field for uplink and downlink application data
    Args:
        msg: PHYPayload[:-4]
        direction: int object, 0 for uplink and 1 for downlink
        fcnt: Necessary only for downlink data
    Returns:
        A 4-byte length bytes object of MIC field

    Downlink MIC B0:
    ------------------------------------------------------------------------------
    | 0x49 | ConfFCnt | 0x0000 | dir | DevAddr | AF(NF)CntDown | 0x00 | len(msg) |
    ------------------------------------------------------------------------------
    Downlink key: SNwkSIntKey

    Uplink MIC B0:
    ----------------------------------------------------------------
    | 0x49 | 0x00000000 | dir | DevAddr | FCntUp | 0x00 | len(msg) |
    ----------------------------------------------------------------
    B0 key: FNwkSIntKey

    B1:
    ----------------------------------------------------------------------------
    | 0x49 | ConfFCnt | TxDr | TxCh | dir | DevAddr | FCntUp | 0x00 | len(msg) |
    ----------------------------------------------------------------------------
    B1 key: SNwkSIntKey
    """
    msglen = len(msg)
    B_f = '<cHBBB4sIBB'
    if direction == 0:
        fcnt = self.fcntup
        key = self.fnwksintkey
    else:
        key = self.snwksintkey

    conffcnt = fcnt if (self.ack and direction == 1) else 0
    B0_elements = [
        b'\x49',
        conffcnt,
        0,
        0,
        direction,
        self.devaddr[::-1],  # 反序
        fcnt,
        0,
        msglen
    ]
    B0 = struct.pack(
        B_f,
        *B0_elements,
    )
    fmsg = B0 + msg
    fcmacobj = CMAC.new(key, ciphermod=AES)
    fcmac = fcmacobj.update(fmsg)
    if direction == 0:  # uplink
        B1_elements = B0_elements[:]
        conffcnt = fcnt if self.ack else 0
        B1_elements[1:4] = [conffcnt, self.txdr, self.txch]
        B1 = struct.pack(
            B_f,
            *B1_elements,
        )
        smsg = B1 + msg
        scmacobj = CMAC.new(self.snwksintkey, ciphermod=AES)
        scmac = scmacobj.update(smsg)
        print('msg: \nB0: {} \nB1: {}\n'.format(
            fmsg.hex(),
            smsg.hex(),
        ))
        return scmac.digest()[:MIC_LEN//2] + fcmac.digest()[:MIC_LEN//2]
    else:  # downlink
        return fcmac.digest()[:MIC_LEN]


class EchoServerProtocol:
    """
    asynchronous UDP server
    """

    def __init__(self, **kwargs):
        # self.homenetid = bytes.fromhex(config.homenetid)
        self.deveui = bytes.fromhex(config.deveui)
        self.appkey = bytes.fromhex(config.appkey)
        self.nwkkey = bytes.fromhex(config.nwkkey)
        self.pulldata_f = '<s2ss8s'
        self.pushack_f = self.pullack_f = '<s2ss'
        self.txdr = 1
        self.txdr2datr = {
            0: 'SF12BW125',
            1: 'SF11BW125',
            2: 'SF10BW125',
            3: 'SF9BW125',
            4: 'SF8BW125',
            5: 'SF7BW125',
            6: 'SF7BW250',
            7: 50000,  # FSK modulation
        }
        self.gen_jskeys()

    def _initialize_session(self, optneg=1):
        """
        Initialize session context according to optneg flag
        Args:
            optneg: 0 or 1
        Returns:
            None
        """
        if optneg:
            # Server supports LoRaWAN 1.1 and later
            # Generate FNwkSIntKey, SNwkSIntKey, NwkSEncKey and AppSKey
            if self.joinreq_type == b'\xFF':  # join request
                nwkskey_prefix = b''.join([
                    self.joinnonce[::-1],
                    self.joineui[::-1],
                    self.devnonce[::-1],
                ])
            else:
                nwkskey_prefix = b''.join([
                    self.joinnonce,
                    self.joineui,
                    bytes(2),
                ])
            fnwksint_msg, snwksint_msg, nwksenc_msg = [
                (prefix + nwkskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x01', b'\x03', b'\x04')  # L 1603
            ]
            self.fnwksintkey, self.snwksintkey, self.nwksenckey = self.gen_keys(
                self.nwkkey, (fnwksint_msg, snwksint_msg, nwksenc_msg)
            )
            print('fnwksintkey: ', self.fnwksintkey.hex())
            print('snwksintkey: ', self.snwksintkey.hex())
            print('nwksenckey: ', self.nwksenckey.hex())

            appsmsg = b''.join([
                b'\x02',
                self.joinnonce[::-1],
                self.joineui[::-1],
                self.devnonce[::-1],
            ]).ljust(AES_BLOCK, b'\x00')
            self.appskey, = self.gen_keys(self.appkey, (appsmsg,))
            print('appskey: ', self.appskey.hex())
        else:
            # Server only supports LoRaWAN 1.0
            sesskey_prefix = b''.join([
                self.joinnonce[::-1],
                self.homenetid[::-1],
                self.devnonce[::-1],
            ])
            apps_msg, fnwksint_msg = [
                (prefix + sesskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x02', b'\x01')
            ]
            self.appskey, self.fnwksintkey = self.gen_keys(
                self.nwkkey, (apps_msg, fnwksint_msg))
            self.snwksintkey = self.nwksenckey = self.fnwksintkey
        self.fcntup = self.rjcount0 = 0
        self.activation = True
        # self.save()

    def gen_keys(self, root, keymsgs: tuple, mode=AES.MODE_ECB):
        """
        Generate necessary keys
        Args:
            root: Root key, could be appkey or nwkkey
            keymsgs: Messages used to generate keys
            mode: AES mode, no need to change
        Returns:
            A list(even one key) of keys
        """
        cryptor = AES.new(root, mode)
        return [cryptor.encrypt(msg) for msg in keymsgs]

    def gen_jskeys(self):
        """
        Generate JS Int & Enc keys
        ------------------------------
        | 0x06 \ 0x05 | DevEUI | pad |
        ------------------------------
        |    1 byte   | 8 bytes|  -  |
        ------------------------------
        """
        # print(b'\x06' + self.deveui[::-1])
        jsintkeymsg, jsenckeymsg = [
            (prefix + self.deveui[::-1]).ljust(AES_BLOCK, b'\x00')
            for prefix in (b'\x06', b'\x05')  # L 1372
        ]
        self.jsintkey, self.jsenckey = self.gen_keys(
            self.nwkkey, (jsintkeymsg, jsenckeymsg))

    def pullack_process(self):
        # identifier = data[3]
        # if identifier == 2:
        pull_data = self.data
        self.version, token, identifier, gweui = parse_bytes(
            'PULL DATA', self.pulldata_f, pull_data
        )
        pull_ack = struct.pack(
            self.pullack_f, self.version, token, b'\x04'
        )
        print('Sending pullack %r to %s port %d' %
              (pull_ack.hex(), self.ip, self.port))
        self.transport.sendto(pull_ack, self.addr)

    def get_phypld(self, data):
        push_data = data
        print("push data: ", type(push_data), push_data)
        print("Push payload length %d bytes." % (len(push_data)-12))
        pushdata_f = self.pulldata_f + '{}s'.format(len(push_data) - 12)
        self.version, push_token, identifier, gweui, push_pld = parse_bytes(
            'PUSH DATA', pushdata_f, push_data
        )
        decoded_push_pld = json.loads(push_pld.decode('ascii'))
        rxpk = decoded_push_pld['rxpk']
        payload = rxpk[0]['data'].encode()  # str --> bytes
        # join: b'AAEAAAAAAAAAAQAAAAAAAADfY9Dd1hQ='
        print('encoded data: ', payload)
        payload = base64.b64decode(payload)  # 如果是join req长度应该是23bytes
        # join: b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdfc\xd0\xdd\xd6\x14'
        print('base64 decode data: ', payload.hex())
        print('base64 decoded data length: %d bytes\n' % len(payload))
        return push_token, payload

    def parse_mhdr(self, mhdr):
        """
        Parse MHDR byte
        Args:
            mhdr: MHDR field
        Returns:
            A proxy of dict values, the field order sticks to the protocol

        MHDR:
        -----------------------
        | MType | RFU | Major |
        -----------------------
        |  000  | 000 |  00   |
        -----------------------
        """
        name = ('mtype', 'rfu', 'major')
        bitlength = (3, 3, 2)
        offset = (5, 2, 0)
        return parse_byte(mhdr, name=name, bitlength=bitlength, offset=offset)

    @property
    def joinenckey(self):
        print('joinreq type: ', self.joinreq_type.hex())
        return self.nwkkey if self.joinreq_type == b'\xFF' else self.jsenckey

    def parse_joinreq(self, mhdr, macpld, mic):
        print("----------Receiving a Join Requst Msg----------")
        self.joinreq_f = '<8s8s2s'
        self.joinreq_type = b'\xFF'
        self.joineui, self.deveui, self.devnonce = parse_bytes(
            "JOIN REQ", self.joinreq_f, macpld
        )
        self.joineui = self.joineui[::-1]
        self.deveui = self.deveui[::-1]
        self.devnonce = self.devnonce[::-1]
        print("JoinEUI: ", self.joineui.hex())
        print("DevEUI: ", self.deveui.hex())
        print("DevNonce: ", self.devnonce.hex())
        joinreq_msg = struct.pack(
            '<s8s8s2s',
            mhdr,
            self.joineui[::-1],
            self.deveui[::-1],
            self.devnonce[::-1]
        )
        cmic = self.calcmic_join(
            key=self.nwkkey,
            macpld=joinreq_msg,)
        print("CMIC: ", cmic.hex())
        if (cmic == mic):
            print("--------Join request MIC VERIFIED!!!--------\n")
        else:
            raise MICError('Join Request', mic, cmic)

    def pushack_process(self, push_token):
        push_ack = struct.pack(
            self.pushack_f, self.version, push_token, b'\x01'
        )
        print('Sending pushack %r to %s port %d' %
              (push_ack.hex(), self.ip, self.port))
        self.transport.sendto(push_ack, self.addr)

    def calcmic_join(self, key, macpld, optneg=0):
        """
        Calculate the MIC field for join-related data (join request, accept and rejoin)
        Args:
            key: Key used to CMAC
            macpld: MACPayload of join related messages
            optneg: Flag of LoRaWAN version (and the type of accept message)
        Returns:
            A 4-byte length bytes object of MIC field

        Join request MIC fields:
        --------------------------------------
        | MHDR | JoinEUI | DevEUI | DevNonce |
        --------------------------------------
        |1 byte| 8 bytes |8 bytes |  2 bytes |
        --------------------------------------
        Key: NwkKey

        Rejoin 0 & 2 MIC fields:
        --------------------------------------------------
        | MHDR | Rejoin Type | NetID | DevEUI | RJcount0 |
        --------------------------------------------------
        |1 byte|    1 byte   |3 bytes|8 bytes |  2 bytes |
        --------------------------------------------------
        Key: SNwkSIntKey

        Rejoin 1 MIC fields:
        ----------------------------------------------------
        | MHDR | Rejoin Type | JoinEUI | DevEUI | RJcount1 |
        ----------------------------------------------------
        |1 byte|    1 byte   | 8 bytes |8 bytes | 2 bytes  |
        ----------------------------------------------------
        Key: JSIntKey

        Join accept MIC fields (OptNeg = 0, LoRaWAN 1.0):
        ----------------------------------------------------------------------
        | MHDR | JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList |
        ----------------------------------------------------------------------
        |1 byte|  3 bytes  |3 bytes| 4 bytes |   1 byte   |  1 byte | 0 ~ 15 |
        ----------------------------------------------------------------------
        Key: NwkKey

        The MACPayload can be directly used of upper messages.

        Join accept MIC fields (OptNeg = 1, LoRaWAN 1.1):
        -------------------------------------------------------------
        | JoinReqType | JoinEUI | DevNonce | MHDR | JoinNonce | NetID ...
        -------------------------------------------------------------
        |   1 byte    | 8 bytes | 2 bytes  |1 byte|  2 bytes  | Same above
        -------------------------------------------------------------
        Key: JSIntKey
        """
        if optneg:
            acptopt_f = '<s8s2s'
            macpld = struct.pack(
                acptopt_f,
                self.joinreq_type,
                self.joineui[::-1],
                self.devnonce[::-1],
            ) + macpld
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(macpld)
        return cobj.digest()[:MIC_LEN]

    def form_dlsettings(self, optneg=1):
        if optneg:
            # self.dlsettings = bytes.fromhex(
            # str(optneg)+config.rx1droffset+config.rx2datarate)
            dlsettings = (optneg << 7) + (config.rx1droffset
                                          << 4) + config.rx2datarate  # int
        return dlsettings.to_bytes(1, 'big')

    def form_joinacpt(self, optneg=1, cflist_option=True):
        """
        Join Accept:
        --------------------------------------------------------------------
        | JoinNonce | Home_NetID | DevAddr | DLSettings | RxDelay | CFList |
        --------------------------------------------------------------------
        |  3 bytes  |   3 bytes  | 4 bytes |   1 byte   | 1 byte  |  (16)  |
        --------------------------------------------------------------------
        """
        print('----------Forming Join Acpt--------')
        mhdr = b'\x20'  # 00100000
        self.joinnonce = secrets.token_bytes(JOINNONCE_LEN)
        """ TODO: 
        The device SHALL accept the Join-accept only if the MIC field is correct 
        and the JoinNonce is strictly greater than the recorded one.
        """
        self.homenetid = bytes.fromhex(config.homenetid)
        self.devaddr = secrets.token_bytes(DEVADDR_LEN)
        self.dlsettings = self.form_dlsettings(optneg)
        self.rxdelay = config.rxdelay.to_bytes(1, 'big')
        joinacpt_mic_key = self.jsintkey if optneg else self.nwkkey
        print('JoinNonce: ', self.joinnonce.hex())
        print('HomeNetID: ', self.homenetid.hex())
        print('DevAddr: ', self.devaddr.hex())
        print('DLSettings: ', self.dlsettings.hex())
        print('RxDelay: ', self.rxdelay.hex())
        joinacpt_f = '<3s3s4sss'
        if not cflist_option:
            # joinacpt_f = '<3s3s4sss'
            macpld = struct.pack(
                joinacpt_f,
                self.joinnonce,
                self.homenetid,
                self.devaddr,
                self.dlsettings,
                self.rxdelay,
            )
        else:
            self.cflist = secrets.token_bytes(CFLIST_LEN)
            print('CFList: ', self.cflist.hex())
            joinacpt_f = joinacpt_f + '{}s'.format(CFLIST_LEN)
            macpld = struct.pack(
                joinacpt_f,
                self.joinnonce,
                self.homenetid,
                self.devaddr,
                self.dlsettings,
                self.rxdelay,
                self.cflist,
            )
        macpld_len = len(macpld)
        mic = self.calcmic_join(
            key=joinacpt_mic_key,
            macpld=struct.pack(
                f"<c{macpld_len}s",
                mhdr,
                macpld),
            optneg=optneg,
        )
        print('MIC: ', mic.hex())
        macpldmic_f = '<{}s4s'.format(macpld_len)
        macpldmic = struct.pack(
            macpldmic_f,
            macpld,
            mic,
        )
        encrypted_macpldmic = self.joinacpt_encrypt(macpldmic)
        joinacpt_f = '<s{}s'.format(len(encrypted_macpldmic))
        phypld = struct.pack(
            joinacpt_f,
            mhdr,
            encrypted_macpldmic)
        print("PHYPLD: ", phypld.hex())
        return phypld

    def joinacpt_encrypt(self, macpldmic):
        """
        Encrypt join accept message
        Args:
            macpldmic: bytes of macpayload + mic
        Returns:
            bytes of encrypted join accept message(without mhdr byte)

        Decryption keys:
        ----------------------
        | ReqType |   Key    |
        ----------------------
        |  Join   |  NwkKey  |
        ----------------------
        | Rejoin  | JSEncKey |
        ----------------------
        """
        macpldmic_len = len(macpldmic)
        print("macpldmic befor encryption: ", macpldmic.hex())
        cryptor = AES.new(self.joinenckey, AES.MODE_ECB)
        print('macpldmic after encryption: ', cryptor.encrypt(macpldmic).hex())
        return cryptor.decrypt(macpldmic)

    def add_data(self, txpk, data):
        """
        Add data and data size to txpk
        Args:
            txpk: Dict of txpk lists
            data: Target data
        Returns:
            A dict of complete txpk data
        """
        txpk['txpk'].update({
            'size': len(data),
            'data': data,
        })
        return txpk

    def form_txpk(self):
        """
        Form txpk field
        Args:
            mote: Object of Mote class to get "chan" and "datr" field
        Returns:
            A dict contains txpk key-value
        """
        return {
            'txpk': {
                "imme": True,
                "freq": 864.123456,
                "rfch": 0,
                "powe": 14,
                "modu": 'LORA',
                "datr": self.txdr2datr[self.txdr],
                "codr": '4/6',
                "ipol": False,
                "size": 32,
                "data": '',
            }
        }

    def form_pullresponce_pld(self, data):
        """
        Form payload field of PUSH_DATA
        Args:
            data: data field in txpk
        Returns:
            Payload of the PULL_RESPONCE after ASCII encoding
        """
        data = self.b64data(data)
        payload = self.add_data(self.form_txpk(), data)
        return json.dumps(
            payload
        ).encode('ascii')

    def b64data(self, data):
        """
        base64 encode data, then decode to string by UTF-8
        Args:
            data: bytes data
        Returns:
            A string of base64 encoded data
        """
        return base64.b64encode(data).decode()

    def form_pullresponce(self, data):
        """
        Args:
            data: PHYPayload
        Returns:
            A bytes of complete PULL_RESPONCE, ready to be sent

        PULL_Responce
        -----------------------------------------------
        |   Version    | Token | Identifier | Payload |
        -----------------------------------------------
        | 0x01 or 0x02 |2 bytes|    0x03    |    -    |
        -----------------------------------------------
        """
        payload = self.form_pullresponce_pld(data=data)
        token = secrets.token_bytes(TOKEN_LEN)
        pullresponce_id = b'\x03'
        return b''.join([
            self.version,
            token,
            pullresponce_id,
            payload
        ])

    def join_pullresponce_process(self):
        phypld = self.form_joinacpt(optneg=1, cflist_option=True)
        self._initialize_session(optneg=1)  # 存储join过程的四个key
        print('Sending pull responce %r to %s port %d' %
              (self.form_pullresponce(phypld), self.ip, self.port))
        self.transport.sendto(self.form_pullresponce(phypld), self.addr)

        http_data = {
            'fnwksintkey': self.fnwksintkey.hex(),
            'snwksintkey': self.snwksintkey.hex(),
            'nwksenckey': self.nwksenckey.hex(),
            'appskey': self.appskey.hex(),
            'DevEUI': self.deveui.hex(),
            'JoinEUI': self.joineui.hex(),
            'DevNonce': self.devnonce.hex(),
        }
        http_post(url=config.http_url, content=http_data, state='join')

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # print(data)
        self.data = data
        self.addr = addr
        self.ip, self.port = self.addr

        print('Received %r from %s port %d' %
              (self.data.hex(), self.ip, self.port))
        print("Received data length: %d bytes" % len(self.data))

        # Parse Data
        # 1. identifier --> pull data / push data
        identifier = self.data[3]
        # 1.1 pull data => back pull ack
        if identifier == 2:
            self.pullack_process()

        # 1.2 push data => 解包并校验MIC
        elif identifier == 0:  # b'\x00'
            # parse push data
            push_token, payload = self.get_phypld(data)
            # sending a push ack as soon as receiving a push data(join request)
            self.pushack_process(push_token)

            # payload = memoryview(base64.b64decode(payload))  # 0x bytes
            pld_len = len(payload)
            macpld_len = pld_len - 5  # MHDR: 1 byte  MIC: 4 bytes

            """
            Payload:
            ------------------------------------
            |   MHDR    | MACPayload |   MIC   |
            ------------------------------------
            |  1 bytes  |            | 4 bytes |
            ------------------------------------
            """
            payload_f = '<s{macpldlen}s4s'.format(macpldlen=macpld_len)
            mhdr, macpld, mic = parse_bytes('PHY Payload', payload_f, payload)
            print('MHDR: ', mhdr.hex())
            print("MIC: ", mic.hex())
            # mhdr_bits = BitArray(hex=str(mhdr))
            mtype, rfu, major = self.parse_mhdr(mhdr)
            print("MType in Decimal system: ", mtype)

            if mtype == 0:  # join request(000)
                self.parse_joinreq(mhdr, macpld, mic)
                # sending a pull responce
                self.join_pullresponce_process()

            elif mtype == 6:  # rejoin request(110)
                print("Recieved a Rejoin Request...")
                pass


async def main():
    # config = load_config()
    # target = (config.dest.hostname, config.dest.port)
    # local = (config.src.hostname, config.src.port)
    local = (config.client_addr, config.port)  # local = ("127.0.0.1", 12255)
    print("Starting a UDP server...")

    http_post(url=config.http_url, content={}, state='register')

    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoServerProtocol(),
        local_addr=local)

    try:
        await asyncio.sleep(3600)  # Serve for 1 hour.
    finally:
        transport.close()


asyncio.run(main())
