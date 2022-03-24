import struct
import json
import base64
from exceptions import StructParseError


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


def parse_mhdr(mhdr):
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


def parse_bytes(typ, fmt, data):
    try:
        return struct.unpack(fmt, data)
    except struct.error:
        raise StructParseError(typ, fmt, data) from None


pull_data = b'\x02\x9a\xd1\x02\xe6W\xe8\xff\xfel\xe6P'
# push_data = b'''\x02\x1c\xed\x00\xe6W\xe8\xff\xfel\xe6P
#     {"rxpk": [{"tmst": 1631114151, "chan": 1, "rfch": 1,
#     "freq": 868.3, "stat": 1, "modu": "LORA", "datr": "SF7BW125",
#     "codr": "4/5", "lsnr": 2, "rssi": -119, "size": 32,
#     "data": "AAEAAAAAAAAAAQAAAAAAAACa0cF32ik="}],
#     "stat": {"time": "2021-09-08 23:15:51 GMT", "lati": 39.9075,
#     "long": 116.38806, "rxnb": 1, "rxok": 0, "rxfw": 0, "ackr": 0,
#     "dwnb": 0, "txnb": 0}}'''
push_data = b'''\x02\xfd\xeb\x00\xe6W\xe8\xff\xfel\xe6P
    {"rxpk": [{"tmst": 1631177595, "chan": 1, "rfch": 1, "freq": 868.3, 
    "stat": 1, "modu": "LORA", "datr": "SF7BW125", "codr": "4/5", "lsnr": 2, 
    "rssi": -119, "size": 32, "data": "AAEAAAAAAAAAAQAAAAAAAAAwf96Qe2k="}], 
    "stat": {"time": "2021-09-09 16:53:15 GMT", "lati": 39.9075, 
    "long": 116.38806, "rxnb": 1, "rxok": 0, "rxfw": 0, "ackr": 0, "dwnb": 0, 
    "txnb": 0}}'''
# print(pull_data[3])
# print(len(pull_data))  # 12
print(push_data[3])
print(len(push_data))  # 407

# push_data = memoryview(push_data)
pulldata_f = pullack_f = '<s2ss8s'
identifier = push_data[3]
if identifier == 0:  # b'\x00'
    # parse push data
    pushdata_f = pulldata_f + '{}s'.format(len(push_data) - 12)
    version, token, identifier, gweui, push_pld = parse_bytes(
        'PUSH DATA', pushdata_f, push_data
    )
    decoded_push_pld = json.loads(push_pld.decode('ascii'))
    rxpk = decoded_push_pld['rxpk']
    payload = rxpk[0]['data'].encode()  # str --> bytes
    pld_len = len(payload)
    macpldlen = pld_len - 5
    payload = memoryview(base64.b64decode(payload))  # 0x bytes

    """
    Payload:
    ------------------------------------
    |   MHDR    | MACPayload |   MIC   | 
    ------------------------------------
    |  1 bytes  |            | 4 bytes |   
    ------------------------------------
    """
    payload_f = '<s{macpldlen}s4s'.format(macpldlen=macpldlen)
    mhdr, macpld, mic = parse_bytes('PHY Payload', payload_f, payload)

    # MACPayload = payload[0:-4]
    # msg = payload[:-4]  # used for MIC calculation
    # MIC_origin = payload[-4:]
    # mhdr = payload[0].to_bytes(1, "big")  # int: 0 --> 1 byte

    mtype, rfu, major = parse_mhdr(mhdr)
    print(mtype)
    if mtype == 0:  # join request(000)
        joinreq_f = '<8s8s2s'
        joineui, deveui, devnonce = parse_bytes(
            "JOIN REQ", joinreq_f, macpld
        )
        
    # elif mtype == 6: # rejoin request(110)
