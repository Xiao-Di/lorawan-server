#!/usr/bin/env python

import base64
import struct
import secrets
import bytes

from Crypto.Cipher import AES
from Crypto.Hash import CMAC



def parse_bytes(typ, fmt, data):
    try:
        return struct.unpack(fmt, data)
    except struct.error:
        raise StructParseError(typ, fmt, data) from None

class Register:
    """
    注册过程 生成密钥
    """
    def __init__(self, joineui, deveui, appkey, nwkkey):
        self.joineui = bytes.fromhex(joineui)
        self.deveui = bytes.fromhex(deveui)
        self.appkey = bytes.fromhex(appkey)
        self.nwkkey = bytes.fromhex(nwkkey)
        
        self.txdr = 5  # Uplink data rate index
        self.txch = 1  # Channel index
        
        self.gen_jskeys()
        self.activation = False
        self.activation_mode = 'OTAA'
        self.ack = False
        self.version = "1.1"
        self.msg_file = "message.json"
        # self.save()
        
    def _initialize_session(self): # 私有方法
        """
        Initialize session context according to optneg flag
        Args:
            optneg: 0 or 1
        Returns:
            None
        """
        # if optneg:
        # Server supports LoRaWAN 1.1 and later
        # Generate FNwkSIntKey, SNwkSIntKey, NwkSEncKey and AppSKey
        nwkskey_prefix = b''.join([
            self.joinnonce[::-1],
            self.joineui[::-1],
            self.devnonce[::-1],
        ])
        fnwksint_msg, snwksint_msg, nwksenc_msg = [
            (prefix + nwkskey_prefix).ljust(AES_BLOCK, b'\x00')
            for prefix in (b'\x01', b'\x03', b'\x04')
        ]
        self.fnwksintkey, self.snwksintkey, self.nwksenckey = self.gen_keys(
            self.nwkkey, (fnwksint_msg, snwksint_msg, nwksenc_msg)
        )
        appsmsg = b''.join([
            b'\x02',
            self.joinnonce[::-1],
            self.joineui[::-1],
            self.devnonce[::-1],
        ]).ljust(AES_BLOCK, b'\x00')
        self.appskey, = self.gen_keys(self.appkey, (appsmsg,))

        self.fcntup = self.rjcount0 = 0
        self.activation = True
        # self.save()