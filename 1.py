import numpy as np
# import bytes
import secrets
"""
push payload:  b'{"rxpk": [{"tmst": 1632538981, "chan": 1, "rfch": 1, "freq": 868.3, "stat": 1, "modu": "LORA", "datr": "SF7BW125", "codr": "4/5", "lsnr": 2, "rssi": -119, "size": 32, "data": "AAEAAAAAAAAAAQAAAAAAAAD4YuDFOHg="}], "stat": {"time": "2021-09-25 11:03:01 GMT", "lati": 39.9075, "long": 116.38806, "rxnb": 1, "rxok": 0, "rxfw": 0, "ackr": 0, "dwnb": 0, "txnb": 0}}'
push payload after ascii decoding:  {'rxpk': [{'tmst': 1632538981, 'chan': 1, 'rfch': 1, 'freq': 868.3, 'stat': 1, 'modu': 'LORA', 'datr': 'SF7BW125', 'codr': '4/5', 'lsnr': 2, 'rssi': -119, 'size': 32, 'data': 'AAEAAAAAAAAAAQAAAAAAAAD4YuDFOHg='}], 'stat': {'time': '2021-09-25 11:03:01 GMT', 'lati': 39.9075, 'long': 116.38806, 'rxnb': 1, 'rxok': 0, 'rxfw': 0, 'ackr': 0, 'dwnb': 0, 'txnb': 0}}
Rxpk:  [{'tmst': 1632538981, 'chan': 1, 'rfch': 1, 'freq': 868.3, 'stat': 1, 'modu': 'LORA', 'datr': 'SF7BW125',
    'codr': '4/5', 'lsnr': 2, 'rssi': -119, 'size': 32, 'data': 'AAEAAAAAAAAAAQAAAAAAAAD4YuDFOHg='}]
data:  AAEAAAAAAAAAAQAAAAAAAAD4YuDFOHg=
encoded data:  b'AAEAAAAAAAAAAQAAAAAAAAD4YuDFOHg='
base64 decode data:  b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xf8b\xe0\xc58x'
base64 decoded data length: 23 bytes
"""


print(len("0001000000000000000100000000000000755fcb99494a"))
print(len("AAEAAAAAAAAAAQAAAAAAAAB1X8uZSUo="))

# optneg = 1
# dlsettings = str(optneg)+'000'+'0000'
# print(dlsettings)
# dlsettings_byte = hex(int(dlsettings, 2))
# print(dlsettings_byte)

# print((10).to_bytes(1, 'big').hex())

optneg = 0
if optneg:
    print('optneg is set')

x = 'fe4b'
print(int(x, 16))

# print(byte.fromhex(00))
devnonce = secrets.token_bytes(2)
print(devnonce)

print(hex(771))
print(hex(771)[1])
print(int('3330', 16))


state = 'register'
register_data = {
    'deveui': '000',
    'appkey': '111',
    'nwkkey': '222',
}
register_data.update({'state': state})
print(register_data)
