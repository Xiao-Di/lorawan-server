import os
import json


client_addr = "127.0.0.1"
port = 12255

http_url = 'http://10.3.242.234:12345'

MIC_len = 4

# device & gateway
# joineui = "0101010101010102"
deveui = "0202020202020203"
appkey = "0102030405060708090a0b0c0d0e0f22"
nwkkey = "0102030405060708090a0b0c0d0e0f11"
# GatewayEUI = "1111111111111111"

# server
homenetid = "000001"  # 3 bytes
# devaddr = "00a1d920"  # 4 bytes

rx1droffset = 0  # 3 bits
rx2datarate = 0  # 4 bits
rxdelay = 1  # 1 byte \x10
