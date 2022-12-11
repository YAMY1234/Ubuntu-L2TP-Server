# -*- coding: utf-8 -*-
"""
Created on Mon Oct 11 22:10:34 2021

@author: lenovo
"""


import socket

udpsocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sdata = b"cat lend rabblit 5000 dollors!" # 加b是为了将字符串转为字节
saddr=('192.168.18.2',1701)  # 此处的ip应为自己的目标ip, port为端口号
udpsocket.sendto(sdata,saddr)
