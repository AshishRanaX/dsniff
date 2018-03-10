#simple python dns server
import socket
from os import popen,system
from dns import resolver
from requests import get



res=resolver.Resolver()
res.nameservers=['8.8.8.8','8.8.4.4']
res.timeout = 3
res.lifetime = 3

with open('web_list') as f:
    wlist=f.read().splitlines()


system("if [ ! -d 'logs' ];then  mkdir logs; fi")

def chk_wlist(site,mac):
  
  flag=0
  for s_site in site.split("."):
    if s_site in wlist:
      flag=1
  if(flag==1):
    notification_system(mac,site)
  
  return flag

def ret_mac(ip):
  popen("ping -c 1 "+ip)
  s=popen("arp -n "+ip).read()
  try:
    mac=s.split(" ")[59]
  except IndexError:
    mac=ip
  return mac

def notification_system(mac,site):
  #This function will be called
  #whenever someone in your network tries to surf website in wlist
  #you can write whatever you want to ,
  #eg. mailing api, SMS , or anything
  

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''

    tipo = (ord(data[2]) >> 3) & 15   
    if tipo == 0:                     
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.domain+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def respuesta(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'
      packet+=self.data[12:]                                      
      packet+='\xc0\x0c'                                          
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'          
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
    return packet

if __name__ == '__main__':

  print 'Mini DNS Server'
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  
  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      src_addr=addr[0]
      p=DNSQuery(data)
      mac_a=ret_mac(src_addr)
      chk_wlist(p.domain,mac_a)
        
      try:
        ip=res.query(p.domain)[0].address
        system('echo $(date +%Y-%m-%d.%H:%M:%S),'+p.domain+' >> logs/'+mac_a)   
        udps.sendto(p.respuesta(ip), addr)
        print 'Request: %s -> %s' % (p.domain, ip)
      except:
        print 'Request: %s -> failed' % (p.domain)
  except KeyboardInterrupt:
    print 'Stopping DNS Server'
udps.close()
