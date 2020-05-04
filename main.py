import ipwhois
import re
import subprocess
import socket
from bs4 import BeautifulSoup
from time import sleep
import requests


def getLocation(ip):
    url = 'https://whatismyipaddress.com/ip/{}'.format(ip)
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    location = soup.find_all('meta')[1]
    return re.findall(r'Location: .+-', str(location))[0]


ipAdress = socket.gethostbyname(socket.gethostname())
proc = subprocess.Popen('sudo tcpdump -nn -i en0 udp',
                        shell=True, stdout=subprocess.PIPE)

while proc.poll() is None:
    output = proc.stdout.readline().decode('utf-8')
    foreignIp = re.findall(r'> .+:', output)
    if len(foreignIp) == 0:
        break
    ipsNotSplitted = re.split(r' ', foreignIp[0])[1]
    ipsSplitted = re.split(r'\.', ipsNotSplitted)
    ipsSplitted.pop()
    ips = '.'.join(ipsSplitted)

    if ips != ipAdress:
        try:
            ipLookup = ipwhois.IPWhois(ips).lookup_whois()
            #Blocked UDP connections for example google
            if ipLookup["nets"][0]["country"] != 'US':
                print('-' * 60)
                print('ip: {}'.format(ips))
                print('country: {}'.format(
                    ipLookup["asn_country_code"]))
                print('Address: {}'.format(
                    ipLookup["nets"][0]["address"]))
                print('Name: {}'.format(
                    ipLookup["nets"][0]["name"]))
                print('city: {}'.format(
                    ipLookup["nets"][0]["city"]))
                print('state: {}'.format(
                    ipLookup["nets"][0]["state"]))
                print(getLocation(ips))
                print('-'*60)
                sleep(5)
        except:
            print(ips)
            print('problem')
