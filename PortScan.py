# -*- coding: utf-8 -*-
"""
Created on Sun Oct  7 17:31:10 2018

@author: wmy
"""

import optparse
import socket
import nmap
import threading

def nmapScan(targetHost, targetPorts):
    host = socket.gethostbyname(targetHost)
    try:
        nmScanner = nmap.PortScanner()
    except:
        print('Error: nmap is not found!')
        return
    for port in targetPorts:
        if type(port) == type(""):
            results = nmScanner.scan(host, port)
            state = results['scan'][host]['tcp'][int(port)]['state']
            print("[*] " + host + " tcp/" + port + " " + state)
        else:
            print('Error: targetPorts should be a string list')
            pass
        pass
    pass

host = 'www.baidu.com'
ports = ['80', '443', '3389', '1433', '23']

nmapScan(host, ports)

screenLock = threading.Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print('[+]%d/tcp open' % tgtPort)
        print('[+] ' + str(results))
    except:
        screenLock.acquire()
        print('[-]%d/tcp closed' % tgtPort)
    finally:
        screenLock.release()
        connSkt.close()
        pass
    pass

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % tgtHost)
        return
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ' + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)
    socket.setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print('Scanning port ' + str(tgtPort))
        t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()
        pass
    pass

portScan('www.baidu.com', [80, 443, 3389, 1433, 23])
