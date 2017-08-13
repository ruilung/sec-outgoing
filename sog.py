import time
import sys
import psutil
import socket
import json
import netaddr
import os.path
#import yaml


def netlisten():
# get listen port and listen program  and return it as a list
    proc_names = {}
    for p in psutil.process_iter():
        try:
            proc_names[p.pid] = p.exe() #full path and program name
        except psutil.AccessDenied:
            proc_names[p.pid] = p.name () #only program name, windows system process will hit this
            pass
        except psutil.Error:
            pass
    netlist=[]
    for c in psutil.net_connections(kind='inet'): #only receive ipv4 info
        if c.status=='LISTEN':
            netlist.append([  ":"+str(c.laddr[1]), proc_names.get(c.pid, '?')])
    #print type(netlist)
    netlist=set( map(tuple,netlist) )
    return sorted(netlist)

def netestablish():
# get establish connection
    estblist=[]
    for c in psutil.net_connections(kind='inet'):
        if c.status <> 'LISTEN' and c.raddr:
            # establish, time_wait, close_wait and so on...
            estblist.append([  ":"+str(c.laddr[1]), c.raddr[0],c.raddr[1]  ] )
    return estblist


def config_create():
#create config file with json format
    port=raw_input("input listen port (80,443...): ")
    portlist=port.split(",")
    for i in portlist:
        try:
            a=int(i)
        except ValueError:
            print "listen port range is 1-65535"
            exit(1)
        if a<0 or a>65535:
            print "error input: "+i
            exit(1)
    zone=raw_input("input trust zones (192.168.1.1/24,172.16.31.1/24): ")
    zonelist=zone.split(",")
    for i in zonelist:
        if not netaddr.valid_nmap_range(i):
            print "error input: "+i
            exit(1)
    config_dict={}
    config_dict["port"]=portlist
    config_dict["zone"]=zonelist
    with open("config.json","w") as f:
        json.dump(config_dict,f, sort_keys = True, indent = 4)


if __name__ == '__main__':
    # START #
    if os.path.isfile("config.json"):
        with open("config.json") as f:
            jdata=json.load(f)
        allow_listenport=jdata["port"]
        allow_trustzone=jdata["zone"]
    else:
        config_create()

    listen_port = []
    nlist = netlisten()

    for l_port in nlist:
        listen_port.append(l_port[0])
    # print listen_port

    #allow_listenport = [80, 443]
    #allow_trustzone = [ "192.168.11.1/24", "192.168.1.1/24","127.0.0.1"]

    elist = netestablish()
    # print elist   [[':port', 'ip'], and so on ...

    remote_ip=[]
    for rip in elist:
        remote_ip.append(rip[1])
    #print remote_ip

    empty_flag=1
    for local_estab_port,remote_ip,remote_port in elist:
        if local_estab_port not in listen_port:
            checkflag = 1
            for trust_zone in allow_trustzone:
                if remote_ip  in netaddr.IPNetwork(trust_zone):
                    checkflag=0
            if checkflag:
                empty_flag=0
                print local_estab_port,remote_ip,remote_port

    if empty_flag:
        print "outgoing connections are clean"