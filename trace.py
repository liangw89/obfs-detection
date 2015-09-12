import dpkt
import math
import socket
import cPickle
import csv
import os
import random
import numpy as np
from collections import Counter
from conf import *


class PktMeta(object):
    """the structure of a trace"""
    def __init__(self):
        super(PktMeta, self).__init__()
        self.direction = -1
        self.ts = None
        self.flag = 0
        self.pkt_len = None
        self.payload_len = None
        self.payload_entropy = 0
        self.ssl_fl = 0
        self.payload = None

def entropy(s):
    """
    calcuate the entropy of a string
    :param str s: a string
    """
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

def get_traget_flow(fin):
    """
    select the flow with the most number of packets in a pcap
    :param str fin: the path of the input trace 
    """
    select_row = None

    cmd = "tshark -n -q -z conv,tcp -r %s" % (fin)
    buf = os.popen(cmd).readlines()[5:]
    buf = buf[0].strip("\n")
    select_row = [v for v in buf.split(" ") if v]

    if IS_CAMPUS:
        sip = select_row[0].split(":")[0]
        sport = int(select_row[0].split(":")[1])
        dip = select_row[2].split(":")[0]
        dport = int(select_row[2].split(":")[1])
        return [sip, sport, dip, dport]

    if select_row[0].find(SIP) != -1:
        sip = SIP
        sport = int(select_row[0].split(":")[1])
        dip = select_row[2].split(":")[0]
        dport = int(select_row[2].split(":")[1])
    else:
        sip = SIP
        sport = int(select_row[2].split(":")[1])
        dip = select_row[0].split(":")[0]
        dport = int(select_row[0].split(":")[1])

    return [sip, sport, dip, dport]


def generate_trace(fin, cond, with_payload=False):
    """
    extract basic info from each of packets of selected flow in a pcap, and 
    store the PktMeta instances into a cPickle file. We call the resulting 
    list of PktMeta instances "trace"
    :param str fin: path of the input pcap
    :param str cond: the 4 tuple of the flow selected in the input pcap
    :param boolean with_payload: if with_payload is True, up to 2048 bytes 
    of each payload will be stored 
    """
    SRC_IP = cond[0]
    SRC_PORT = cond[1]
    DST_IP = cond[2]
    DST_PORT = cond[3]
    trace = dpkt.pcap.Reader(open(fin))
    trace_iter = iter(trace)
    start_ts = 0
    all_pkt =[]
    while True:
        try:
            sip, dip, sport, dport = None, None, None, None
            direction = -1
            hd, buff = trace_iter.next()
            if start_ts==0: start_ts = hd
            eth = dpkt.ethernet.Ethernet(buff)
            if eth.type not in [dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6]:
                 continue
            ip = eth.data
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            else:
                continue
            tcp = ip.data
            if type(tcp) != dpkt.tcp.TCP:
                continue
            sport, dport = int(tcp.sport), int(tcp.dport)
            # print sip, sport, dip, dport, "==", SRC_IP, SRC_PORT, DST_IP, DST_PORT
            if sip == SRC_IP and sport == SRC_PORT and dip == DST_IP and dport == DST_PORT:
                direction = UPSTREAM
            elif sip == DST_IP and sport == DST_PORT and dip == SRC_IP and dport == SRC_PORT:
                direction = DOWNSTREAM
            else:
                continue
            pkt =PktMeta()
            payload = tcp.data
            flag = tcp.flags
            delta = hd - start_ts
            pkt.direction = direction
            pkt.ts = delta
            pkt.pkt_len = len(buff)
            pkt.payload_len = len(payload)
            pkt.flag = flag
            pkt.payload_entropy = entropy(payload)
            if with_payload:
                pkt.payload = payload[:2048]
            if len(payload) > 0:
                payload_str = payload.encode("hex")
                if payload_str.startswith("170303") or payload_str.startswith("170302"): 
                    if int(payload_str[6:10], 16) + 5 == pkt.payload_len:
                        pkt.ssl_fl = 1
            all_pkt.append(pkt)
        except:
            break
    return all_pkt


def load_trace(fin, trace_out_dir, with_payload=False, clean_fl=False):
    """
    find if the trace of a flow exists; if exists, load 
    the trace; otherwise generate the trace.
    :param str fin: the path of the input pcap
    :param str trace_out_dir: the directory for storing traces
    :param boolean clean_fl: if this flag is set to True, then 
    the script ignore the existing trace and generate a new trace.
    :param boolean with_payload: if with_payload is True, up to 2048 bytes 
    of each payload will be stored 
    """
    fname = os.path.basename(fin)
    fout = os.path.join(trace_out_dir, "%s_cached.db" % fname)
    if os.path.exists(fout) and not clean_fl:
        pkts = cPickle.load(open(fout))
    else:
        try:
            cond = get_traget_flow(fin)
        except:

            return None
        pkts = generate_trace(fin, cond, with_payload)
        cPickle.dump(pkts, open(fout, "w"))
    return pkts