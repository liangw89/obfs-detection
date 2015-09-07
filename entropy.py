import dpkt
import math
import socket
import cPickle
import csv
import os
import random
import numpy as np
import scipy.stats as stats
import itertools

from numpy import array, asarray, ma, zeros
import scipy.special as special
import scipy.linalg as linalg
from collections import Counter
from scipy.stats import *

M = 2**12 # 2**12 is just for testing, change to 2**22 when use it
SEQ = 8 # block size
RD = [] # reference random distribution
BYTE_USED = 2048
HEX_CHARS = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

SPRT_alpha = 0.05
SPRT_beta = 0.05
SPRT_a = math.log(SPRT_beta / (1-SPRT_alpha), 10)
SPRT_b = math.log((1 - SPRT_beta) / SPRT_alpha, 10)



class PktMeta(object):
    """docstring for PktMeta"""
    def __init__(self):
        super(PktMeta, self).__init__()
        self.direction = -1
        self.ts = None
        self.flag = 0
        self.pkt_len = None
        self.payload_len = None
        self.payload_entropy = 0
        self.ssl_fl = 0

def entropy(s):
    p, lns = Counter(s), float(len(s))
    lns = float(256)
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


def P0(x):
    return 1/float(256)
   

def P1(x):
    if x < 128:
        return 1/float(128)*7/10
    else:
        return 1/float(128)*3/10

def A(x):
    s = 0
    for i in x:
        s = s + math.log(P0(i)/ P1(i), 10)
    lx = len(set(x))
    return -1*s


def sprt(s, is_debug =False):
    ct = []
    x = []
    y = []
    for i in range(len(s)):
        c = s[i]
        ct.append(ord(c))
        p = A(ct)
        x.append(i)
        y.append(p)
        if is_debug:
            print p
            continue
        if p >= SPRT_b:
            return 1
        elif p <= SPRT_a:
            return 0
        else:
            continue
    freq_vector = Counter(ct).values()
    freq_vector = [ float(v) for v in  freq_vector]
    l = len(ct)
    exp_vector = []
    for i in Counter(ct):
        if i < 128:
            exp_vector.append(float(3 * 7/float(10) ))
        else:
            exp_vector.append(float(3 * 3/float(10)))
    p = power_divergence(freq_vector, f_exp=exp_vector, lambda_="mod-log-likelihood")[1]
    if p > 0.1:
        return 1
    else:
        return 0

def get_entropy_dist_rd(SEQ, M):
    RD = []
    _random_str = os.urandom(M)
    ranges = range(len(_random_str)/SEQ)
    for i in ranges:
        RD.append(entropy(_random_str[i*SEQ :(i+1)*SEQ]))
    return RD

def get_uniform_rd(SEQ, M):
    RD = []
    RD = [ int(c, 16) for c in list(os.urandom(M).encode("hex"))]
    return RD

def entropy_dist_test(payload, SEQ, RD):
    # if len(payload) < 193:
    if len(payload) < 149:
       return None

    res = []
    ranges = range(len(payload) / SEQ)
    for i in ranges:
        tmp = entropy(payload[i*SEQ : (i+1) * SEQ])
        res.append(tmp)
    # run ks 2 sample tests
    ks_stat, p_value = stats.ks_2samp(res, RD)    
    return p_value

def uniform_test(payload, SEQ, RD):
    # if len(payload) < 193:
    if len(payload) < 149:
       return None
    payload = payload.encode("hex")

    res = [ int(c, 16) for c in list(payload)]
    ks_stat, p_value = stats.ks_2samp(res, RD)    
    return p_value

def sqrt_test(payload, _size):
    res = sqrt(payload[:_size])
    return res

def run_test(pt_name):
    PASS = 0
    FAIL = 0
    in_dir = os.path.join(TRACE_DIR, pt_name)
    for f in os.listdir(in_dir):
        if not f.endswith(".pcap"):
            continue
        fin = os.path.join(in_dir, f)
        # load pkts of a flow
        pkts = load_trace(fin, False)
        for p in pkts:
            # get the first handshake message
            if p.direction == UPSTREAM and p.payload_len > 0:
                res = entropy_dist_test(p.payload[:BYTE_USED], SEQ, RD)
                if res and res >= 0.1:
                    PASS += 1
                else:
                    FAIL += 1
                break

    return PASS, FAIL

def run_test2():
    PASS = 0
    FAIL = 0
    ct = 0
    st = []
    for l in open("obfs4_key.csv"):
        l = l.strip("\n")
        l = l.decode("hex")
        res = entropy_dist_test(l[:BYTE_USED], SEQ, RD)
        st.append(res)
        if res and res >= 0.1:
            PASS += 1
        else:
            # print l.encode("hex"), len(l)
            FAIL += 1
        ct += 1
        if ct % 1000 == 0:
            print PASS, FAIL
        if ct == 5000:
            break
        continue
    print np.median(st), np.min(st)
    return PASS, FAIL


print run_test2()