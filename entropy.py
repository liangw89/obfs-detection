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

from trace import *

M = 2**12 # 2**12 is just for testing, change to 2**22 when use it
SEQ = 8 # block size
RD = [] # reference random distribution
BYTE_USED = 2048
HEX_CHARS = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

SPRT_alpha = 0.05
SPRT_beta = 0.05
SPRT_a = math.log(SPRT_beta / (1-SPRT_alpha), 10)
SPRT_b = math.log((1 - SPRT_beta) / SPRT_alpha, 10)


ENTROPY_DIST_TEST = "D"
ENTROPY_UNI_TEST = "U"
SPRT_TEST = "S"


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

def get_uniform_rd(M):
    RD = []
    RD = [ int(c, 16) for c in list(os.urandom(M).encode("hex"))]
    return RD

def entropy_dist_test(payload, SEQ, RD, BYTE_USED):
    # if len(payload) < 193:
    payload = payload[:BYTE_USED]

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

def uniform_test(payload, RD, BYTE_USED):
    payload = payload[:BYTE_USED]
    # if len(payload) < 193:
    if len(payload) < 149:
       return None
    payload = payload.encode("hex")

    res = [ int(c, 16) for c in list(payload)]
    ks_stat, p_value = stats.ks_2samp(res, RD)    
    return p_value

def sprt_test(payload, BYTE_USED):
    payload = payload[:BYTE_USED]
    res = sprt(payload)
    return res

def run_test(in_dir, test_key, SEQ=8, M=2**12, BYTE_USED=2048):
    """
    :param str in_dir: the directory that stores pcap files.
    """
    PASS = 0
    FAIL = 0
    RD = []
    ct = 0
    if test_key == ENTROPY_DIST_TEST:
        RD = get_entropy_dist_rd(SEQ, M)
    elif test_key == ENTROPY_UNI_TEST:
        RD = get_uniform_rd(M)
    elif test_key == SPRT_TEST:
        pass
    else:
        raise Exception("Unknown tests")
    fs = os.listdir(in_dir)
    random.shuffle(fs)
    for f in fs:
        if not f.endswith(".pcap"):
            continue
        fin = os.path.join(in_dir, f)
        
        # load pkts of a flow
        pkts = load_trace(fin, in_dir, False, False)
        for p in pkts:
            # get the first handshake message
            if p.direction == UPSTREAM and p.payload_len > 0:
                # print p.payload
                if p.payload == None:
                    break

                if test_key == ENTROPY_DIST_TEST:
                    res = entropy_dist_test(p.payload, SEQ, RD, BYTE_USED)
                elif test_key == ENTROPY_UNI_TEST:
                    res = uniform_test(p.payload, RD, BYTE_USED)
                elif test_key == SPRT_TEST:
                    res = sprt_test(p.payload, BYTE_USED)
                else:
                    raise Exception("Unknown tests")
                if res and res >= 0.1:
                    PASS += 1
                else:
                    FAIL += 1
                break
        ct += 1
        if ct == 5000:
            break
    return PASS, FAIL

def run_test2(fin, test_key, SEQ=8, M=2**12, BYTE_USED=2048):
    """
    :param str fin: the path of the file that stores handshake messages (in hex).
    """
    PASS = 0
    FAIL = 0
    RD = [] 
    ct = 0
    if test_key == ENTROPY_DIST_TEST:
        RD = get_entropy_dist_rd(SEQ, M)
    elif test_key == ENTROPY_UNI_TEST:
        RD = get_uniform_rd(M)
    elif test_key == SPRT_TEST:
        pass
    else:
        raise Exception("Unknown tests")
    buf = open(fin).readlines()
    random.shuffle(buf)
    for l in buf:
        l = l.strip("\n")
        l = l.decode("hex")
        if test_key == ENTROPY_DIST_TEST:
            res = entropy_dist_test(l, SEQ, RD, BYTE_USED)
        elif test_key == ENTROPY_UNI_TEST:
            res = uniform_test(l, RD, BYTE_USED)
        elif test_key == SPRT_TEST:
            res = sprt_test(l, BYTE_USED)
        else:
            raise Exception("Unknown tests")

        if res and res >= 0.1:
            PASS += 1
        else:
            # print l.encode("hex"), len(l)
            FAIL += 1
        ct += 1
        if ct == 5000:
            break
        continue
    return PASS, FAIL

path = "/media/Project/entropy_tests/hd/obfs3"
path = "obfs3_key_test.csv"
print run_test2(path, "D", SEQ=8)
print run_test2(path, "D", SEQ=16)
print run_test2(path, "D", SEQ=32)
print run_test2(path, "U")
print run_test2(path, "S", BYTE_USED=32)