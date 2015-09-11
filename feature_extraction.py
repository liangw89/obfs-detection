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

IS_CAMPUS = True

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


def generate_trace(fin, cond):
    """
    extract basic info from each of packets of selected flow in a pcap, and 
    store the PktMeta instances into a cPickle file. We call the resulting 
    list of PktMeta instances "trace"
    :param str fin: path of the input pcap
    :param str cond: the 4 tuple of the flow selected in the input pcap  
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
            if len(payload) > 0:
                payload_str = payload.encode("hex")
                if payload_str.startswith("170303") or payload_str.startswith("170302"): 
                    if int(payload_str[6:10], 16) + 5 == pkt.payload_len:
                        pkt.ssl_fl = 1
            all_pkt.append(pkt)
        except:
            break
    return all_pkt


def load_trace(fin, trace_out_dir, clean_fl=False):
    """
    find if the trace of a flow exists; if exists, load 
    the trace; otherwise generate the trace.
    :param str fin: the path of the input pcap
    :param str trace_out_dir: the directory for storing traces
    :param boolean clean_fl: if this flag is set to True, then 
    the script ignore the existing trace and generate a new trace.
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
        pkts = generate_trace(fin, cond)
        cPickle.dump(pkts, open(fout, "w"))
    return pkts

def pkt_len_dist(trace, direction):
    """
    payload length distribution of the packets 
    in a given direction; only return the top 5 
    most seen pcap payload lengths.
    """
    _size = []
    for p in trace:
        if direction == ALLSTREAM:
            _size.append(p.payload_len)
        elif p.direction == direction:
            _size.append(p.payload_len)
        else:
            continue
    r = Counter(_size)
    total = sum(r.values())
    try:
        zero_p = round(float(r.pop(0)) / total, 2)
    except:
        zero_p = 0.0
    res = sorted(r.items(), key=lambda x:x[1], reverse=True)[:5]

    res = [(v[0], round(float(v[1]) / total * 100, 2)) for v in res]
    res = [v[0] for v in res]
    return zero_p, res

def pkt_ssl_len_dist(trace, direction):
    """
    payload length distribution of ssl packets 
    in a given direction; only return the top 3 
    most seen pcap payload lengths.
    """
    _size = []
    for p in trace:
        if p.ssl_fl == 0:
            continue
        if direction == ALLSTREAM:
            _size.append(p.payload_len)
        elif p.direction == direction:
            _size.append(p.payload_len)
        else:
            continue
    if not _size:
        return 0, [MISSING_ITEM] * 3

    r = Counter(_size)
    total = sum(r.values())
    res = sorted(r.items(), key=lambda x:x[1], reverse=True)[:3]
    res = [(v[0], round(float(v[1]) / total * 100, 2)) for v in res]
    res = [v[0] for v in res]

    return round(len(_size) / float(trace[-1].ts), 2), res

def pkt_payload_entropy_dist(trace, direction):
    """
    min/max/medain/mean entropies of all the packet payloads
    in a given direction;
    """
    _tmp = []
    for p in trace:
        if p.payload_len == 0:
            continue
        if direction == ALLSTREAM:
            if p.payload_entropy: _tmp.append(p.payload_entropy)
        elif p.direction == direction:
            if p.payload_entropy: _tmp.append(p.payload_entropy)
        else:
            continue
    if not _tmp:
        return [MISSING_ITEM] * 4
    return [round(min(_tmp), 2), round(max(_tmp), 2), round(np.median(_tmp), 2), round(np.average(_tmp), 2)]

def pkt_payload_ack_seq(trace, direction):
    """
    percentage of intervals between ACK packets in a given 
    direction that falls in to a given range. 
    """
    if direction == ALLSTREAM:
        return None
    _tmp = []
    for p in trace:
        if p.flag != FLAG_ACK:
            continue
        if p.direction == direction:
            _tmp.append(p.ts)
        else:
            continue
    data = [(y - x) * 1000 for x, y in zip(_tmp, _tmp[1:])]
    bins = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000])
    if not data:
        # return [0] * 14
        return [0] * 29
    digitized = np.digitize(data, bins)
    tmp = Counter(digitized)
    total = len(data)
    res = []
    # for k in range(1, 15):
    for k in range(1, 30):
        if k not in tmp:
            res.append(0)
        else:
            res.append( round(float(tmp[k]) / total, 2) )
    return res

def pkt_order(trace):
    _order = []
    for p in trace:
        _order.append(p.direction)
    return _order

def pkt_interval_dist(trace):
    _time = []
    for index in range(len(trace)-1):
        _next = trace[index+1]
        _cur = trace[index]
        _time.append((_next.ts - _cur.ts) * 1000)


def get_all_features(trace, cls_label):
    """
    generate features for a given trace
    :param list trace: a list of PktMeta instances. 
    :param str cls_label: the cls of the input trace  
    """
    res = []
    for direction in [UPSTREAM, DOWNSTREAM, ALLSTREAM]:
        # packet size dist
        zero_p, top_size = pkt_len_dist(trace, direction)
        if len(top_size) < 5:
            top_size += (5 - len(top_size)) * [MISSING_ITEM]
        res += [zero_p]
        res += top_size

    for direction in [UPSTREAM, DOWNSTREAM, ALLSTREAM]:
        # ssl size dist
        zero_p, top_size = pkt_ssl_len_dist(trace, direction)
        if len(top_size) < 3:
            top_size += (3 - len(top_size)) * [MISSING_ITEM]
        res += [zero_p]
        res += top_size

    for direction in [UPSTREAM, DOWNSTREAM, ALLSTREAM]:
        #entropy
        tmp = pkt_payload_entropy_dist(trace, direction)
        res += tmp


    for direction in [UPSTREAM, DOWNSTREAM, ALLSTREAM]:
        # if zero_p > 0: print zero_p, fin
        # ack_seq
        tmp = pkt_payload_ack_seq(trace, direction)
        if tmp:
            res += tmp

        
    res.append(cls_label)
    return res

def get_partial_trace_by_time(trace, time_window):
    """
    extract a portion of the input trace based on 
    specified time window
    """
    st = 0
    ed = trace[-1].ts
    if time_window >= ed:
        return trace
    safe_window = ed - time_window
    # start_tm = random.uniform(0, safe_window)
    start_tm = 0
    end_tm = start_tm + time_window
    res = []
    for p in trace:
        if p.ts >= start_tm and p.ts <= end_tm:
            res.append(p)
    return res

def get_partial_trace_by_no(trace, no):
    """
    extract a portion of the input trace based on 
    specified packet number
    """
    _max = len(trace)
    if no >= _max:
        return trace
    safe_window = _max - no
    # start_no = random.randint(0, safe_window)
    start_no = 0
    end_no = start_no + no
    return trace[start_no:end_no]
 
def copy_dir_struct(in_dir, out_dir):
    for r, d, f in os.walk(in_dir):
        r = r.replace(in_dir, out_dir)
        if not os.path.exists(r):
            os.mkdir(r)

def generate_feature_csv(strategy, strategy_paras, cls_labels, setting_id, trail_no=0):
    """generate csvs that storing the features extracted from traces"""
    func = None
    if strategy == "time":
        func = get_partial_trace_by_time
    elif strategy == "no":
        func = get_partial_trace_by_no
    else:
        raise ValueError('Unknown strategy specified! Should be "no" or "time" ')
    copy_dir_struct(PCAP_ROOT_DIR, TRACE_ROOT_DIR)
    copy_dir_struct(PCAP_ROOT_DIR, CSV_ROOT_DIR)
    for no in strategy_paras:
        for _cls in cls_labels:
            all_res = []
            in_dir = os.path.join(PCAP_ROOT_DIR, str(setting_id), _cls)

            trace_out_dir = os.path.join(TRACE_ROOT_DIR, str(setting_id), _cls)

            csv_dir = os.path.join(CSV_ROOT_DIR, str(setting_id), _cls)

            csv_name = os.path.join(csv_dir, "%s_%s_%s_%s.csv" % (_cls, strategy, no, trail_no))
            fcsv = csv.writer(open(csv_name, "w"), delimiter=',')
            for f in os.listdir(in_dir):
                fin = os.path.join(in_dir, f)
                res = [fin]
                pkts = load_trace(fin, trace_out_dir, False)
                if not pkts:
                    continue
                pkts = func(pkts, no)
                try:
                    # remove TCP handshake
                    res += get_all_features(pkts[3:], _cls)
                except:
                    continue
                all_res.append(res)
            # write csv headers
            fcsv.writerow(range(len(all_res[0])))
            # write features
            fcsv.writerows(all_res)
            
if __name__ == '__main__':
    for strategy in ["no", "time"]:
        if strategy == "no":
            strategy_paras = range(20, 50, 5)
        else:
            strategy_paras = range(2, 5, 1)
        cls_labels = ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google", "norm"]
        #cls_labels = ["norm"]
        for setting_id in [1, 2, 3]:

            generate_feature_csv(strategy, strategy_paras, cls_labels, setting_id)


