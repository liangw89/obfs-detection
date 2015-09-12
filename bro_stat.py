import time

import MySQLdb as sqldb

import os
import sys
from dpkt.ip import *
from dpkt.ethernet import *
import dpkt
from socket import *
import socket
import hashlib
import csv
from struct import *
import ipaddr

from conf import *

tb_proto = {
"tcp": IP_PROTO_TCP,
"udp": IP_PROTO_UDP
} 

tb_suffixs = ["pkt_meta", "pkt_raw", "flow_meta", "flow_http", "flow_ssl"]

fp_pkt_raw = None
fp_flow_pkt = None
fp_flow_meta = None

class FlowDB(object):
    """docstring for FlowDB"""
    def __init__(self, fin):
        super(FlowDB, self).__init__()
        self.fin = fin
        self.fname = os.path.basename(fin)
        self.flow_dict = {}
        self.conn_table = []
        self.http_table = []
        self.ssl_table = []
        self.conn_csv_name = os.path.join(BRO_CSV_DIR, "%s_flow_meta.csv" % self.fname)
        self.http_csv_name = os.path.join(BRO_CSV_DIR, "%s_flow_http.csv" % self.fname)
        self.ssl_csv_name = os.path.join(BRO_CSV_DIR, "%s_flow_ssl.csv" % self.fname)
        

    def get_stat_tables(self):
        if not os.path.exists(BRO_TMP_DIR):
            os.makedirs(BRO_TMP_DIR)
        os.popen("bro -r %s" % self.fin)
        os.popen('for f in *.log ; do mv "$f" %s/%s_"$f" ; done' % (BRO_TMP_DIR, self.fname))
        self.bro_conn_stat()
        self.bro_http_stat()
        self.bro_ssl_stat()

    def bro_conn_stat(self):
        cmd = "cat %s/%s_conn.log | bro-cut uid id.orig_h id.orig_p \
        id.resp_h id.resp_p proto ts duration service conn_state orig_pkts \
        orig_ip_bytes resp_pkts resp_ip_bytes" % (BRO_TMP_DIR, self.fname)
        PROTO_INDEX = 6
        TS_INDEX = 7
        tmp = os.popen(cmd).readlines()
        tmp = [v.strip("\n").split("\t") for v in tmp]
        self.conn_table = [[self.fname] + v for v in tmp]
        for v in self.conn_table:
            v[PROTO_INDEX] = tb_proto[v[PROTO_INDEX]] if v[PROTO_INDEX] in tb_proto else 0
        
        for i in tmp:
            key, subkey, val = i[1:6], i[6:8], i[0]
            subkey[0] = float(subkey[0])
            if key[-1] == 0:
                key[1], key[3] = "", ""
            key, subkey = tuple(key), tuple(subkey)
            if key not in self.flow_dict:
                self.flow_dict[key] = {}
            self.flow_dict[key][subkey] = val

    def bro_http_stat(self):
        cmd = "cat %s/%s_http.log | bro-cut uid ts \
        host uri method status_code status_msg response_body_len \
        filename resp_fuids resp_mime_types" % (BRO_TMP_DIR, self.fname)
        
        tmp = os.popen(cmd).readlines()
        tmp = [v.strip("\n").split("\t") for v in tmp]
        self.http_table = tmp

    def bro_ssl_stat(self):
        cmd = "cat %s/%s_ssl.log | bro-cut uid ts \
        version server_name" % (BRO_TMP_DIR, self.fname)
        tmp = os.popen(cmd).readlines()
        tmp = [v.strip("\n").split("\t") for v in tmp]
        self.ssl_table = tmp

    def export_csv(self, tb, fname):
        if not tb:
            return False
        fp = open(fname, "w")
        fp_csv = csv.writer(fp, delimiter='\t', quoting=csv.QUOTE_MINIMAL)
        fp_csv.writerows(tb)

    def export_all_csvs(self):
        if not os.path.exists(BRO_CSV_DIR):
            os.makedirs(BRO_CSV_DIR)
 
        self.export_csv(self.conn_table, self.conn_csv_name)
        self.export_csv(self.http_table, self.http_csv_name)
        self.export_csv(self.ssl_table, self.ssl_csv_name)

    def get_flow_id(self, sip, sport, dip, dport, proto, ts):
        sk = (sip, sport, dip, dport, proto)
        sk1 = (dip, dport, sip, sport, proto)
        if sk in self.flow_dict:
            tmp = self.flow_dict[sk] 
        elif sk1 in self.flow_dict:
            tmp = self.flow_dict[sk1]
        else:
            return False
        if len(tmp) == 1:
            return tmp.values()[0]
        for k in tmp:
            base = k[0]
            delta = k[1] 
            delta = 0 if delta == "-" else float(delta)
            if ts - base <= delta + 0.1 and ts >= base:
                return tmp[k]
        return False
        

def get_target_traces(dir_name):
    tmp = []
    for f in sorted(os.listdir(dir_name)):
        tmp.append(os.path.abspath(os.path.join(dir_name, f)))
    return tmp

def get_pkt_id(ts, pkt):
    return hashlib.sha1("%.10f" % ts + str(pkt)).digest().encode('base64')[:20]
 
def init_csv_fp(fin):
    if not os.path.exists(BRO_CSV_DIR):
        os.makedirs(BRO_CSV_DIR)
    fp = open(os.path.join(BRO_CSV_DIR, os.path.basename(fin) + "_pkt_raw.csv"), "ab")
    fp_pkt_raw = csv.writer(fp, delimiter='|', quoting=csv.QUOTE_MINIMAL)
    fp = open(os.path.join(BRO_CSV_DIR, os.path.basename(fin) + "_pkt_meta.csv"), "ab")
    fp_pkt_meta = csv.writer(fp, delimiter='|', quoting=csv.QUOTE_MINIMAL)
    return fp_pkt_raw, fp_pkt_meta


def pcap_to_csv(fin, only_flow = True):
    """generate csvs for a pcap, based on Bro analysis results"""
    if not only_flow:
        raise Exception("only_flow = False is deprecated!")
    flow_db = FlowDB(fin)
    flow_db.get_stat_tables()
    flow_db.export_all_csvs()
    return None

    # the following code is deprecated
    """
    trace = dpkt.pcap.Reader(open(fin))
    trace_iter = iter(trace)
    fp_pkt_raw, fp_pkt_meta = init_csv_fp(fin)
    while True:
        try:
            ts, pkt = trace_iter.next()
            buff = []
            pid = get_pkt_id(ts, pkt)
            fd_size = len(pkt)
            fd_tm = ts
            fd_raw = pkt.encode("hex")
            fd_sip = None
            fd_sport = None
            fd_dip = None
            fd_dport = None
            fd_proto = None

            eth = dpkt.ethernet.Ethernet(pkt)
            # predefined types: https://code.google.com/p/dpkt/source/browse/trunk/dpkt/ethernet.py?r=62 
            if eth.type not in [ETH_TYPE_IP, ETH_TYPE_IP6]:
                continue
            ip = eth.data
            if eth.type == ETH_TYPE_IP:
                fd_sip, fd_dip = socket.inet_ntoa(ip.src), \
            socket.inet_ntoa(ip.dst)
                if hasattr(ip, 'ip6'):
                    fd_sip, fd_dip = socket.inet_ntop(AF_INET6, ip.ip6.src), \
             socket.inet_ntop(AF_INET6, ip.ip6.dst)
            if eth.type == ETH_TYPE_IP6:
                fd_sip, fd_dip = socket.inet_ntop(AF_INET6, ip.src), \
            socket.inet_ntop(AF_INET6, ip.dst)

            tmp = ip.data
            # predefined protocol types: https://code.google.com/p/dpkt/source/browse/trunk/dpkt/ip.py
            if ip.p in [IP_PROTO_UDP, IP_PROTO_TCP]:
                #fd_proto = 1 if ip.p == IP_PROTO_UDP else 2
                fd_proto = ip.p
                fd_sport, fd_dport = str(tmp.sport), str(tmp.dport)
            else:
                fd_proto = 0
                fd_sport, fd_dport = "", ""
                pass
            fid = flow_db.get_flow_id(fd_sip, fd_sport, fd_dip, fd_dport, fd_proto, fd_tm)
            if not fid:
                continue
            fp_pkt_raw.writerow([pid, fd_raw, "%.10f" % fd_tm, fid, fd_size])
            fp_pkt_meta.writerow([pid, "%.10f" % fd_tm, fid, fd_size])
        except:
            break
    """
            

def create_tables():
    """create tales in the mysql and hive databases"""

    sql = SQL_TB_FLOW_META.format(TABLE_NAME ="%s_flow_meta" % (TABLE_PREX))
    conn = sqldb.connect(**DB_CONIFG)
    cur = conn.cursor()
    cur.execute(sql)

    sql = SQL_TB_FLOW_SSL.format(TABLE_NAME ="%s_flow_ssl" % (TABLE_PREX))
    conn = sqldb.connect(**DB_CONIFG)
    cur = conn.cursor()
    cur.execute(sql)

    sql = SQL_TB_FLOW_HTTP.format(TABLE_NAME ="%s_flow_http" % (TABLE_PREX))
    conn = sqldb.connect(**DB_CONIFG)
    cur = conn.cursor()
    cur.execute(sql)

    """
    sql = SQL_TB_PKT_META.format(TABLE_NAME = "%s_pkt_meta" % (TABLE_PREX))
    conn = sqldb.connect(**DB_CONIFG)
    cur = conn.cursor()
    cur.execute(sql)

    sql = SQL_TB_PKT_RAW.format(TABLE_NAME ="%s_pkt_raw" % (TABLE_PREX))
    cmd = 'hive --database %s -S -e "%s"' % (HIVE_DB, sql)
    os.popen(cmd)
    sql = SQL_TB_PKT_RAW_INDEX.format(TABLE_NAME ="%s_pkt_raw" % (TABLE_PREX))
    cmd = 'hive --database %s -S -e "%s"' % (HIVE_DB, sql)
    os.popen(cmd)
    """

def load_data(csv_name, table_name):
    """import csv to database, called by csv_to_db"""
    print "loading:", csv_name, table_name
    try:
        conn = sqldb.connect(**DB_CONIFG)
        cur = conn.cursor()
        sql = SQL_MYSQL_LOAD_DATA.format(CSV_NAME = csv_name, TABLE_NAME = table_name)
        print "Use MYSQL", sql
        cur.execute(sql)
        conn.commit()
    except:
        sql = SQL_HIVE_LOAD_DATA.format(CSV_NAME = csv_name, TABLE_NAME = table_name)
        cmd = 'hive --database %s -S -e "%s"' % (HIVE_DB, sql)
        print "Use Hive", cmd
        os.popen(cmd)

def csv_to_db():
    """import csv to databases"""
    for csv in sorted(os.listdir(BRO_CSV_DIR)):
        for sf in tb_suffixs:
            if sf in csv:
                tb = "%s_%s" % (TABLE_PREX, sf)
                break
        load_data(os.path.abspath(os.path.join(BRO_CSV_DIR, csv)), tb)


if __name__ == '__main__':
    
    ts = get_target_traces(BRO_PCAP_DIR)
    create_tables()
    
    for tf in ts:
        print tf
        pcap_to_csv(tf, True)
        
    csv_to_db()

