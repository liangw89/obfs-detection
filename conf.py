
SAMPLESIZE = 9
TRAINSZIE = 2
VALIDSIZE = 3
TESTSIZE = SAMPLESIZE - TRAINSZIE - VALIDSIZE
IS_CAMPUS = True

PCAP_ROOT_DIR = "./pcap_test"
TRACE_ROOT_DIR = "./trace_test"
CSV_ROOT_DIR = "./csv_test"
CSV_ML_RES = "test.csv"
MODEL_DIR = "./models"
DOMAIN_LIST = "top-1m.csv"
SIP = "10.0.2.15"

TBB_DIR = "./"
TOR_TIMEOUT = 60
PAGE_TIMEOUT = 60

USER_PASSWORD = "123456"

PT_OPTIONS = ["fte", "meek-amazon", "meek-google", "obfs3", "norm", "obfs4"]


BRO_TMP_DIR = "bro_tmp"
BRO_CSV_DIR = "bro_trace_csv"
BRO_PCAP_DIR = "/media/Project/share/tor_trace/pcap"

#flags
UPSTREAM = 1
DOWNSTREAM = 0
ALLSTREAM = 2
FLAG_ACK = 16
FLAG_PUSH_ACK = 24
MISSING_ITEM = -1


#[DataBase]
TABLE_PREX = "test_trace"

DB_CONIFG = {
'host': 'localhost',
'db': 'test',
'user': 'root',
'passwd': 'root',
'local_infile': 1
}
HIVE_DB = "test"

SQL_MYSQL_LOAD_DATA = "LOAD DATA LOCAL INFILE '{CSV_NAME}' INTO TABLE `{TABLE_NAME}` " \
 "FIELDS TERMINATED BY '\t'"

SQL_HIVE_LOAD_DATA = "LOAD DATA LOCAL INPATH '{CSV_NAME}' INTO TABLE {TABLE_NAME}" 

SQL_TB_PKT_RAW = "CREATE TABLE IF NOT EXISTS {TABLE_NAME} (" \
" pid string, " \
" raw string, " \
" ts string, " \
" fid string, " \
" size int " \
") row format delimited " \
"fields terminated by '|' "\
"stored as TEXTFILE"

SQL_TB_PKT_META = "CREATE TABLE IF NOT EXISTS `{TABLE_NAME}` (" \
"`pid` varchar(64) NOT NULL," \
"`ts` varchar(64) NOT NULL," \
"`fid` varchar(64) NOT NULL," \
"`size` int(8) NOT NULL," \
"PRIMARY KEY (`pid`)," \
"KEY `fid` (`fid`)" \
") ENGINE=InnoDB DEFAULT CHARSET=utf8"


SQL_TB_FLOW_META = "CREATE TABLE IF NOT EXISTS {TABLE_NAME} (" \
"`fn`  varchar(128), " \
"`fid`  varchar(64), " \
"`sip` varchar(64), " \
"`sport` int(8), " \
"`dip` varchar(64), " \
"`dport` int(8)," \
"`proto` int(8)," \
"`ts` varchar(64), " \
"`dur` varchar(64), " \
"`service` varchar(64), " \
"`state` varchar(8), " \
"`orig_pkts` int(8), "\
"`orig_bytes` int(8), "\
"`resp_pkts` int(8), " \
"`resp_bytes` int(8), " \
"PRIMARY KEY (`fid`), " \
"KEY `fn` (`fn`), " \
"KEY `sip` (`sip`), " \
"KEY `dip` (`dip`)" \
") ENGINE=InnoDB DEFAULT CHARSET=utf8"

SQL_TB_FLOW_HTTP = "CREATE TABLE IF NOT EXISTS {TABLE_NAME} (" \
"`fid`  varchar(64), " \
"`ts` varchar(64), " \
"`host` varchar(64), " \
"`uri` varchar(2048), " \
"`method` varchar(64), " \
"`status_code` varchar(16), " \
"`status_msg` varchar(64), " \
"`resp_len` int(8), " \
"`filename` varchar(64), " \
"`session_id` varchar(64), " \
"`resp_type` varchar(64), " \
"PRIMARY KEY (`fid`), " \
"KEY `uri` (`uri`), " \
"KEY `host` (`host`), " \
"KEY `session_id` (`session_id`)" \
") ENGINE=InnoDB DEFAULT CHARSET=utf8"

SQL_TB_FLOW_SSL = "CREATE TABLE IF NOT EXISTS {TABLE_NAME} (" \
"`fid`  varchar(64), " \
"`ts` varchar(64), " \
"`version` varchar(64), " \
"`server_name` varchar(64), " \
"PRIMARY KEY (`fid`), " \
"KEY `server_name` (`server_name`)" \
") ENGINE=InnoDB DEFAULT CHARSET=utf8"

SQL_TB_PKT_RAW_INDEX = "CREATE INDEX ipid on TABLE {TABLE_NAME}(pid) " \
" AS 'org.apache.hadoop.hive.ql.index.compact.CompactIndexHandler' WITH DEFERRED REBUILD; "