from __future__ import division
import cPickle
import random
import csv
import sys
import numpy as np
import os
from sklearn import *
from sklearn.metrics import *
from sklearn.tree import DecisionTreeClassifier as DT
from sklearn.ensemble import RandomForestClassifier as RF
from sklearn.neighbors import KNeighborsClassifier as KNN
from sklearn.ensemble import AdaBoostClassifier as AB
from sklearn.naive_bayes import GaussianNB as NB
from sklearn.svm import SVC as SVM
from sklearn.externals import joblib

from collections import Counter
from conf import *

s_indexs = range(0, 30) + [100]
e_indexs = range(30, 42) + [100]
t_indexs = range(42, 100) + [100]

es_indexs = e_indexs + s_indexs 
es_indexs.sort()
es_indexs = es_indexs[:-1]

st_indexs = s_indexs + t_indexs
st_indexs.sort()
st_indexs = st_indexs[:-1]

et_indexs = e_indexs + t_indexs
et_indexs.sort()
et_indexs = et_indexs[:-1]

all_indexs = e_indexs + t_indexs + s_indexs
all_indexs.sort()
all_indexs = all_indexs[:-2]

feature_sets = {}
feature_sets["E"] = e_indexs
feature_sets["T"] = t_indexs
feature_sets["S"] = s_indexs
feature_sets["ES"] = es_indexs
feature_sets["ET"] = et_indexs
feature_sets["ST"] = st_indexs
feature_sets["EST"] = all_indexs



def remove_features(inst, indexs):
    tmp = []
    for i in range(len(inst)):
        if i in indexs:
            tmp.append(inst[i])
    return tmp


class ML(object):
    """docstring for ML"""
    def __init__(self, cls_labels, setting_id):
        super(ML, self).__init__()
        self.cls_labels = cls_labels
        self.header = None
        self.insts_all = {}
        self.insts_hold_out = {}
        self.train_set = []
        self.val_set = []
        self.test_set = []
        self.hold_out_nos = 0
        self.train_val_set_nos = 0
        self.train_set_nos = 0
        self.val_set_nos = 0
        self.setting_id = setting_id



    def init_insts(self, strategy, strategy_para):
        self._strategy_para = strategy_para
        # init training/test instances
        for _cls in self.cls_labels:
            self.insts_all[_cls] = []
            self.insts_hold_out[_cls] = []
            # tmp = self.load_csv("%s/csv2/%s_%s_0.csv" % (_dir, pt_name, self._train_sg_para))
            csv_name = os.path.join(CSV_ROOT_DIR, str(self.setting_id), _cls, "%s_%s_%s_%s.csv" % (_cls, strategy, strategy_para, 0))
            tmp = self.load_csv(csv_name)
            for no in xrange(len(tmp)):
                self.insts_all[_cls].append(tmp[no])

            
    def load_csv(self, fname):
        f = open(fname)
        self.header = f.readline()
        self.header = self.header.strip().split(",")[1:]
        self.header[-1] = "cls"
        buf = [v.strip() for v in f.readlines()]
        f.close()
        return [v.split(",")[1:] for v in buf]

    def get_header(self):
        return self.header


    def random_split_train_test(self):
        self.hold_out_nos = random.sample(range(SAMPLESIZE), TESTSIZE)
        self.train_val_set_nos = list(set(range(SAMPLESIZE)) - set(self.hold_out_nos))
        # print len(self.hold_out_nos), len(self.train_val_set_nos)
        
    def random_split_train_val(self):
        random.shuffle(self.train_val_set_nos)
        self.train_set_nos = self.train_val_set_nos[:TRAINSZIE]
        self.val_set_nos = self.train_val_set_nos[TRAINSZIE:]
        # print len(self.train_set_nos), len(self.val_set_nos)

    def get_test_set(self):
        self.test_set = []
        for _cls in self.insts_all:
            cur_inst_sets = self.insts_all[_cls]
            
            for _no in self.hold_out_nos:
                cur_inst = cur_inst_sets[_no]
                self.test_set.append(cur_inst)
        return self.test_set

    def get_train_set(self):
        self.train_set = []
        self.val_set = []
        for _cls in self.insts_all:
            cur_inst_sets = self.insts_all[_cls]
            for _no in self.train_set_nos:
                cur_inst = cur_inst_sets[_no]
                self.train_set.append(cur_inst)
            for _no in self.val_set_nos:
                cur_inst = cur_inst_sets[_no]
                self.val_set.append(cur_inst)
        return self.train_set, self.val_set

    def select_feature(self, dataset, feature_set_key):
        tmp = []
        feature_indexs = feature_sets[feature_set_key]
        for inst in dataset:
            tmp.append(remove_features(inst, feature_indexs))
        return tmp


def relabel(_set, target):
    for v in _set:
        if v[-1] != target:
            v[-1] = "false"
        else:
            v[-1] = "true"
    return _set


def get_stat(ytest, ypred):
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    label = "true"
    for i in range(len(ypred)):
        if ypred[i] == label and ytest[i] == label:
            tp += 1
        elif ypred[i] == label and ytest[i] != label:
            fp += 1
        elif ypred[i] != label and ytest[i] == label:
            fn += 1
        elif ypred[i] != label and ytest[i] != label:
            tn += 1
    # print tp, fp, fn, tn
    tpr = float(tp / list(ytest).count("true"))
    fpr = float(fp / list(ytest).count("false"))
    fnr = float(fn / list(ytest).count("true"))
    tnr = float(tn / list(ytest).count("false"))
    auc = precision_score(ytest, ypred, pos_label=label)
    
    return [tpr, fpr, fnr, tnr, auc]
    
def stat_on_train(model, train_set, val_set, is_using_val_set=True):
    if model == "DT":
        model = DT()
    elif model == "KNN":
        model = KNN()
    elif model == "NB":
        model = NB()
    else:
        exit()
    xtrain = np.array([[float(i) for i in v[:-1]] for v in train_set])
    ytrain = np.array([v[-1] for v in train_set])
    xtest = np.array([[float(i) for i in v[:-1]] for v in val_set])
    ytest = np.array([v[-1] for v in val_set])
    clf = model.fit(xtrain, ytrain)
    ypred = clf.predict(xtest)
    if is_using_val_set:
        clf = model.fit(np.concatenate((xtrain, xtest), axis=0), np.concatenate((ytrain, ytest), axis=0))
    return get_stat(ytest, ypred), clf

def stat_on_test(clf, test_set):
    xtest = np.array([[float(i) for i in v[:-1]] for v in test_set])
    ytest = np.array([v[-1] for v in test_set])
    ypred = clf.predict(xtest)
    return get_stat(ytest, ypred)

def save_res(model_para, train_res, test_res):
    res = model_para + train_res + test_res
    res = ",".join([str(v) for v in res])
    print res 
    res = res + "\n"
    f = open(CSV_ML_RES, "a")
    f.write(res)
    f.close()

def outer_fold(ml_inst, run_no, setting_id, is_debug=True):
    
    inner_fold_no = 10
    max_auc = 0
    best_para = None
    train_res_all = {}
    for no in xrange(inner_fold_no):
        ml_inst.random_split_train_val()
        
        for strategy in ["no", "time"]:
            if strategy == "no":
                strategy_paras = range(20, 50, 5)
            else:
                strategy_paras = range(2, 5, 1)
            for strategy_para in strategy_paras:
                ml_inst.init_insts(strategy, strategy_para)
                _test_set = ml_inst.get_test_set()
                _train_set, _val_set = ml_inst.get_train_set()

                for feature_set_key in ["E", "T", "S", "ES", "ET", "ST", "EST"]:
                    for model in ["DT", "KNN", "NB"]:
                        auc_avg = []
                        for target_cls in ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google"]:
                            model_para = [run_no, no, strategy, strategy_para, feature_set_key, model, target_cls]
        
                            test_set = ml_inst.select_feature(_test_set, feature_set_key)
                            test_set = relabel(test_set, target_cls)

                            train_set = ml_inst.select_feature(_train_set, feature_set_key)
                            train_set = relabel(train_set, target_cls)

                            val_set = ml_inst.select_feature(_val_set, feature_set_key)
                            val_set = relabel(val_set, target_cls)
                            
                            train_res, clf = stat_on_train(model, train_set, val_set)

                            if is_debug:
                                test_res = stat_on_test(clf, test_set)
                                save_res(model_para, train_res, test_res)
                                continue

                        auc_avg.append(train_res[-1])
                        auc_avg = np.mean(auc_avg)
                        key = (strategy, strategy_para, feature_set_key, model)
                        if key not in train_res_all:
                            train_res_all[key] = []
                        train_res_all[key].append(auc_avg)
    if is_debug:
        return None
    for k in train_res_all:
        train_res_all[k] = float(np.mean(train_res_all[k]))
    tmp = sorted(train_res_all.items(), key=lambda x: x[1], reverse=True)
    strategy, strategy_para, feature_set_key, model = tmp[0][0]
    ml_inst.init_insts(strategy, strategy_para)
    _test_set = ml_inst.get_test_set()
    _train_set, _val_set = ml_inst.get_train_set()
    test_set = ml_inst.select_feature(_test_set, feature_set_key)
    test_set = relabel(test_set, target_cls)
    train_set = ml_inst.select_feature(_train_set + _val_set, feature_set_key)
    train_set = relabel(train_set, target_cls)
    test_res, clf = stat_on_train(model, train_set, test_set)
    print tmp[0][0], tmp[0][1], test_res


def model_parameter_selection(is_debug=True): 
    header = "round_no,inner_fold_no,strategy,strategy_para,model,feature_set,cls,tpr_train,\
    fpr_train,fnr_train,tnr_train,auc_train,tpr_test,fpr_test,fnr_test,tnr_test,auc_test"
    f = open(CSV_ML_RES, "w")
    f.write(header + "\n")
    f.close()
    setting_id = 1
    for run_no in xrange(1):
        cls_labels =  ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google", "norm"]
        ml_inst = ML(cls_labels, setting_id)
        ml_inst.random_split_train_test()
        outer_fold(ml_inst, run_no, setting_id, is_debug)

def portability_test(strategy, strategy_para, feature_set_key, model):
    cls_labels =  ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google", "norm"]
    for setting_id_x in range(1, 4):
        for setting_id_y in range(1, 4):
            ml_inst_x = ML(cls_labels, setting_id_x)
            ml_inst_x.random_split_train_test()
            ml_inst_x.random_split_train_val()
            ml_inst_x.init_insts(strategy, strategy_para)
            _test_set = ml_inst_x.get_test_set()
            
            if setting_id_x  == setting_id_y:    
                _train_set, _val_set = ml_inst_x.get_train_set()
            else:
                ml_inst_y = ML(cls_labels, setting_id_y)
                ml_inst_y.init_insts(strategy, strategy_para)
                ml_inst_y.random_split_train_test()
                ml_inst_y.random_split_train_val()
                _train_set, _val_set = ml_inst_y.get_train_set()
            

            train_set = _train_set + _val_set

            tpr_avg = []
            fpr_avg = []
            for target_cls in ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google"]:
                test_set = ml_inst_x.select_feature(_test_set, feature_set_key)
                test_set = relabel(test_set, target_cls)

                train_set = ml_inst_x.select_feature(_train_set, feature_set_key)
                train_set = relabel(train_set, target_cls)           
 
                test_res, clf = stat_on_train(model, train_set, test_set)
                tpr_avg.append(test_res[0])
                fpr_avg.append(test_res[1])
            tpr_avg = float(np.mean(tpr_avg))
            fpr_avg = float(np.mean(fpr_avg))
            print setting_id_x, setting_id_y, tpr_avg, fpr_avg

def model_selection(strategy, strategy_para, feature_set_key, model):
    cls_labels =  ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google", "norm"]
    auc_best = 0
    models_best = {}
    for no in xrange(20):
        test_set = []
        train_set = []
        for setting_id in range(1, 4):
            ml_inst = ML(cls_labels, setting_id)
            ml_inst.random_split_train_test()
            ml_inst.random_split_train_val()
            ml_inst.init_insts(strategy, strategy_para)
            _test_set = ml_inst.get_test_set() 
            _train_set, _val_set = ml_inst.get_train_set()
            test_set += _test_set
            train_set = train_set + _train_set + _val_set
        # tpr_avg = []
        # fpr_avg = []

        auc_avg = []
        models = {}
        for target_cls in ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google"]:
            
            test_set = ml_inst.select_feature(_test_set, feature_set_key)
            test_set = relabel(test_set, target_cls)

            train_set = ml_inst.select_feature(_train_set, feature_set_key)
            train_set = relabel(train_set, target_cls)

            test_res, clf = stat_on_train(model, train_set, test_set, False)

            models[target_cls] = clf
            # tpr_avg.append(test_res[0])
            # fpr_avg.append(test_res[1])
            auc_avg.append(test_res[-1])
        
        # tpr_avg = float(np.mean(tpr_avg))
        # fpr_avg = float(np.mean(fpr_avg))
        auc_avg = float(np.mean(auc_avg))
        # print auc_avg
        if auc_avg >= auc_best:
            models_best = models
            auc_best = auc_avg
    print auc_best
    for k in models_best:
        joblib.dump(models_best[k], os.path.join(MODEL_DIR, '%s_model.pkl' % (k)))


def online_test(fin):
    feature_set_key = "ET"
    clfs = {}
    fp_cls = {}
    for target_cls in ["obfs3", "obfs4", "fte", "meek-amazon", "meek-google"]:
        clfs[target_cls] = joblib.load(os.path.join(MODEL_DIR, '%s_model.pkl' % (target_cls)))
        fp_cls[target_cls] = [] 

    f = open(fin)
    f.readline()
    for v in f:
        v = v.strip()
        tmp = v.split(",")
        fn, t = tmp[0], tmp[1:]
        inst = remove_features(t[:-1], feature_sets[feature_set_key])
        xtest = np.array(inst)
        for key in clfs:
            ypred = clfs[key].predict(xtest)[0]
            if ypred == "true":
                fp_cls[key].append(fn)
    f.close()
    print fp_cls

if __name__ == '__main__':
    # model_parameter_selection(False)
    # model_selection("no", "30", "ET", "DT")
    online_test("/media/Project/share/csv_test/4/norm/norm_no_30_0.csv")