import pandas
import time
import sys
import numpy as np
from threading import Thread
import random
from sklearn.experimental import enable_hist_gradient_boosting
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, \
    IsolationForest, ExtraTreesClassifier
from sklearn import ensemble
import lightgbm as lgb
from lightgbm.sklearn import LGBMClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from pyod.models.hbos import HBOS
from pyod.models.ocsvm import OCSVM
from sklearn.neighbors import KernelDensity, KNeighborsClassifier, LocalOutlierFactor
import catboost


def select_model(df: pandas.core.frame, algorithm: str, hyperparameter=None):
    print("算法选择：算法名称：{}".format(algorithm))
    # Split features and labels
    print(df.shape)
    x = df.drop(['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp', 'Label'], axis=1)
    print(x.shape)
    y = df['Label']
    clf = ""
    if algorithm == "HGB":
        if hyperparameter is not None:
            clf = ensemble.HistGradientBoostingClassifier(verbose=1, **hyperparameter)
            print("进入算法名称：{}".format("HistGradientBoostingClassifier"))
        else:
            clf = 0
    elif algorithm == "Lightgbm":
        if hyperparameter is not None:
            clf = LGBMClassifier(**hyperparameter)
            print("进入算法名称：{}".format("LGBMClassifier"))
        else:
            clf = 0
    elif algorithm == "ExtraTrees":
        if hyperparameter is not None:
            if 'max_depth' in hyperparameter:
                if hyperparameter['max_depth'] == 'None':
                    hyperparameter['max_depth'] = None
            clf = ExtraTreesClassifier(verbose=3, **hyperparameter)
            print("进入算法名称：{}".format("ExtraTreesClassifier"))
        else:
            clf = 0
    elif algorithm == "CART":
        z_scaler = StandardScaler()
        x = z_scaler.fit_transform(x.values)
        y = y.values
        if hyperparameter is not None:
            clf = DecisionTreeClassifier(**hyperparameter)
            print("进入算法名称：{}".format("DecisionTreeClassifier"))
        else:
            clf = 0

    elif algorithm == "HBOS":
        if hyperparameter is not None:
            clf = HBOS(**hyperparameter)
            print("进入算法名称：{}".format("HBOS"))

        else:
            clf = 0

    elif algorithm == "OCSVM":
        if hyperparameter is not None:
            clf = OCSVM(**hyperparameter)
        else:
            clf = 0

    elif algorithm == "RF":
        if hyperparameter is not None:
            clf = RandomForestClassifier(verbose=99, **hyperparameter)
        else:
            clf = 0

    elif algorithm == "Iforest":
        if hyperparameter is not None:
            clf = IsolationForest(verbose=99, **hyperparameter)
        else:
            clf = 0

    elif algorithm == "GBDT":
        if hyperparameter is not None:
            clf = GradientBoostingClassifier(verbose=99, random_state=10, **hyperparameter)
        else:
            clf = 0

    elif algorithm == "KDE":
        z_scaler = StandardScaler()
        x = z_scaler.fit_transform(x.values)
        y = y.values
        if hyperparameter is not None:
            clf = KernelDensity(**hyperparameter)
        else:
            clf = 0

    elif algorithm == "KNN":
        if hyperparameter is not None:
            clf = KNeighborsClassifier(**hyperparameter)
        else:
            clf = 0

    elif algorithm == "LOF":
        if hyperparameter is not None:
            clf = LocalOutlierFactor(novelty=True, **hyperparameter)
        else:
            clf = 0

    return clf, x, y


class Logger(object):
    def __init__(self, filename='default.log', stream=sys.stdout):
        self.terminal = stream
        self.log = open(filename, 'a', encoding='utf-8')

    def write(self, message):
        # self.terminal.write(message)
        # self.terminal.flush()
        self.log.write(message)
        self.log.flush()

    def flush(self):
        pass


# 要在后台运行的任务
def print_train_content(algorithm, start, stop_flag):
    while 1:
        print('%s算法正在训练,训练时长:%.2f秒' % (algorithm, time.time() - start))
        time.sleep(random.uniform(0, 3))
        if stop_flag():
            break


def train_model(algorithm, clf, x, y, train_log_path):
    cmd = sys.stdout
    sys.stdout = Logger(train_log_path, sys.stdout)
    # sys.stdout = open(train_log_path, mode='a', encoding='utf-8')
    start = time.time()

    # 清空loss
    open("loss.csv", "w")

    if algorithm == "Lightgbm":
        clf.fit(x, y, eval_set=[(x, y)], callbacks=[lgb.log_evaluation(1)])
    elif algorithm == 'CatBoost':
        clf.fit(x, y, log_cout=sys.stdout)
    elif algorithm in ['CART', 'KNN', 'HBOS', 'OCSVM', 'KDE', 'LOF']:
        stop_flag = False
        t = Thread(target=print_train_content, args=(algorithm, start, lambda: stop_flag))
        t.daemon = 1
        t.start()
        clf.fit(x, y)
        stop_flag = True
    else:
        clf.fit(x, y)

    end = time.time()
    # sys.stdout.close()
    sys.stdout = cmd

    return start, end


def test_model(algorithm, clf, x):
    if algorithm == "Iforest":
        y_pred = clf.predict(x)
        # 修改预测结果
        y_pred[y_pred == 1] = 0
        y_pred[y_pred == -1] = 1

    elif algorithm == "LOF":
        y_pred = clf.predict(x)
        # 修改预测结果
        y_pred[y_pred == 1] = 0
        y_pred[y_pred == -1] = 1

    elif algorithm == "KDE":
        dens_pred = clf.score_samples(x)
        y_pre = []
        for i in range(len(dens_pred)):
            if dens_pred[i] >= 0.3:
                y_pre.append(1)
            else:
                y_pre.append(0)
        y_pred = np.array(y_pre)

    else:
        y_pred = clf.predict(x)

    return y_pred

