import os
import logging
import pandas as pd
import numpy as np
import time
import joblib
import json
import dmPython
import shutil
from sklearn import metrics
from sklearn.model_selection import train_test_split
from utils.models import select_model, train_model, test_model
from utils.db_config import dm_user, dm_pwds, dm_host, dm_port, dm_db, dm_table, data_types_dict, rename_col, cols_name, \
    extra_name, dm_res_table, extra_data_types_dict, protocol_model_path, Abnormal_Label_chinese_dict

# Log setting
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S", level=logging.INFO)


def process(csv_path: str):
    df = pd.read_csv(csv_path, skipinitialspace=True)

    print("Feature num:", df.shape[1] - 1)

    # Drop NaN
    nan_rows = df[df.isna().any(axis=1)].shape[0]
    logging.info("Del NaN in {} rows".format(nan_rows))

    # Drop inf
    inf_rows = df[df.isin([np.inf]).any(axis=1)].shape[0]
    logging.info("Del Inf in {} rows".format(inf_rows))
    df = df.replace([np.inf], np.nan)
    # df = df.dropna(axis=0, how='any')
    df = df.fillna(0)

    # df[df < 0] = 0
    # df[df < 0] = np.nan
    # nan_rows = df[df.isna().any(axis=1)].shape[0]
    # logging.info("Still NaN in {} rows".format(nan_rows))

    return df


def process_db(db_data: list):
    """
    处理数据库数据
    :param db_data:数据库数据
    :return: df
    """
    df = pd.DataFrame.from_records(db_data)

    # Drop NaN
    nan_rows = df[df.isna().any(axis=1)].shape[0]
    logging.info("Del NaN in {} rows".format(nan_rows))

    # Drop inf
    inf_rows = df[df.isin([np.inf]).any(axis=1)].shape[0]
    logging.info("Del Inf in {} rows".format(inf_rows))
    df = df.replace([np.inf], np.nan)
    # df = df.dropna(axis=0, how='any')
    df = df.fillna(0)

    if 'ip_client' in df.columns.tolist():
        df = df.astype(data_types_dict)
    elif 'ip_client'.upper() in df.columns.tolist():
        data_types_dict_upper = {}
        for i, j in data_types_dict.items():
            data_types_dict_upper[i.upper()] = j
        df = df.astype(data_types_dict_upper)

    df = df.astype(extra_data_types_dict)

    df['Timestamp'] = df.apply(lambda x: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(x['time_start'] / 1000000.0))), axis=1)
    df['Flow Duration'] = df.apply(lambda x: x['time_stop'] - x['time_start'] + 1, axis=1)
    df['Flow Bytes/s'] = df.apply(lambda x: (x['packet_up'] + x['packet_dn']) / x['Flow Duration'] * 1000000.0, axis=1)
    df['Flow Packets/s'] = df.apply(lambda x: (x['byte_up'] + x['byte_dn']) / x['Flow Duration'] * 1000000.0, axis=1)
    # df['Flow IAT Mean'] = df.apply(lambda x: x['Flow Duration'] / 1000000.0 / (x['packet_up'] + x['packet_dn']), axis=1)
    # 之前写成秒了，应该是微秒
    df['Flow IAT Mean'] = df.apply(lambda x: x['Flow Duration'] / (x['packet_up'] + x['packet_dn']), axis=1)
    df['Packet Length Mean'] = df.apply(lambda x: (x['byte_up'] + x['byte_dn']) / (x['packet_up'] + x['packet_dn']), axis=1)
    # print(df.head())


    if 'ip_client' in df.columns.tolist():
        df = df.rename(columns=rename_col)
    elif 'ip_client'.upper() in df.columns.tolist():
        rename_col_upper = {}
        for i, j in rename_col.items():
            rename_col_upper[i.upper()] = j
        df = df.rename(columns=rename_col_upper)
    # print(df.head())

    df = df.drop(['time_start', 'time_stop'], axis=1)
    # 重新排序列并补齐所有列
    df = df.reindex(columns=cols_name+extra_name)
    # 把补齐默认的nan转变为0
    df = df.fillna(0)

    print("Feature num:", df.shape[1] - 1)
    df_feature = df.iloc[:, :84]
    df_extra = df.iloc[:, 84:]

    return df_feature, df_extra


def model_init(config_path: str):
    """
    模型及参数初始化
    :param config_path: 配置文件路径
    :return: 算法及配置参数（json）
    """
    with open(config_path, encoding='utf-8')as file:
        file_json = ''.join(file.readlines())
    return file_json


def get_save_folder(algorithm_folder: str, algorithm: str, description=''):
    """
    获得当前训练模型保存文件夹和算法id
    :param algorithm_folder:算法文件夹位置
    :param algorithm:算法名称
    :param description:模型描述，备注
    :return:模型文件夹，算法id
    """
    # 获取当前时间
    time_now = time.strftime("%Y%m%d-%H%M%S", time.localtime())

    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 使用游标的execute()方法执行SQL查询
    sql = "insert into %s.%s(algorithm, create_time, description) values (?,?,?)" % (dm_db, dm_table)
    sql1 = "select id from %s.%s where create_time = ?" % (dm_db, dm_table)
    try:
        cursor.execute(sql, (algorithm, time_now, description))
        cursor.execute(sql1, time_now)
        db.commit()
        last_id = cursor.fetchone()
        try:
            last_id = last_id['ID']
        except:
            last_id = last_id['ID'.lower()]
        print("插入成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    # 创建本次训练模型文件夹
    save_folder = os.path.join(algorithm_folder, str(last_id) + '-' + time_now)
    os.makedirs(save_folder, exist_ok=True)
    # print(save_folder)
    return save_folder, last_id


def train(is_supervise: int, algorithm: str, id: str, csv_path: str, hyperparameter: dict, save_folder='./'):
    """
    训练
    :param is_supervise:是否有监督算法(0无监督，1有监督)
    :param algorithm:算法名称
    :param id:算法id
    :param csv_path:训练集位置
    :param hyperparameter:超参数字典
    :param save_folder:保存目录
    :return:无
    """
    if isinstance(hyperparameter, str):
        # print(hyperparameter)
        hyperparameter = eval(hyperparameter)

    df = process(csv_path)
    print("Class distribution\n{}".format(df.Label.value_counts()))

    clf, x, y = select_model(df, algorithm, hyperparameter)
    print(x.shape)

    X_train, X_valid, Y_train, Y_valid = train_test_split(x, y, stratify=y, test_size=0.2, random_state=621)

    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 写训练集ACC
    sql = "update %s.%s set csv_path=?,save_folder=?,hyperparameter=?,is_supervise=? where ID = ?" % (dm_db, dm_table)

    try:
        cursor.execute(sql, (csv_path, save_folder, str(hyperparameter), is_supervise, id))
        db.commit()
        print("修改成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()


    # 输出到文件
    train_log_path = os.path.join(save_folder, 'train.log')
    with open(train_log_path, mode='w', encoding='utf-8') as f:
        print('算法%s正在进行训练' % algorithm, file=f)
    start, end = train_model(algorithm, clf, X_train, Y_train, train_log_path)
    print('Training time: %s Seconds' % (end - start))

    # 保存模型
    model_path = os.path.join(save_folder, 'model.pkl')
    joblib.dump(clf, model_path)

    with open(train_log_path, 'a', encoding='utf-8') as f:
        print('训练完成\t训练用时%s Seconds\t模型保存在: %s' % ((end - start), save_folder), file=f)

    # 计算训练集和验证集指标
    if is_supervise == 1:
        with open(train_log_path, 'a', encoding='utf-8') as f:
            print('有监督算法开始进行训练集ACC计算', file=f)

        y_train_pred = test_model(algorithm, clf, X_train)
        train_accuracy = metrics.accuracy_score(y_true=Y_train, y_pred=y_train_pred)
        print('训练集ACC:', train_accuracy)

        with open(train_log_path, 'a', encoding='utf-8') as f:
            print('计算完成\t训练集准确率: %s' % train_accuracy, file=f)

        # 训练集同源数据进行验证
        y_valid_pred = test_model(algorithm, clf, X_valid)
        valid_accuracy = metrics.accuracy_score(y_true=Y_valid, y_pred=y_valid_pred)
        print("验证集ACC:", valid_accuracy)
        # precision，仅预测的正例中正例预测准的比例
        precision, recall, f1_score, _ = metrics.precision_recall_fscore_support(Y_valid, y_valid_pred, average='binary')
        res = pd.DataFrame([precision, recall, f1_score],
                           index=['Precision', 'Recall', 'F1_score'])
        print('验证集指标:\n', res)

        # 达梦
        db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                              cursorclass=dmPython.DictCursor)
        cursor = db.cursor()

        # 写训练集ACC和验证集指标
        sql = "update %s.%s set train_acc=?, valid_acc=?, valid_precision=?, valid_recall=?, valid_f1=? where ID = ?" % (dm_db, dm_table)

        try:
            cursor.execute(sql, (str(train_accuracy), str(valid_accuracy), str(precision), str(recall), str(f1_score), int(id)))
            db.commit()
            print("修改成功")
        except Exception as e:
            print(e)
            db.rollback()
        finally:
            cursor.close()
            db.close()

    with open(os.path.join(save_folder, 'hyperparameter.log'), 'a', encoding='utf-8') as f:
        print('训练超参数:\n%s' % hyperparameter, file=f)
    return id, save_folder


def offline_valid_test(is_supervise: int, model_id: int, algorithm: str, csv_path: str, flag: int):
    """
    离线验证和测试程序
    :param is_supervise:是否有监督算法(0无监督，1有监督)
    :param model_id:模型id
    :param algorithm:算法名称
    :param csv_path:数据集路径
    :param flag: 0：验证；1：离线测试
    :return:
        有监督算法离线验证: accuracy, precision, recall, f1_score
        有监督算法离线测试：result_csv_path, accuracy, precision, recall, f1_score
        无监督算法离线测试：result_csv_path
    """
    if flag == 0 and is_supervise == 0:
        print('有监督算法才能做验证！')
        return 0

    df = process(csv_path)

    # 数据库中寻找该id模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 写验证集ACC
    sql = "select save_folder from %s.%s where id = ?" % (dm_db, dm_table)

    save_folder = []
    try:
        cursor.execute(sql, model_id)
        save_folder = cursor.fetchone()
        print(save_folder)
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    try:
        folder_path = save_folder['SAVE_FOLDER']
    except:
        folder_path = save_folder['SAVE_FOLDER'.lower()]
    clf = joblib.load(os.path.join(folder_path, 'model.pkl'))
    print("Class distribution\n{}".format(df.Label.value_counts()))

    _, x, y = select_model(df, algorithm)

    start = time.time()
    y_pred = test_model(algorithm, clf, x)
    end = time.time()
    print('Testing time: %s Seconds' % (end - start))

    # 进行验证，一定是有监督
    if flag == 0:
        if is_supervise == 0:
            print('有监督算法才能做验证！')
            return 0
        # acc, 所有预测准的，包括负例和正例
        accuracy = metrics.accuracy_score(y_true=y, y_pred=y_pred)
        print("Accuracy:", accuracy)
        # precision，仅预测的正例中正例预测准的比例
        precision, recall, f1_score, _ = metrics.precision_recall_fscore_support(y, y_pred, average='binary')
        res = pd.DataFrame([precision, recall, f1_score],
                           index=['Precision', 'Recall', 'F1_score'])
        print(res)

        # 达梦
        db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                              cursorclass=dmPython.DictCursor)
        cursor = db.cursor()

        # 写验证集ACC
        sql = "update %s.%s set valid_acc=?, valid_precision=?, valid_recall=?, valid_f1=? where ID = ?" % (dm_db, dm_table)

        try:
            cursor.execute(sql, (accuracy, precision, recall, f1_score, model_id))
            db.commit()
            print("修改成功")
        except Exception as e:
            print(e)
            db.rollback()
        finally:
            cursor.close()
            db.close()

        # 写验证日志
        valid_log_path = os.path.join(folder_path, 'valid.log')
        valid_time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open(valid_log_path, 'a', encoding='utf-8') as f:
            print('%s验证完成\t验证集位置: %s' % (valid_time_now, csv_path), file=f)
            print('验证集准确率: %s\t验证集精确率: %s\t验证集召回率: %s\t验证集F1分数: %s\n'
                  % (accuracy, precision, recall, f1_score), file=f)

        return accuracy, precision, recall, f1_score
    # 离线测试，输出分类结果
    elif flag == 1:
        # 输出分类结果至文件
        x = df.reset_index(drop=True).drop(['Label'], axis=1)
        y_pred_df = pd.DataFrame(y_pred, columns=['Label'])
        x_y_pred_df = pd.concat([x, y_pred_df], axis=1)

        # 创建离线测试结果文件夹并写测试分类结果
        test_time_now_log = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        test_time_now = test_time_now_log.replace('-', '').replace(':', '').replace(' ', '-')
        test_save_folder = os.path.join(os.path.join(folder_path, 'offline_test'))
        os.makedirs(test_save_folder, exist_ok=True)
        result_csv_path = os.path.join(test_save_folder, '%s.csv' % test_time_now)
        x_y_pred_df.to_csv(result_csv_path, index=0)

        # 写测试日志
        test_log_path = os.path.join(folder_path, 'test.log')
        with open(test_log_path, 'a', encoding='utf-8') as f:
            print('%s离线测试完成\t测试集位置: %s\t离线测试分类结果位置: %s' % (test_time_now_log, csv_path, result_csv_path), file=f)

        # 有监督离线测试，输出指标
        if is_supervise == 1:
            # acc, 所有预测准的，包括负例和正例
            accuracy = metrics.accuracy_score(y_true=y, y_pred=y_pred)
            print("Accuracy:", accuracy)
            # precision，仅预测的正例中正例预测准的比例
            precision, recall, f1_score, _ = metrics.precision_recall_fscore_support(y, y_pred, average='binary')
            res = pd.DataFrame([precision, recall, f1_score],
                               index=['Precision', 'Recall', 'F1_score'])
            print(res)
            return result_csv_path, accuracy, precision, recall, f1_score

        return result_csv_path


def online_test(algorithm: str, csv_path: str, result_save_folder: str):
    """
    实时测试程序，返回分类结果保存路径
    :param algorithm:算法名称
    :param csv_path:数据集路径
    :param result_save_folder:分类结果保存路径文件夹
    :return: result_csv_path
    """
    df = process(csv_path)

    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 获取默认模型位置
    sql = "select save_folder from %s.%s where algorithm = ? and is_default=1" % (dm_db, dm_table)

    save_folder = []
    try:
        cursor.execute(sql, algorithm)
        save_folder = cursor.fetchall()
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    if len(save_folder) == 0:
        print('该算法没有默认模型')
        return 0
    elif len(save_folder) > 1:
        print('该算法默认模型过多')
        return 0

    try:
        folder_path = save_folder[0]['SAVE_FOLDER']
    except:
        folder_path = save_folder[0]['SAVE_FOLDER'.lower()]
    clf = joblib.load(os.path.join(folder_path, 'model.pkl'))
    print("Class distribution\n{}".format(df.Label.value_counts()))

    _, x, y = select_model(df, algorithm)

    start = time.time()
    y_pred = test_model(algorithm, clf, x)
    end = time.time()
    print('Testing time: %s Seconds' % (end - start))

    # 构建分类结果
    x = df.reset_index(drop=True).drop(['Label'], axis=1)
    y_pred_df = pd.DataFrame(y_pred, columns=['Label'])
    x_y_pred_df = pd.concat([x, y_pred_df], axis=1)

    # 输出分类结果至文件
    test_time_now_log = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    test_time_now = test_time_now_log.replace('-', '').replace(':', '').replace(' ', '-')
    os.makedirs(result_save_folder, exist_ok=True)
    result_csv_path = os.path.join(result_save_folder, '%s.csv' % test_time_now)
    x_y_pred_df.to_csv(result_csv_path, index=0)

    # 写测试日志
    test_log_path = os.path.join(folder_path, 'test.log')
    with open(test_log_path, 'a', encoding='utf-8') as f:
        print('%s实时预测完成\t测试集位置: %s\t实时预测分类结果位置: %s' % (test_time_now_log, csv_path, result_csv_path), file=f)

    return result_csv_path


def online_test_db(db_data: list, result_save_folder: str):
    """
    弃用，使用online_test_db_db将结果输出到数据库
    实时测试程序，返回分类结果保存路径
    :param db_data:数据库原始数据
    :param result_save_folder:分类结果保存路径文件夹
    :return: result_csv_path
    """
    df = process_db(db_data)

    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 获取默认模型位置
    sql = "select algorithm, save_folder from %s.%s where is_default=1" % (dm_db, dm_table)

    save_folder = []
    try:
        cursor.execute(sql)
        save_folder = cursor.fetchall()
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    if len(save_folder) == 0:
        print('没有默认模型')
        return 0
    elif len(save_folder) > 1:
        print('默认模型过多')
        return 0

    try:
        folder_path = save_folder[0]['SAVE_FOLDER']
    except:
        folder_path = save_folder[0]['SAVE_FOLDER'.lower()]

    try:
        algorithm = save_folder[0]['ALGORITHM']
    except:
        algorithm = save_folder[0]['ALGORITHM'.lower()]

    clf = joblib.load(os.path.join(folder_path, 'model.pkl'))
    print("Class distribution\n{}".format(df.Label.value_counts()))

    _, x, y = select_model(df, algorithm)

    start = time.time()
    y_pred = test_model(algorithm, clf, x)
    end = time.time()
    print('Testing time: %s Seconds' % (end - start))

    # 构建分类结果
    x = df.reset_index(drop=True).drop(['Label'], axis=1)
    y_pred_df = pd.DataFrame(y_pred, columns=['Label'])
    x_y_pred_df = pd.concat([x, y_pred_df], axis=1)

    # 输出分类结果至文件
    test_time_now_log = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    test_time_now = test_time_now_log.replace('-', '').replace(':', '').replace(' ', '-')
    os.makedirs(result_save_folder, exist_ok=True)
    result_csv_path = os.path.join(result_save_folder, '%s.csv' % test_time_now)
    x_y_pred_df.to_csv(result_csv_path, index=0)

    # 写测试日志
    test_log_path = os.path.join(folder_path, 'test.log')
    with open(test_log_path, 'a', encoding='utf-8') as f:
        print('%s实时预测完成\t实时预测分类结果位置: %s' % (test_time_now_log, result_csv_path), file=f)

    return result_csv_path


def model_list(algorithm: str):
    """
    根据算法返回已经训练的模型
    :param algorithm:算法名称
    :return: list
    """
    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 根据算法ID 查询训练实例
    sql = "select * from %s.%s where algorithm = ?" % (dm_db, dm_table)
    try:
        res = db.execute(sql, algorithm, with_column_types=True)
        db.disconnect()
        column, res_data, data = res[1], res[0], []
        for ele in res_data:
            each_dict = {}
            for i, k in enumerate(column):
                each_dict[k[0]] = ele[i]
            data.append(each_dict)
        print("查找成功")
        return data

    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()


def delete_model(model_id: int):
    """
    删除模型记录及其本地文件
    :param model_id:删除模型id
    :return:'删除成功' or 错误信息
    """
    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 写验证集ACC
    sql = "select save_folder from %s.%s where id = ?" % (dm_db, dm_table)
    sql1 = "delete from %s.%s where id = ?" % (dm_db, dm_table)

    try:
        cursor.execute(sql, model_id)
        save_folder = cursor.fetchone()
        try:
            save_folder = save_folder['SAVE_FOLDER']
        except:
            save_folder = save_folder['SAVE_FOLDER'.lower()]
        cursor.execute(sql1, model_id)
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    try:
        shutil.rmtree(save_folder)
    except OSError as e:
        print("Error: %s - %s." % (e.filename, e.strerror))

    print('删除成功')

def cancel_default(model_id: int):
    """
    模型设置为非默认
    :param model_id:
    :return:
    """
    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 写验证集ACC
    sql = "update %s.%s set is_default=0 where ID = ?" % (dm_db, dm_table)

    try:
        cursor.execute(sql, model_id)
        db.commit()
        print("取消默认成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()


def set_default(algorithm: str, model_id: int):
    """
    设置默认模型，并取消原有默认模型
    :param algorithm:算法名称
    :param model_id:要设置为默认模型的模型id
    :return:
    """
    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    sql = "select id from %s.%s where is_default=1" % (dm_db, dm_table)

    try:
        cursor.execute(sql, algorithm)
        default_model_id = cursor.fetchall()
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()

    if len(default_model_id) > 1:
        print('该算法存在多个默认模型，请确认数据库信息')
        return 0
    if len(default_model_id) == 1:
        default_model_id = default_model_id[0]
        try:
            default_model_id = default_model_id['ID']
        except:
            default_model_id = default_model_id['ID'.lower()]
        print('原本默认模型id: %s' % default_model_id)
        cancel_default(default_model_id)

    sql = "update %s.%s set is_default =  1 where ID = ? and algorithm = ?" % (dm_db, dm_table)

    try:
        cursor.execute(sql, (model_id, algorithm))
        db.commit()
        print("默认模型设置成功")
        return 1
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

def online_test_db_db(db_data: list):
    """
    使用online_test_db_db将结果输出到数据库
    实时测试程序，同时进行异常分类和协议识别
    :param db_data:数据库原始数据
    :return:
    """
    df, df_extra = process_db(db_data)

    # 数据库中寻找该算法默认模型
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 获取默认模型位置
    sql = "select algorithm, save_folder from %s.%s where is_default=1" % (dm_db, dm_table)

    save_folder = []
    try:
        cursor.execute(sql)
        save_folder = cursor.fetchall()
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    if len(save_folder) == 0:
        print('没有默认模型')
        return 0
    elif len(save_folder) > 1:
        print('默认模型过多')
        return 0

    try:
        folder_path = save_folder[0]['SAVE_FOLDER']
    except:
        folder_path = save_folder[0]['SAVE_FOLDER'.lower()]

    try:
        algorithm = save_folder[0]['ALGORITHM']
    except:
        algorithm = save_folder[0]['ALGORITHM'.lower()]

    # 加载训练好的模型
    clf_ab = joblib.load(os.path.join(folder_path, 'model.pkl'))
    clf_proto = joblib.load(os.path.join(protocol_model_path, 'model.pkl'))

    # 获取训练数据
    _, x, y = select_model(df, algorithm)

    start = time.time()
    # 获取分类结果
    y_pred_ab = test_model(algorithm, clf_ab, x)
    y_pred_proto = clf_proto.predict(x)

    end = time.time()
    print('Testing time: %s Seconds' % (end - start))

    # 构建异常分类结果
    feature = df.reset_index(drop=True).drop(['Label'], axis=1)
    y_pred_ab_df = pd.DataFrame(y_pred_ab, columns=['Abnormal_Label'])
    y_pred_proto_df = pd.DataFrame(y_pred_proto, columns=['Protocol_Label'])
    x_y_pred_df = pd.concat([feature, y_pred_ab_df, y_pred_proto_df, df_extra], axis=1)

    # 分类结果改成中文
    x_y_pred_df['Abnormal_Label'] = x_y_pred_df.apply(lambda x: Abnormal_Label_chinese_dict[str(x['Abnormal_Label'])], axis=1)

    test_time_now_log = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    # 输出分类结果至数据库
    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)

    # 构造sql语句
    column_name_list = cols_name[:-1] + ['Abnormal_Label', 'Protocol_Label'] + extra_name
    cursor = db.cursor()
    column_name = "\"" + '\",\"'.join(column_name_list) + "\""
    sss = '?' + ',?'*101

    # 将dataframe处理成列表
    # x_y_pred_df_list = []
    # for indexs in x_y_pred_df.index:
    #     x_y_pred_df_list.append([int(i) if type(i) == np.int64 or type(i) == np.int32 else i for i in x_y_pred_df.loc[indexs].values[:]])

    x_y_pred_df_list = x_y_pred_df.values.tolist()

    # 使用游标的execute()方法执行SQL
    sql = "insert into %s.%s (%s) values (%s)" % (dm_db, dm_res_table, column_name, sss)
    try:
        cursor.executemany(sql, x_y_pred_df_list)
        db.commit()
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    # 写测试日志
    test_log_path = os.path.join(folder_path, 'test.log')
    with open(test_log_path, 'a', encoding='utf-8') as f:
        print('%s实时预测完成' % (test_time_now_log), file=f)

    return 0


if __name__ == '__main__':
    # hyperparameter = {'max_iter': 100} # hgb
    # hyperparameter = {'learning_rate': 0.1}   # lightgbm
    # hyperparameter = {'n_estimators':100, 'max_samples':256, 'contamination':0.5}   # Iforest
    # hyperparameter = {'n_estimators':100, 'max_depth':None}   # RF
    # hyperparameter = {'splitter':'best', 'max_depth':None, 'min_samples_split':2} # CART
    # hyperparameter = {'contamination':0.25}   # OCSVM
    # hyperparameter = {'iterations': 1000, 'depth': 5, 'learning_rate': 0.002, 'loss_function': 'Logloss'} # catboost
    # hyperparameter = {'n_estimators':100,'learning_rate':0.1,'max_depth':3,'min_samples_split':2,'min_samples_leaf':1} # gbdt
    # hyperparameter = {'n_neighbors':5} # KNN
    # hyperparameter = {'kernel':'gaussian', 'bandwidth':0.2} # kde
    # hyperparameter = {'n_neighbors':20, 'contamination':0.5} # lof

    # algorithm_folder = r'D:\zch\laboratory\2022-3-加密流量\对接版程序'

    # 有监督
    algorithm = 'HGB'   # ok
    # algorithm = 'Lightgbm'    # ok
    # algorithm = 'CART'
    # algorithm = 'RF'
    # algorithm = 'GBDT'  # ok
    # algorithm = 'ExtraTrees'
    # algorithm = 'KNN'

    # 无监督
    # algorithm = 'HBOS'
    # algorithm = 'OCSVM'
    # algorithm = 'LOF'
    # algorithm = 'KDE'
    # algorithm = 'Iforest'

    #config_path = r'/home/gckj/code/config/parm.json'
    #result = model_init(config_path=config_path)

    algorithm_folder = r'D:\zch\laboratory\2022-3-加密流量\对接版程序\对接内容\AI'
    # algorithm = "HGB"
    # algorithm = "Iforest"
    description = '这里是模型描述'
    save_folder, id = get_save_folder(algorithm_folder, algorithm, description)
    print('模型id：{}'.format(id))

    is_supervise = 1
    # train_path = 'D:/zch/laboratory/2022-3-加密流量/对接版程序/20220531_1659_000.pcap_Flow.csv'
    train_path = 'D:/zch/laboratory/2022-3-加密流量/对接版程序/对接内容/AI/data/test1.csv'
    # train_path = r'D:\zch\laboratory\2022-3-加密流量\MachineLearningCVE\ProcessedDataset\联调数据\meter\样本\有标签_data3.csv'
    # hyperparameter = {'n_estimators': 100, 'max_samples': 256, 'contamination': 0.5}  # Iforest
    # hyperparameter = {}  #
    hyperparameter = {'max_iter': 101}  # hgb
    train(is_supervise, algorithm, id, train_path, hyperparameter, save_folder)

    #   0 验证 1  离线
    flag = 1
    model_id = 170
    # test_path = 'D:/zch/laboratory/2022-3-加密流量/对接版程序/20220531_1659_000.pcap_Flow.csv'
    test_path = r'D:\zch\laboratory\2022-3-加密流量\MachineLearningCVE\ProcessedDataset\联调数据\meter\样本\有标签_data7.csv'
    # result_csv_path = offline_valid_test(is_supervise, model_id, algorithm, test_path, flag=flag)
    # print("离线数据测试结果：{}".format(result_csv_path))

    result_save_folder = r'D:\zch\laboratory\2022-3-加密流量\对接版程序\对接内容\AI\实时预测'
    # online_test(algorithm, test_path, result_save_folder)

    delete_model_id = 144
    # delete_model(delete_model_id)

    algorithm = 'HGB'
    # set_default(algorithm, 151)

    # cancel_default(145)

    # f = open('db_json_new.json', 'r')
    # # 读取demp.json文件内容
    # j = json.load(f)
    #
    # db_data = j
    # result_save_folder = r'D:\zch\laboratory\2022-3-加密流量\对接版程序\对接内容\AI\实时预测'
    # online_test_db_db(db_data)


