import os.path

import pandas as pd
import dmPython
import logging
import numpy as np
import time
from db_config import data_types_dict, rename_col, cols_name, protocol_csv_path


dm_user = "SYSDBA"
dm_pwds = "SYSDBA"
dm_host = "LOCALHOST"
dm_port = 5236
dm_db = "CIC"
dm_table = "GC_GEN_ESP"


def db2csv(label_name, csv_save_folder=protocol_csv_path):
    db_cols_name = ["ip_client", "port_client", "ip_server", "port_server", "ip_proto", "time_start", "time_stop", "packet_up",
                    "packet_dn", "byte_up", "byte_dn", "time_standard", "byte_standard", "count_fin", "count_syn", "count_ack"]

    # db_cols_name = [i.upper() for i in db_cols_name]

    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 构造sql
    column_name = "\"" + '\",\"'.join(db_cols_name) + "\""
    sql = "select %s from %s.%s" % (column_name, dm_db, dm_table)

    try:
        cursor.execute(sql)
        db_data = cursor.fetchall()
        db.commit()
        print("查找成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    df = pd.DataFrame.from_records(db_data)

    if 'ip_client' in df.columns.tolist():
        df = df.astype(data_types_dict)
    elif 'ip_client'.upper() in df.columns.tolist():
        data_types_dict_upper = {}
        for i, j in data_types_dict.items():
            data_types_dict_upper[i.upper()] = j
        df = df.astype(data_types_dict_upper)


    # Drop NaN
    nan_rows = df[df.isna().any(axis=1)].shape[0]
    logging.info("Del NaN in {} rows".format(nan_rows))

    # Drop inf
    inf_rows = df[df.isin([np.inf]).any(axis=1)].shape[0]
    logging.info("Del Inf in {} rows".format(inf_rows))
    df = df.replace([np.inf], np.nan)
    df = df.dropna(axis=0, how='any')

    df['Timestamp'] = df.apply(lambda x: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(x['time_start'] / 1000000.0))), axis=1)
    df['Flow Duration'] = df.apply(lambda x: x['time_stop'] - x['time_start'], axis=1)
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
    df = df.reindex(columns=cols_name)
    # 把补齐默认的nan转变为0
    df = df.fillna(0)

    print("Feature num:", df.shape[1] - 1)

    df['Label'] = label_name

    df.to_csv(os.path.join(csv_save_folder, label_name + '.csv'), index=False)


if __name__ == '__main__':
    csv_save_folder = protocol_csv_path
    label_name = 'Proprietary'
    db2csv(label_name, csv_save_folder)
