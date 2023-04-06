import datetime
import logging
import numpy as np
import pandas as pd
import time
import dmPython
from utils.db_config import dm_user, dm_pwds, dm_host, dm_port, dm_db, origin_data_table, baseline_table, baseline_abnormal_table

# Log setting
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S", level=logging.INFO)


def process(dt):
    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 使用游标的execute()方法执行SQL查询
    sql = "select time_start, ip_client, byte_up, byte_dn from %s.%s" % (dm_db, origin_data_table)
    try:
        cursor.execute(sql)
        origin_data = cursor.fetchall()
        db.commit()
        print("查询成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    print(origin_data)

    df = pd.DataFrame.from_records(origin_data)

    data_types_dict = {
        "time_start": float,
        "ip_client": str,
        "byte_up": float,
        "byte_dn": float
    }

    df = df.astype(data_types_dict)

    rename_col = {
        'time_start': 'time',
        'ip_client': 'sIP',
        'byte_up': 'outlen',
        'byte_dn': 'inlen'
    }

    df = df.rename(columns=rename_col)

    df['time'] = df.apply(lambda x: time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(float(x['time'] / 1000000.0))),
                          axis=1)

    # Drop NaN
    nan_rows = df[df.isna().any(axis=1)].shape[0]
    logging.info("Del NaN in {} rows".format(nan_rows))

    # Drop inf
    inf_rows = df[df.isin([np.inf]).any(axis=1)].shape[0]
    logging.info("Del Inf in {} rows".format(inf_rows))
    df = df.replace([np.inf], np.nan)
    df = df.dropna(axis=0, how='any')

    # 取近一个小时的数据
    dt = datetime.datetime.strptime(dt, "%Y/%m/%d %H:%M:%S")
    begin = (dt + datetime.timedelta(hours=-1)).strftime("%Y/%m/%d %H:%M:%S")
    end = dt.strftime("%Y/%m/%d %H:%M:%S")
    df1 = df[(df['time'] >= begin) & (df['time'] < end)]
    return df1


def baselinetest(df):
    # print(df)
    df1 = df.copy()
    baselines = []
    baseline_total = {}

    # 取基线
    # fopen = open("baseline.txt")
    # for line in fopen:
    #     line = line.strip("\n")
    #     output_dict = json.loads(line)
    #     if output_dict['sIP'] == 'Total':
    #         baseline_total = output_dict
    #     else:
    #         baselines.append(output_dict)
    # fopen.close()

    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 使用游标的execute()方法执行SQL查询
    sql = "select sIP, updatetime, baseline_in, baseline_out, threshold_in, threshold_out from %s.%s" % (dm_db, baseline_table)
    try:
        cursor.execute(sql)
        baseline_data = cursor.fetchall()
        db.commit()
        print("查询成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()

    baseline_total = [i for i in baseline_data if i['sIP'] == 'Total'][0]
    baselines = [i for i in baseline_data if i['sIP'] != 'Total']

    # 时间换成小时
    df['time'] = pd.to_datetime(df['time'], format='%Y/%m/%d %H:%M')
    df['time'] = df['time'].dt.strftime('%H')

    # cmd = sys.stdout
    # sys.stdout = open('baselinetest.log', mode='w', encoding='utf-8')
    # start = time.time()

    #########################################单用户#######################################
    # 对每条数据检测
    abnormal_list = []
    # f = open("baselinetest.txt", 'a')
    for index, row in df.iterrows():
        # print(index, type(row), row['time'], row['sIP'], row['outlen'], row['inlen'])
        for baseline in baselines:
            try:
                baseline['threshold_in'] = eval(baseline['threshold_in'])
                baseline['threshold_out'] = eval(baseline['threshold_out'])
            except:
                pass
            if baseline['sIP'] == row['sIP']:
                abnormal_in = 0
                abnormal_out = 0

                # 检测入流量是否超出上下阈值
                threshold_in_up = baseline['threshold_in'][int(row['time'])][0]
                threshold_in_down = baseline['threshold_in'][int(row['time'])][1]

                if row['inlen'] > threshold_in_up or row['inlen'] < threshold_in_down:
                    abnormal_in = 1

                # 检测出流量是否超出上下阈值
                threshold_out_up = baseline['threshold_out'][int(row['time'])][0]
                threshold_out_down = baseline['threshold_out'][int(row['time'])][1]
                if row['outlen'] > threshold_out_up or row['outlen'] < threshold_out_down:
                    abnormal_out = 1

                if abnormal_in + abnormal_out >= 1:
                    result = {
                        "sIP": row['sIP'],
                        "time": df1.loc[index]['time'],
                        "inlen": row['inlen'],
                        "inlen_abnormal": abnormal_in,
                        "outlen": row['outlen'],
                        "outlen_abnormal": abnormal_out,
                    }
                    # result_json = json.dumps(result)
                    # f.write(result_json)
                    # f.write('\n')
                    abnormal_list.append(tuple(result.values()))

    #########################################全局用户#######################################
    # 对总流量检测
    times_total = df["time"].unique()
    baseline_total['threshold_in'] = eval(baseline_total['threshold_in'])
    baseline_total['threshold_out'] = eval(baseline_total['threshold_out'])
    for total_timehour in times_total:
        total_df_time = df[df["time"] == total_timehour]
        total_mean = total_df_time.mean()
        total_mean_out, total_mean_in = total_mean["outlen"], total_mean["inlen"]

        abnormal_total_in = 0
        abnormal_total_out = 0

        # 检测入流量是否超出上下阈值
        threshold_total_in_up = baseline_total['threshold_in'][int(row['time'])][0]
        threshold_total_in_down = baseline_total['threshold_in'][int(row['time'])][1]

        if total_mean_in > threshold_total_in_up or total_mean_in < threshold_total_in_down:
            abnormal_total_in = 1

        # 检测出流量是否超出上下阈值
        threshold_total_out_up = baseline_total['threshold_out'][int(row['time'])][0]
        threshold_total_out_down = baseline_total['threshold_out'][int(row['time'])][1]

        if total_mean_out > threshold_total_out_up or total_mean_out < threshold_total_out_down:
            abnormal_total_out = 1

        if abnormal_total_in + abnormal_total_out >= 1:
            dt = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(time.time())))
            result_total = {
                "sIP": "Total",
                "time": dt,
                "inlen": total_mean_in,
                "inlen_abnormal": abnormal_total_in,
                "outlen": total_mean_out,
                "outlen_abnormal": abnormal_total_out,
            }
            # result_total_json = json.dumps(result_total)
            # f.write(result_total_json)
            # f.write('\n')
            abnormal_list.append(tuple(result_total.values()))
    # f.close()
    print(abnormal_list)

    # 达梦
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    # 使用游标的execute()方法执行SQL查询
    sql = "insert into %s.%s(sIP, time, inlen, inlen_abnormal, outlen, outlen_abnormal) values (?,?,?,?,?,?)" % (dm_db, baseline_abnormal_table)
    try:
        cursor.executemany(sql, abnormal_list)
        db.commit()
        print("插入成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()


if __name__ == '__main__':
    dt = '2021/06/29 15:07:55'
    test_df = process(dt)
    baselinetest(test_df)

    # while True:
    #     dt = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(time.time())))
    #     minute = dt.split(':')[1]
    #     second = dt.split(':')[2]
    #     # print(minute+':'+second)
    #
    #     # 每小时运行一次
    #     if minute == '00' and (second == '00' or second == '01'):
    #         test_df = process(dt)
    #         baselinetest(test_df)
    #         time.sleep(2)
