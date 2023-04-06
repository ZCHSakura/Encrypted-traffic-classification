import logging
import numpy as np
import pandas as pd
import time
import dmPython
from utils.db_config import dm_user, dm_pwds, dm_host, dm_port, dm_db, origin_data_table, baseline_table

# Z-score中的K值，K值越大，阈值越大
k = 3

# Log setting
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S", level=logging.INFO)


def process():
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

    return df


def makebaseline(df):
    # 时间换成小时
    df['time'] = pd.to_datetime(df['time'], format='%Y/%m/%d %H:%M')
    df['time'] = df['time'].dt.strftime('%H')

    baseline_list = []
    ##############################################全局用户#################################################
    # 计算总基线
    times_total = df["time"].unique()
    total_in = {}
    total_out = {}
    total_threshold_in = {}
    total_threshold_out = {}
    for total_timehour in times_total:
        total_df_time = df[df["time"] == total_timehour]
        total_mean = total_df_time.mean()
        # 总出入基线
        total_mean_out, total_mean_in = total_mean["outlen"], total_mean["inlen"]
        total_std = total_df_time.std()
        total_std_out, total_std_in = total_std["outlen"], total_std["inlen"]

        # 总入基线上下阈值
        total_in_up = k * total_std_in + total_mean_in
        total_in_down = -k * total_std_in + total_mean_in
        if total_in_down < 0:
            total_in_down = 0

        # 总出基线上下阈值
        total_out_up = k * total_std_out + total_mean_out
        total_out_down = -k * total_std_out + total_mean_out
        if total_out_down < 0:
            total_out_down = 0

        total_threshold_in[int(total_timehour)] = [total_in_up, total_in_down]
        total_threshold_out[int(total_timehour)] = [total_out_up, total_out_down]
        total_in[int(total_timehour)] = [total_mean_in, total_std_in]
        total_out[int(total_timehour)] = [total_mean_out, total_std_out]

    # 添加0
    for i in range(24):
        if i not in total_in.keys():
            total_in[i] = [0, 0]
        if i not in total_out.keys():
            total_out[i] = [0, 0]
        if i not in total_threshold_in.keys():
            total_threshold_in[i] = [0, 0]
        if i not in total_threshold_out.keys():
            total_threshold_out[i] = [0, 0]

    # 排序
    total_in = dict(sorted(total_in.items(), key=lambda x: x[0]))
    total_out = dict(sorted(total_out.items(), key=lambda x: x[0]))
    total_threshold_in = dict(sorted(total_threshold_in.items(), key=lambda x: x[0]))
    total_threshold_out = dict(sorted(total_threshold_out.items(), key=lambda x: x[0]))

    dt = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(time.time())))

    # 输入多级字典数据
    baseline_total = {
        "sIP": "Total",
        "updatetime": dt,
        "baseline_in": str(total_in).replace('nan', '0.0'),
        "baseline_out": str(total_out).replace('nan', '0.0'),
        "threshold_in": str(total_threshold_in).replace('nan', '0.0'),
        "threshold_out": str(total_threshold_out).replace('nan', '0.0')
    }

    baseline_list.append(baseline_total)

    ##############################################单用户#################################################

    # 分别对每个源IP建基线
    sIPs = df["sIP"].unique()
    for sIP in sIPs:
        df_ip = df[df["sIP"] == sIP]

        times = df_ip["time"].unique()
        oneip_in = {}
        oneip_out = {}
        threshold_in = {}
        threshold_out = {}
        for timehour in times:
            df_ip_time = df_ip[df_ip["time"] == timehour]
            # print(df_ip_time)
            mean = df_ip_time.mean()
            # 出入基线
            mean_out, mean_in = mean["outlen"], mean["inlen"]
            std = df_ip_time.std()
            std_out, std_in = std["outlen"], std["inlen"]

            # 入基线上下阈值
            oneip_in_up = k * std_in + mean_in
            oneip_in_down = -k * std_in + mean_in
            if oneip_in_down < 0:
                oneip_in_down = 0

            # 出基线上下阈值
            oneip_out_up = k * std_out + mean_out
            oneip_out_down = -k * std_out + mean_out
            if oneip_out_down < 0:
                oneip_out_down = 0

            threshold_in[int(timehour)] = [oneip_in_up, oneip_in_down]
            threshold_out[int(timehour)] = [oneip_out_up, oneip_out_down]
            oneip_in[int(timehour)] = [mean_in, std_in]
            oneip_out[int(timehour)] = [mean_out, std_out]

        # 补0
        for i in range(24):
            if i not in oneip_in.keys():
                oneip_in[i] = [0, 0]
            if i not in oneip_out.keys():
                oneip_out[i] = [0, 0]
            if i not in threshold_in.keys():
                threshold_in[i] = [0, 0]
            if i not in threshold_out.keys():
                threshold_out[i] = [0, 0]

        # 排序
        oneip_in = dict(sorted(oneip_in.items(), key=lambda x: x[0]))
        oneip_out = dict(sorted(oneip_out.items(), key=lambda x: x[0]))
        threshold_in = dict(sorted(threshold_in.items(), key=lambda x: x[0]))
        threshold_out = dict(sorted(threshold_out.items(), key=lambda x: x[0]))

        dt = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(time.time())))

        # 输入多级字典数据
        baseline_all = {
            "sIP": sIP,
            "updatetime": dt,
            "baseline_in": str(oneip_in).replace('nan', '0.0'),
            "baseline_out": str(oneip_out).replace('nan', '0.0'),
            "threshold_in": str(threshold_in).replace('nan', '0.0'),
            "threshold_out": str(threshold_out).replace('nan', '0.0')
        }

        baseline_list.append(baseline_all)

    # print(baseline_list)

    baseline_list_tuple = [tuple(i.values()) for i in baseline_list]

    # 添加并更新基线
    db = dmPython.connect(user=dm_user, password=dm_pwds, server=dm_host, port=dm_port,
                          cursorclass=dmPython.DictCursor)
    cursor = db.cursor()

    sql = "merge into %s.%s " \
          "using (select ? sIP,? updatetime,? baseline_in,? baseline_out,? threshold_in,? threshold_out from dual) t " \
          "on(%s.%s.sIP = t.sIP) " \
          "when matched then " \
          "update set updatetime=t.updatetime,baseline_in=t.baseline_in,baseline_out=t.baseline_out,threshold_in=t.threshold_in,threshold_out=t.threshold_out " \
          "when not matched then " \
          "insert (sIP, updatetime, baseline_in, baseline_out, threshold_in, threshold_out) values(t.sIP,t.updatetime, t.baseline_in, t.baseline_out, t.threshold_in, t.threshold_out)" \
          % (dm_db, baseline_table, dm_db, baseline_table)
    try:
        cursor.executemany(sql, baseline_list_tuple)
        db.commit()
        print("更新成功")
    except Exception as e:
        print(e)
        db.rollback()
    finally:
        cursor.close()
        db.close()


if __name__ == '__main__':
    train_df = process()
    makebaseline(train_df)

    # while True:
    #     dt = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(time.time())))
    #     hour=dt.split(' ')[1].split(':')[0]
    #     minute=dt.split(':')[1]
    #     # print(hour+':'+minute)
    #
    #     # 每天00:00运行一次
    #     if hour=='00' and minute=='00':
    #         time.sleep(60)
    #         train_df = process()
    #         makebaseline(train_df)
