import subprocess
import os
import pandas as pd
import time
from utils.db_config import CIC_dfm
from utils.only_esp_flow import process as process_only_esp


def check_java_env():
    # 检查环境变量是否包含Java环境目录

    with os.popen("echo $PATH") as f:
        str_path = f.read()
        if "jre" not in str_path:
            print("ERROR $PATH without jre env: {}".format(str_path))
    pass


def load_csv():
    df = pd.read_csv('./extract_csv/有标签_data1.csv', skipinitialspace=True)
    return df


def unsupervise_extract(mode_id: int, pcap_list: list, csv_save_folder: str):
    """
    无监督算法流量特征提取，包含训练，离线测试和在线测试
    :param mode_id:
        1为训练;
        2为离线测试;
        3为在线测试;
    :param pcap_list: 要进行特征提取的pcap包路径列表(在线测试时里面只能包含一个)
    :param csv_save_folder: 提取出的csv文件要保存的目录
    :return: csv_save_path: 提取出的csv文件路径
    """
    
    check_java_env()
    print(CIC_dfm)
    print(pcap_list)
    time_now = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    os.makedirs(csv_save_folder, exist_ok=True)
    if mode_id not in [1, 2, 3]:
        print('mode_id出错')
        return 0

    if mode_id == 3:
        try:
            assert len(pcap_list) == 1
        except:
            print('在线测试时pcap_list中只能包含一个pcap包')
            return 0

    for pcap_path in pcap_list:
        pcap_name = pcap_path.split(os.sep)[-1].replace('.pcap', '')
        cmd = '%s %s %s' % (CIC_dfm, pcap_path, csv_save_folder)
        p = subprocess.Popen(cmd, shell=True)
        return_code = p.wait()
        csv_path = os.path.join(csv_save_folder, pcap_name + '.pcap_Flow.csv')
        if pcap_path == pcap_list[0]:
            df = pd.read_csv(csv_path, skipinitialspace=True)
            df = df.drop(df[df['Protocol'] == int('0')].index)
            df_esp = process_only_esp(pcap_path)
            df = pd.concat([df, df_esp], ignore_index=True)
        else:
            temp_df = pd.read_csv(csv_path, skipinitialspace=True)
            temp_df = temp_df.drop(temp_df[temp_df['Protocol'] == int('0')].index)
            temp_df_esp = process_only_esp(pcap_path)
            temp_df = pd.concat([temp_df, temp_df_esp], ignore_index=True)

            df = pd.concat([df, temp_df], ignore_index=True)
        # os.remove(csv_path)

    csv_save_path = os.path.join(csv_save_folder, '无标签-%s.csv' % time_now)
    df.to_csv(csv_save_path, index=0)
    return csv_save_path


def supervise_extract(mode_id: int, pcap_list: list, norm_pcap_list: list,
                      abnorm_pcap_list: list, csv_save_folder: str):
    """
    有监督算法流量特征提取，包含训练，离线测试和在线测试
    :param mode_id:
        1为训练;
        2为离线测试;
        3为在线测试;
    :param pcap_list: 在线测试要进行特征提取的pcap包路径列表(里面只能包含一个)
    :param norm_pcap_list: 训练和离线测试要进行特征提取的全正常流量pcap包路径列表(至少包含一个)
    :param abnorm_pcap_list: 训练和离线测试要进行特征提取的全异常流量pcap包路径列表(至少包含一个)
    :param csv_save_folder: 提取出的csv文件要保存的目录
    :return: csv_save_path: 提取出的csv文件路径
    """
    
    check_java_env()
    print(CIC_dfm)
    print(norm_pcap_list)
    print(abnorm_pcap_list)
    time_now = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    os.makedirs(csv_save_folder, exist_ok=True)

    if mode_id not in [1, 2, 3]:
        print('mode_id出错')
        return 0

    if mode_id == 3:
        try:
            assert len(pcap_list) == 1
        except:
            print('在线测试时pcap_list中只能包含一个pcap包')
            return 0
    else:
        try:
            assert len(norm_pcap_list) > 0 and len(abnorm_pcap_list) > 0
        except:
            print('需要同时包含正常和异常pcap包')
            return 0

    if mode_id == 3:
        pcap_path = pcap_list[0]
        pcap_name = pcap_path.split(os.sep)[-1].replace('.pcap', '')
        cmd = '%s %s %s' % (CIC_dfm, pcap_path, csv_save_folder)
        p = subprocess.Popen(cmd, shell=True)
        return_code = p.wait()
        csv_path = os.path.join(csv_save_folder, pcap_name + '.pcap_Flow.csv')
        df = pd.read_csv(csv_path, skipinitialspace=True)
    else:
        for pcap_path in norm_pcap_list:
            pcap_name = pcap_path.split(os.sep)[-1].replace('.pcap', '')
            cmd = '%s %s %s' % (CIC_dfm, pcap_path, csv_save_folder)
            p = subprocess.Popen(cmd, shell=True)
            return_code = p.wait()
            csv_path = os.path.join(csv_save_folder, pcap_name + '.pcap_Flow.csv')
            if pcap_path == norm_pcap_list[0]:
                df_norm = pd.read_csv(csv_path, skipinitialspace=True)
                df_norm = df_norm.drop(df_norm[df_norm['Protocol'] == int('0')].index)
                df_norm_esp = process_only_esp(pcap_path)
                df_norm = pd.concat([df_norm, df_norm_esp], ignore_index=True)
            else:
                temp_df = pd.read_csv(csv_path, skipinitialspace=True)
                temp_df = temp_df.drop(temp_df[temp_df['Protocol'] == int('0')].index)
                temp_df_esp = process_only_esp(pcap_path)
                temp_df = pd.concat([temp_df, temp_df_esp], ignore_index=True)

                df_norm = pd.concat([df_norm, temp_df], ignore_index=True)
            df_norm['Label'] = 0
            os.remove(csv_path)

        for pcap_path in abnorm_pcap_list:
            pcap_name = pcap_path.split(os.sep)[-1].replace('.pcap', '')
            cmd = '%s %s %s' % (CIC_dfm, pcap_path, csv_save_folder)
            p = subprocess.Popen(cmd, shell=True)
            return_code = p.wait()
            csv_path = os.path.join(csv_save_folder, pcap_name + '.pcap_Flow.csv')
            if pcap_path == abnorm_pcap_list[0]:
                df_abnorm = pd.read_csv(csv_path, skipinitialspace=True)
                df_abnorm = df_abnorm.drop(df_abnorm[df_abnorm['Protocol'] == int('0')].index)
                df_abnorm_esp = process_only_esp(pcap_path)
                df_abnorm = pd.concat([df_abnorm, df_abnorm_esp], ignore_index=True)
            else:
                temp_df = pd.read_csv(csv_path, skipinitialspace=True)
                temp_df = temp_df.drop(temp_df[temp_df['Protocol'] == int('0')].index)
                temp_df_esp = process_only_esp(pcap_path)
                temp_df = pd.concat([temp_df, temp_df_esp], ignore_index=True)
                df_abnorm = pd.concat([df_abnorm, temp_df], ignore_index=True)
            df_abnorm['Label'] = 1
            os.remove(csv_path)
            
        df = pd.concat([df_abnorm, df_norm], ignore_index=True)

    csv_save_path = os.path.join(csv_save_folder, '有标签-%s.csv' % time_now)
    df.to_csv(csv_save_path, index=0)
    return csv_save_path


if __name__ == '__main__':
    # pcap_list = ['/home/zhouchenghao/test1.pcap', '/home/zhouchenghao/test2.pcap', '/home/zhouchenghao/test3.pcap']
    pcap_list = ['E:/laboratory/2022-3-加密流量/AI/esp/VPN_ESP&TLS_20211019.pcapng', 'E:/laboratory/2022-3-加密流量/AI/esp/VPN_ESP&TLS_20211019.pcapng', 'E:/laboratory/2022-3-加密流量/AI/esp/VPN_ESP&TLS_20211019.pcapng']
    csv_save_folder = './extract_csv'
    mode_id = 1
    _ = unsupervise_extract(mode_id, pcap_list, csv_save_folder)

    norm_pcap_list = ['/home/zhouchenghao/test1.pcap', '/home/zhouchenghao/test3.pcap']
    abnorm_pcap_list = ['/home/zhouchenghao/test2.pcap']
    pcap_list = ['/home/zhouchenghao/test1.pcap']
    mode_id = 2
    # _ = supervise_extract(mode_id, pcap_list, norm_pcap_list, abnorm_pcap_list, csv_save_folder)

    print(_)

    # pcap_path = '/home/zhouchenghao/20220531_1659_000.pcap'
    # csv_folder = '/home/zhouchenghao'
    #
    # cmd = '/home/zhouchenghao/Traffic/CICFlowMeter-master/build/distributions/CICFlowMeter-4.0/bin/cfm %s %s' % (pcap_path, csv_folder)
    # p = subprocess.Popen(cmd, shell=True)
    # return_code = p.wait()
    # print(return_code)
    # print('wuhuqifei')
