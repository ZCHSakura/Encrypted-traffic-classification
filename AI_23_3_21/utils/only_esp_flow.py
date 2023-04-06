from scapy.all import *
import numpy as np
import pandas as pd
from datetime import datetime


# ------------------------------------ ESP ------------------------------------ #
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#


# ------------------------------------ MAIN ------------------------------------ #
features = ['源IP', '源端口', '目的IP', '目的端口', '协议', '时间戳', '流持续时间(µs)', '每微秒流字节数(Bytes/µs)', '每微秒流包数(Packets/µs)',
            '前向数据包大小(Bytes)', '后向数据包大小(Bytes)', '数据包间隔时间均值(µs)', '数据包间隔时间标准差(µs)', '数据包大小均值(Bytes)',
            '数据包大小标准差(Bytes)', '带有FIN的数据包数', '带有SYN的数据包数', '带有ACK的数据包数']

features = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Flow Bytes/s',
            'Flow Packets/s',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow IAT Mean', 'Flow IAT Std',
            'Packet Length Mean',
            'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'ACK Flag Count']

csv_feature_data = list()  # 最后转化为DataFrame输出的数据
ip_groups_esp = dict()


def extract(packet):
    get_g_esp(packet)


def process(path):
    sniff(prn=extract, lfilter=lambda x: ESP in x, offline=path)
    print('read done.')
    process_esp()
    print('process done.')
    return pd.DataFrame(data=csv_feature_data, columns=features)


if __name__ == '__main__':
    df = process('VPN_ESP&TLS_20211019.pcapng')
    df.to_csv('flow_features.csv', index=False)
    print('csv文件已生成.')
