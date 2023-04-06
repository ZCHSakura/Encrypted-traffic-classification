from scapy.all import *
import numpy as np
import pandas as pd
from datetime import datetime


# ------------------------------------ ESP ------------------------------------ #
def process_esp():
    spi_groups = get_h()
    flow_groups = get_f(spi_groups)
    extract_features_esp(flow_groups)


## 根据IP对分组 G1 G2 G3...
def get_g_esp(packet):
    srcIp = packet[IP].src  # 传输模式适用，隧道模式未知
    dstIp = packet[IP].dst
    if (srcIp, dstIp) in ip_groups_esp.keys():
        ip_groups_esp[(srcIp, dstIp)].append(packet)
    elif (dstIp, srcIp) in ip_groups_esp.keys():
        ip_groups_esp[(dstIp, srcIp)].append(packet)
    else:
        ip_groups_esp[(srcIp, dstIp)] = [packet]


## 根据SPI分组 H1 H2 H3...
def get_h():
    spi_groups = dict()

    for ips, packets in ip_groups_esp.items():
        spi_groups[ips] = dict()
        for packet in packets:
            spi = packet['ESP'].spi
            if spi in spi_groups[ips].keys():
                spi_groups[ips][spi].append(packet)
            else:
                spi_groups[ips][spi] = list()
    return spi_groups


## 根据相应字节组成流 F1,F2,F3,...
### 获取ori中第start~end字节的字节列表(列表长度为4)
def byte_list(ori, start, end):
    return [ori[start - 1], ori[start], ori[start + 1], ori[start + 2]]


### 得到packet归属的流，返回流在flow_dict中的key值，不归属于任何流则返回-1
def join_flow(packet, flow_dict, flow_count):
    # ESP载荷第14个字节满足X & 0x20 == 0
    if packet['ESP'].original[13] & 0x20 == 0:
        A = byte_list(packet['ESP'].original, 17, 20)
        B = byte_list(packet['ESP'].original, 21, 24)
    # ESP载荷第14个字节满足X & 0x20 != 0
    else:
        A = byte_list(packet['ESP'].original, 33, 36)
        B = byte_list(packet['ESP'].original, 37, 40)

    # 在flow_count个分组中查找能插入的流分组
    for i in range(1, flow_count + 1):
        first_packet = flow_dict[i][0]  # 取第一个包
        if first_packet['ESP'].original[13] & 0x20 == 0:
            A_temp = byte_list(first_packet['ESP'].original, 17, 20)
            B_temp = byte_list(first_packet['ESP'].original, 21, 24)
        # ESP载荷第14个字节满足X & 0x20 != 0
        else:
            A_temp = byte_list(first_packet['ESP'].original, 33, 36)
            B_temp = byte_list(first_packet['ESP'].original, 37, 40)
        if A == A_temp or A == B_temp or A_temp == B:
            return i
    return -1


### 分流
def get_f(spi_groups):
    flow_groups = dict()

    for ips, spi_dict in spi_groups.items():
        flow_groups[ips] = dict()
        for spi, packets in spi_dict.items():
            flow_groups[ips][spi] = dict()
            flow_count = 0  # 记录SPI中F(即流)的个数
            # 根据seq排序（升序），这样可保证后续分流时也为升序
            packets.sort(key=lambda x: x['ESP'].seq, reverse=False)

            # SPI == 0x00000000的分组H
            if spi == 0:
                # 检查每个包，是否可以加入到现有的流分组，若不能，创建一个新的分组
                for packet in packets:
                    index = join_flow(packet, flow_groups[ips][spi], flow_count)
                    if index == -1:
                        flow_count += 1
                        flow_groups[ips][spi][flow_count] = [packet]
                    else:
                        flow_groups[ips][spi][index].append(packet)
            # SPI != 0x00000000的分组H
            else:
                flow_groups[ips][spi][1] = packets
            return flow_groups


## 提取ESP协议的流特征
def extract_features_esp(flow_groups):
    for ips, spi_dict in flow_groups.items():
        for spi, flow_dict in spi_dict.items():
            for flow_id, packets in flow_dict.items():
                size_packets = len(packets)  # 流的包数
                if size_packets == 1:
                    continue
                len_packets = [p.len for p in packets]  # 包大小(IP及以上层的大小)数组
                timestamps = [datetime.fromtimestamp(float(p.time)) for p in packets]  # 数据包时间戳数组
                timeDelta_packets = [td.microseconds for td in np.diff(timestamps)]  # 包间隔时间差列表(µs)
                duration = (timestamps[size_packets - 1] - timestamps[0]).microseconds  # 流持续时间
                total_len = np.sum(len_packets)  # 所有包的字节加和

                forward_len = 0  # 前向数据包大小
                backward_len = 0  # 后向数据包大小
                # 统计前/后向数据包大小

                for packet in packets:
                    if packet['IP'].src == ips[0]:  # 前向
                        forward_len += packet.len
                    else:
                        backward_len += packet.len

                flow_features = [ips[0],
                                 0,
                                 ips[1],
                                 0,
                                 8,
                                 timestamps[0].strftime('%Y-%m-%d %H:%M:%S'),
                                 duration,
                                 float(total_len / duration * 1000000.0),
                                 float(size_packets / duration * 1000000.0),
                                 forward_len,
                                 backward_len,
                                 np.mean(timeDelta_packets),
                                 np.std(timeDelta_packets),
                                 np.mean(len_packets),
                                 np.std(len_packets),
                                 0,
                                 0,
                                 0
                                 ]
                csv_feature_data.append(flow_features)


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
