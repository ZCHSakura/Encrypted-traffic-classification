dm_user = "SYSDBA"
dm_pwds = "***"
dm_host = "LOCALHOST"
dm_port = 5236
dm_db = "CIC"
dm_table = "model_list"
dm_res_table = "ONLINE_TEST_RES"

CIC_dfm = "/CICFlowMeter-master/build/distributions/CICFlowMeter-4.0/bin/cfm"

protocol_model_path = '/AI/protocol_model'
protocol_csv_path = '/AI/protocol_csv'

Abnormal_Label_chinese_dict = {
    '0': '正常',
    '1': '异常',
}

data_types_dict = {
    "ip_client": str,
    "port_client": int,
    "ip_server": str,
    "port_server": int,
    "ip_proto": str,
    "time_start": float,
    "time_stop": float,
    "packet_up": int,
    "packet_dn": int,
    "byte_up": float,
    "byte_dn": float,
    "time_standard": float,
    "byte_standard": float,
    "count_fin": int,
    "count_syn": int,
    "count_ack": int,
}

extra_data_types_dict = {
    "ID": int,
    "STREAM_ID": int,
    "TASK_ID": int,
    "FID": int,
    "OID": int,
    "TIME_START": int,
    "TIME_STOP": int,
    "PACKET_UP": int,
    "PACKET_DN": int,
    "BYTE_UP": int,
    "BYTE_DN": int,
}

rename_col = {
    'ip_client': 'Src IP',
    'port_client': 'Src Port',
    'ip_server': 'Dst IP',
    'port_server': 'Dst Port',
    'ip_proto': 'Protocol',
    'byte_up': 'Total Length of Fwd Packets',
    'byte_dn': 'Total Length of Bwd Packets',
    'time_standard': 'Flow IAT Std',
    'byte_standard': 'Packet Length Std',
    'count_fin': 'FIN Flag Count',
    'count_syn': 'SYN Flag Count',
    'count_ack': 'ACK Flag Count',
    'packet_up': 'Total Fwd Packets',
    'packet_dn': 'Total Backward Packets'
}

cols_name = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration',
             'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
             'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
             'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
             'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
             'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
             'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
             'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
             'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
             'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
             'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
             'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
             'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
             'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
             'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
             'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
             'Idle Max', 'Idle Min', 'Label']

extra_name = ['ID', 'STREAM_ID', 'TASK_ID', 'FID', 'OID', 'TIME_START', 'TIME_STOP', 'PACKET_UP', 'PACKET_DN',
              'BYTE_UP', 'BYTE_DN', 'CLIENTCOUNTRY', 'CLIENTCITY', 'CLIENTISP', 'SERVERCOUNTRY', 'SERVERCITY',
              'SERVERISP']
