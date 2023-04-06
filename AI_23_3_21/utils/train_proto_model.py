import pandas as pd
import numpy as np
import logging
import os
import joblib
from sklearn.experimental import enable_hist_gradient_boosting
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from db_config import protocol_model_path, protocol_csv_path, cols_name


CIC_rename_dict = {
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'CWR Flag Count': 'CWE Flag Count',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward'
}


def process(df: pd.core.frame):
    print("Feature num:", df.shape[1] - 1)

    # Drop NaN
    nan_rows = df[df.isna().any(axis=1)].shape[0]
    logging.info("Del NaN in {} rows".format(nan_rows))

    # Drop inf
    inf_rows = df[df.isin([np.inf]).any(axis=1)].shape[0]
    logging.info("Del Inf in {} rows".format(inf_rows))
    df = df.replace([np.inf], np.nan)
    df = df.dropna(axis=0, how='any')

    # df[df < 0] = 0
    # df[df < 0] = np.nan
    # nan_rows = df[df.isna().any(axis=1)].shape[0]
    # logging.info("Still NaN in {} rows".format(nan_rows))

    return df


def train(public_csv_path, label_name, proto_csv_folder=protocol_csv_path, save_folder=protocol_model_path):
    """
    训练
    :param public_csv_path:选取的公开数据集csv文件位置
    :param save_folder:协议识别保存目录（默认路径写在db_config.py的protocol_model_path中）
    :return:无
    """
    data_list = []

    # 公开数据集
    tmp = pd.read_csv(public_csv_path)
    tmp = tmp.rename(columns=CIC_rename_dict)

    # 专有流量
    df = pd.read_csv(os.path.join(proto_csv_folder, label_name + '.csv'))

    # 合并数据集
    df = pd.concat([tmp, df], ignore_index=False)

    df = process(df)
    print("Class distribution\n{}".format(df.Label.value_counts()))

    x = df[['Protocol', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow IAT Std', 'Packet Length Std',
            'FIN Flag Count', 'SYN Flag Count', 'ACK Flag Count', 'Total Fwd Packets', 'Total Backward Packets',
            'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Packet Length Mean']]
    x = x.reindex(columns=cols_name)
    x = x.fillna(0)
    x = x.drop(['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp', 'Label'], axis=1)
    y = df['Label']

    # clf = HistGradientBoostingClassifier(verbose=1)
    clf = RandomForestClassifier(verbose=1)

    # 训练
    clf.fit(x, y)

    # 保存模型
    model_path = os.path.join(save_folder, 'model.pkl')
    joblib.dump(clf, model_path)


if __name__ == '__main__':
    csv_path = 'D:/zch/laboratory/2022-3-加密流量/对接版程序/对接内容/AI/protocol_csv/data_all_pro.csv'
    train(public_csv_path=csv_path, label_name='Proprietary')
