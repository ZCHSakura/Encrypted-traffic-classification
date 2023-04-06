import os.path
from utils.db_config import protocol_csv_path, protocol_model_path
from utils.make_db2csv import db2csv
from utils.train_proto_model import train

def train_protocol_model(public_csv_path, label_name):
    """
    使用公开数据集csv和数据库中数据进行协议识别多分类模型训练
    :param public_csv_path:公开数据集csv路径
    :param label_name:专有协议名称
    :return:model_path:训练出来的协议识别分类模型保存位置
    """
    os.makedirs(protocol_csv_path, exist_ok=True)
    os.makedirs(protocol_model_path, exist_ok=True)
    db2csv(label_name=label_name, csv_save_folder=protocol_csv_path)
    train(public_csv_path=public_csv_path, label_name=label_name)
    model_path = os.path.join(protocol_model_path, 'model.pkl')
    print(model_path)
    return model_path


if __name__ == '__main__':
    public_csv_path = 'D:/zch/laboratory/2022-3-加密流量/对接版程序/对接内容/AI/protocol_csv/data_all_pro.csv'
    label_name = 'Proprietary'
    train_protocol_model(public_csv_path, label_name)
