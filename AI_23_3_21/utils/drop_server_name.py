import pandas as pd

df = pd.read_csv(r'D:/zch/laboratory/2022-3-加密流量/对接版程序/对接内容/AI/vpn-nonvpn_new/csv/Coarse_all/data_all_pro.csv')

df['Label'] = df['service_name']
df = df.drop(['service_name'], axis=1)
print(df.head())
df = df.drop(['Unnamed: 0', 'Unnamed: 0.1'], axis=1)

df.to_csv(r"D:\zch\laboratory\2022-3-加密流量\对接版程序\对接内容\AI\protocol_csv\data_all_pro_new.csv", index=False)