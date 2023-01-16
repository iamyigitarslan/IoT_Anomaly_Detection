from pickle import TRUE
import pandas as pd
import numpy as np

capture_34 = "$your_folder_path/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled"
capture_43 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-43-1/bro/conn.log.labeled"
capture_44 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled"
capture_49 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-49-1/bro/conn.log.labeled"
capture_52 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-52-1/bro/conn.log.labeled"
capture_20 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled"
capture_21 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-21-1/bro/conn.log.labeled"
capture_42 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled"
capture_60 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-60-1/bro/conn.log.labeled"
capture_17 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-17-1/bro/conn.log.labeled"
capture_36 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-36-1/bro/conn.log.labeled"
capture_33 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-33-1/bro/conn.log.labeled"
capture_8 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled"
capture_35 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-35-1/bro/conn.log.labeled"
capture_48 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-48-1/bro/conn.log.labeled"
capture_39 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-39-1/bro/conn.log.labeled"
capture_7 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-7-1/bro/conn.log.labeled"
capture_9 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-9-1/bro/conn.log.labeled"
capture_3 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled"
capture_1 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled"
capture_41 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled"
capture_51 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled"
capture_71 = "$your_folder_path/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled"

df34 = pd.read_table(filepath_or_buffer=capture_34, skiprows=10, nrows=400000) 
df34.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df34.drop(df34.tail(1).index,inplace=True)

df43 = pd.read_table(filepath_or_buffer=capture_43, skiprows=10, nrows=400000)
df43.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df43.drop(df43.tail(1).index,inplace=True)

df44 = pd.read_table(filepath_or_buffer=capture_44, skiprows=10, nrows=400000)
df44.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df44.drop(df44.tail(1).index,inplace=True)

df49 = pd.read_table(filepath_or_buffer=capture_49, skiprows=10, nrows=400000)
df49.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df49.drop(df49.tail(1).index,inplace=True)

df52 = pd.read_table(filepath_or_buffer=capture_52, skiprows=10, nrows=400000)
df52.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df52.drop(df52.tail(1).index,inplace=True)

df20 = pd.read_table(filepath_or_buffer=capture_20, skiprows=10, nrows=400000)
df20.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df20.drop(df20.tail(1).index,inplace=True)

df21 = pd.read_table(filepath_or_buffer=capture_21, skiprows=10, nrows=400000)
df21.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df21.drop(df21.tail(1).index,inplace=True)

df42 = pd.read_table(filepath_or_buffer=capture_42, skiprows=10, nrows=400000)
df42.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df42.drop(df42.tail(1).index,inplace=True)

df60 = pd.read_table(filepath_or_buffer=capture_60, skiprows=10, nrows=400000)
df60.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df60.drop(df60.tail(1).index,inplace=True)

df17 = pd.read_table(filepath_or_buffer=capture_17, skiprows=10, nrows=400000)
df17.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df17.drop(df17.tail(1).index,inplace=True)

df36 = pd.read_table(filepath_or_buffer=capture_36, skiprows=10, nrows=400000)
df36.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df36.drop(df36.tail(1).index,inplace=True)

df33 = pd.read_table(filepath_or_buffer=capture_33, skiprows=10, nrows=400000)
df33.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df33.drop(df33.tail(1).index,inplace=True)

df8 = pd.read_table(filepath_or_buffer=capture_8, skiprows=10, nrows=400000)
df8.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df8.drop(df8.tail(1).index,inplace=True)

df35 = pd.read_table(filepath_or_buffer=capture_35, skiprows=10, nrows=400000)
df35.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df35.drop(df35.tail(1).index,inplace=True)

df48 = pd.read_table(filepath_or_buffer=capture_48, skiprows=10, nrows=400000)
df48.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df48.drop(df48.tail(1).index,inplace=True)

df39 = pd.read_table(filepath_or_buffer=capture_39, skiprows=10, nrows=400000)
df39.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df39.drop(df39.tail(1).index,inplace=True)

df7 = pd.read_table(filepath_or_buffer=capture_7, skiprows=10, nrows=400000)
df7.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df7.drop(df7.tail(1).index,inplace=True)

df9 = pd.read_table(filepath_or_buffer=capture_9, skiprows=10, nrows=400000)
df9.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df9.drop(df9.tail(1).index,inplace=True)

df3 = pd.read_table(filepath_or_buffer=capture_3, skiprows=10, nrows=400000)
df3.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df3.drop(df3.tail(1).index,inplace=True)

df1 = pd.read_table(filepath_or_buffer=capture_1, skiprows=10, nrows=400000)
df1.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df1.drop(df1.tail(1).index,inplace=True)

df41 = pd.read_table(filepath_or_buffer=capture_41, skiprows=10, nrows=400000)
df41.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df41.drop(df41.tail(1).index,inplace=True)

df51 = pd.read_table(filepath_or_buffer=capture_51, skiprows=10, nrows=400000)
df51.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df51.drop(df51.tail(1).index,inplace=True)

df71 = pd.read_table(filepath_or_buffer=capture_71, skiprows=10, nrows=400000)
df71.columns=['ts',
              'uid',
              'id.orig_h',
              'id.orig_p',
              'id.resp_h',
              'id.resp_p',
              'proto',
              'service',
              'duration',
              'orig_bytes',
              'resp_bytes',
              'conn_state',
              'local_orig',
              'local_resp',
              'missed_bytes',
              'history',
              'orig_pkts',
              'orig_ip_bytes',
              'resp_pkts',
              'resp_ip_bytes',
              'label']
df71.drop(df71.tail(1).index,inplace=True)

frames=[df1, df17, df20, df21, df3, df33, df34, df35, df36, df39, df42, df43, df44, df48, df49, df52, df60, df7, df8, df9, df41, df51, df71]

df_c=pd.concat(frames)

df_c['label'].value_counts()

df_c.loc[(df_c.label == '-   Malicious   PartOfAHorizontalPortScan'), 'label'] = 'PartOfAHorizontalPortScan'
df_c.loc[(df_c.label == '(empty)   Malicious   PartOfAHorizontalPortScan'), 'label'] = 'PartOfAHorizontalPortScan'
df_c.loc[(df_c.label == '-   Malicious   Okiru'), 'label'] = 'Okiru'
df_c.loc[(df_c.label == '(empty)   Malicious   Okiru'), 'label'] = 'Okiru'
df_c.loc[(df_c.label == '-   Benign   -'), 'label'] = 'Benign'
df_c.loc[(df_c.label == '-   benign   -'), 'label'] = 'Benign'
df_c.loc[(df_c.label == '(empty)   Benign   -'), 'label'] = 'Benign'
df_c.loc[(df_c.label == '-   Malicious   DDoS'), 'label'] = 'DDoS'
df_c.loc[(df_c.label == '-   Malicious   C&C'), 'label'] = 'C&C'
df_c.loc[(df_c.label == '(empty)   Malicious   C&C'), 'label'] = 'C&C'
df_c.loc[(df_c.label == '-   Malicious   Attack'), 'label'] = 'Attack'
df_c.loc[(df_c.label == '(empty)   Malicious   Attack'), 'label'] = 'Attack'
df_c.loc[(df_c.label == '-   Malicious   C&C-HeartBeat'), 'label'] = 'C&C-HeartBeat'
df_c.loc[(df_c.label == '(empty)   Malicious   C&C-HeartBeat'), 'label'] = 'C&C-HeartBeat'
df_c.loc[(df_c.label == '-   Malicious   C&C-FileDownload'), 'label'] = 'C&C-FileDownload'
df_c.loc[(df_c.label == '-   Malicious   C&C-Torii'), 'label'] = 'C&C-Torii'
df_c.loc[(df_c.label == '-   Malicious   C&C-HeartBeat-FileDownload'), 'label'] = 'C&C-HeartBeat-FileDownload'
df_c.loc[(df_c.label == '-   Malicious   FileDownload'), 'label'] = 'FileDownload'
df_c.loc[(df_c.label == '-   Malicious   C&C-Mirai'), 'label'] = 'C&C-Mirai'
df_c.loc[(df_c.label == '-   Malicious   Okiru-Attack'), 'label'] = 'Okiru-Attack'

df_c['label'].value_counts()

pd.options.display.max_rows = 300
pd.options.display.max_columns = 300



df_c = pd.get_dummies(df_c, columns=['proto'])
df_c = pd.get_dummies(df_c, columns=['conn_state'])

df_c.to_csv('dump')

df_c = df_c.drop(columns=['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p', 'service','local_orig','local_resp','history','missed_bytes','proto_icmp','proto_tcp','conn_state_OTH','conn_state_REJ','conn_state_RSTOS0','conn_state_RSTRH','conn_state_S0','conn_state_SH','conn_state_SHR'])

df_c = df_c.replace('-', np.nan)

df_c.interpolate(inplace=True)
df_c.dropna(inplace=True)

print(df_c.isnull().sum())

df_c.to_csv('iot23_combined12-4b.csv')