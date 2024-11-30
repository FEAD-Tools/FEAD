import pandas as pd

frame=pd.read_csv('./audibeat-log-full/nodes_with_encode_reduce_index.csv',engine='python')
data = frame.drop_duplicates(subset=['obj_subj_index'], keep='first', inplace=False)
data.to_csv('./audibeat-log-full/nodes_with_encode_reduce_index_deldup.csv', encoding='utf8')