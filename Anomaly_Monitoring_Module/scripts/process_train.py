import time
import torch
import pandas as pd
import json
from io import StringIO
from torch_geometric.data import Data, InMemoryDataset

class TrainDataset(InMemoryDataset):
    def __init__(self, data_list):
        super(TrainDataset, self).__init__('/tmp/TestDataset')
        self.data, self.slices = self.collate(data_list)
    def _download(self):
        pass
    def _process(self):
        pass

def process_csv_data(csv_data):
    df = pd.read_csv(StringIO(csv_data), na_values=['NA', 'NaN'])
    df.fillna('', inplace=True)
    result_dict = {}
    for index, row in df.iterrows():
        key = row['obj_subj']
        value = json.loads(row["anomaly_score"])[0]
        result_dict[key] = value    
    return result_dict

def GenerateTrainDataset(data_path, model_path, with_anomaly = False):
    node_cnt = 0
    provenance = []
    nodeType_cnt = 0
    edgeType_cnt = 0
    nodeType_map = {}
    edgeType_map = {}
    edge_s = [] 
    edge_e = [] 
    nodeId_map = {}
    nodeId_map_reverse = {}

    benign_nodeinfo_path = ""
    benign_node_dict = {}
    if with_anomaly:
        benign_nodeinfo_path = data_path + 'nodes_with_encode_reduce_index_deldup_anomaly_benign.csv'
        csv_data = ""
        with open(benign_nodeinfo_path,"r") as r:
            csv_data = r.read()
        benign_node_dict = process_csv_data(csv_data)

    with open(data_path + "train.txt", 'r') as f:
        for line in f:
            temp = line.strip('\n').split('\t')
            if not (temp[0] in nodeId_map.keys()):
                nodeId_map[temp[0]] = node_cnt
                nodeId_map_reverse[node_cnt]=temp[0]
                node_cnt += 1
            temp[0] = nodeId_map[temp[0]]	
            if not (temp[2] in nodeId_map.keys()):
                nodeId_map[temp[2]] = node_cnt
                nodeId_map_reverse[node_cnt]=temp[2]
                node_cnt += 1
            temp[2] = nodeId_map[temp[2]]
            if not (temp[1] in nodeType_map.keys()):
                nodeType_map[temp[1]] = nodeType_cnt
                nodeType_cnt += 1
            temp[1] = nodeType_map[temp[1]]
            if not (temp[3] in nodeType_map.keys()):
                nodeType_map[temp[3]] = nodeType_cnt
                nodeType_cnt += 1
            temp[3] = nodeType_map[temp[3]]
            if not (temp[4] in edgeType_map.keys()):
                edgeType_map[temp[4]] = edgeType_cnt
                edgeType_cnt += 1
            temp[4] = edgeType_map[temp[4]]
            edge_s.append(temp[0])
            edge_e.append(temp[2])
            provenance.append(temp)
    with open(model_path + 'feature.txt', 'w') as feature_fp:
        for i in edgeType_map.keys():
            feature_fp.write(str(i)+'\t'+str(edgeType_map[i])+'\n')
    with open(model_path + 'label.txt', 'w') as label_fp:
        for i in nodeType_map.keys():
            label_fp.write(str(i)+'\t'+str(nodeType_map[i])+'\n')
    feature_num = edgeType_cnt
    if with_anomaly:
        feature_num = edgeType_cnt + 1
    label_num = nodeType_cnt

    x_list = []
    y_list = []
    train_mask = []
    test_mask = []
    for i in range(node_cnt):
        temp_list = []
        for j in range(feature_num*2):
            temp_list.append(0)
        x_list.append(temp_list)
        y_list.append(0)
        train_mask.append(True)
        test_mask.append(True)

    for temp in provenance:
        srcId = temp[0]
        srcType = temp[1]
        dstId = temp[2]
        dstType = temp[3]
        edge = temp[4]
        x_list[srcId][edge] += 1
        if with_anomaly:
            src_id = nodeId_map_reverse[srcId]
            src_info = benign_node_dict.get(src_id, 0)
            x_list[srcId][feature_num - 1] = src_info
        y_list[srcId] = srcType
        x_list[dstId][edge + feature_num] += 1
        if with_anomaly:
            dst_id = nodeId_map_reverse[dstId]
            dst_info = benign_node_dict.get(dst_id, 0)
            x_list[dstId][feature_num * 2 - 1] = dst_info
        y_list[dstId] = dstType

    x = torch.tensor(x_list, dtype = torch.float)
    y = torch.tensor(y_list, dtype = torch.long)
    train_mask = torch.tensor(train_mask, dtype = torch.bool)
    test_mask = train_mask
    edge_index = torch.tensor([edge_s, edge_e], dtype = torch.long)
    data = Data(x = x, y = y, edge_index = edge_index, train_mask = train_mask, test_mask = test_mask)
    feature_num *= 2
    return [data], feature_num, label_num
