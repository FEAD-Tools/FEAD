import torch
from torch_geometric.data import Data, InMemoryDataset
import pandas as pd
from io import StringIO
import json
import csv
def process_csv_data(csv_data):
    df = pd.read_csv(StringIO(csv_data), na_values = ['NA', 'NaN'])
    df.fillna('', inplace=True)
    result_dict = {}
    for index, row in df.iterrows():
        key = row['obj_subj']
        value = json.loads(row["anomaly_score"])[0]
        result_dict[key] = value
    return result_dict

class TestDataset(InMemoryDataset):
    def __init__(self, data_list):
        super(TestDataset, self).__init__('/tmp/TestDataset')
        self.data, self.slices = self.collate(data_list)
    def _download(self):
        pass
    def _process(self):
        pass

def GenerateTestDataset(data_path, model_path, with_anomaly = False):
    feature_num = 0
    label_num = 0
    feature_map = {}
    label_map = {}
    with open(model_path + 'feature.txt', 'r') as f_feature:
        for i in f_feature:
            temp = i.strip('\n').split('\t')
            feature_map[temp[0]] = int(temp[1])
            feature_num += 1
    if with_anomaly:
        feature_num += 1
    with open(model_path + 'label.txt', 'r') as f_label:
        for i in f_label:
            temp = i.strip('\n').split('\t')
            label_map[temp[0]] = int(temp[1])
            label_num += 1
    ground_truth = {}
    with open('groundtruth_id.txt', 'r') as f_gt:
        for line in f_gt:
            ground_truth[line.strip('\n')] = 1

    node_cnt = 0
    node_id2index_map = {}
    node_index2id_map = {}
    provenance = []
    edge_s = []
    edge_e = []
    adjTargetToSource = {}
    adjSourceToTarget = {}

    fw1 = open('index_to_id.txt', 'w')
    fw2 = open('groundtruth_index_type_id.txt', 'w')

    malicious_nodeinfo_path = ""
    malicious_node_dict = {}
    if with_anomaly:
        malicious_nodeinfo_path = data_path + 'nodes_with_encode_reduce_index_deldup_anomaly_malicious.csv'
        csv_data = ""
        with open(malicious_nodeinfo_path,"r") as r:
                csv_data = r.read()
        malicious_node_dict = process_csv_data(csv_data)

    gtNode = []
    with open(data_path + "test.txt", 'r') as f:
        for line in f:
            temp = line.strip('\n').split('\t')
            #useless data
            if not (temp[1] in label_map.keys()): continue
            if not (temp[3] in label_map.keys()): continue
            if not (temp[4] in feature_map.keys()): continue

            if not (temp[0] in node_id2index_map.keys()):
                node_id2index_map[temp[0]] = node_cnt
                node_index2id_map[node_cnt] = temp[0]
                fw1.write(str(node_cnt) + ' ' + temp[0] + '\n')
                if temp[0] in ground_truth.keys():
                    fw2.write(str(node_id2index_map[temp[0]]) + ' ' + temp[1] + ' ' + temp[0] + '\n')
                    gtNode.append(node_cnt)
                node_cnt += 1
            temp[0] = node_id2index_map[temp[0]]
            if not (temp[2] in node_id2index_map.keys()):
                node_id2index_map[temp[2]] = node_cnt
                node_index2id_map[node_cnt] = temp[2]
                fw1.write(str(node_cnt) + ' ' + temp[2] + '\n')
                if temp[2] in ground_truth.keys():
                    fw2.write(str(node_id2index_map[temp[2]]) + ' ' + temp[3] + ' ' + temp[2] + '\n')
                    gtNode.append(node_cnt)
                node_cnt += 1
            temp[2] = node_id2index_map[temp[2]]
            temp[1] = label_map[temp[1]]
            temp[3] = label_map[temp[3]]
            temp[4] = feature_map[temp[4]]
            edge_s.append(temp[0])
            edge_e.append(temp[2])

            if temp[2] in adjTargetToSource.keys():
                adjTargetToSource[temp[2]].append(temp[0])
            else:
                adjTargetToSource[temp[2]] = [temp[0]]
            if temp[0] in adjSourceToTarget.keys():
                adjSourceToTarget[temp[0]].append(temp[2])
            else:
                adjSourceToTarget[temp[0]] = [temp[2]]
            provenance.append(temp)
    
    fw1.close()
    fw2.close()
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

    with open('node_features.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = ['EdgeID', 'NodeId', 'Features', 'Type']
        csvwriter.writerow(headers)
        index = 0
        for temp in provenance:
            srcId = temp[0]
            srcType = temp[1]
            dstId = temp[2]
            dstType = temp[3]
            edge = temp[4]

            x_list[srcId][edge] += 1
            src_id = node_index2id_map[srcId]
            if with_anomaly:
                src_info = malicious_node_dict.get(src_id, 0)
                x_list[srcId][feature_num - 1] = src_info
            y_list[srcId] = srcType

            x_list[dstId][edge + feature_num] += 1
            dst_id = node_index2id_map[dstId]
            if with_anomaly:
                dst_info = malicious_node_dict.get(dst_id, 0)
                x_list[dstId][feature_num * 2 - 1] = dst_info
            y_list[dstId] = dstType

            label = "0"
            if srcId in gtNode:
                label = "1"
            csvwriter.writerow([str(index),src_id, x_list[srcId], srcType,label])        
            label = "0"
            if dstId in gtNode:
                label = "1"
            csvwriter.writerow([str(index),dst_id, x_list[dstId], dstType,label])
            index += 1

    x = torch.tensor(x_list, dtype=torch.float)	
    y = torch.tensor(y_list, dtype=torch.long)
    train_mask = torch.tensor(train_mask, dtype=torch.bool)
    test_mask = torch.tensor(test_mask, dtype=torch.bool)
    edge_index = torch.tensor([edge_s, edge_e], dtype=torch.long)
    data1 = Data(x=x, y=y,edge_index=edge_index, train_mask=train_mask, test_mask = test_mask)
    feature_num *= 2 

    gtNode2HopSet = set()
    twoHopTogtNode = {}
    for i in gtNode:
        gtNode2HopSet.add(i)
        if not i in twoHopTogtNode.keys():
            twoHopTogtNode[i] = []
        if not i in twoHopTogtNode[i]:
            twoHopTogtNode[i].append(i)
        if i in adjTargetToSource.keys():
            for j in adjTargetToSource[i]:
                gtNode2HopSet.add(j)
                if not j in twoHopTogtNode.keys():
                    twoHopTogtNode[j] = []
                if not i in twoHopTogtNode[j]:
                    twoHopTogtNode[j].append(i)	
                if not j in adjTargetToSource.keys(): 
                    continue
                for k in adjTargetToSource[j]:
                    gtNode2HopSet.add(k)
                    if not k in twoHopTogtNode.keys():
                        twoHopTogtNode[k] = []
                    if not i in twoHopTogtNode[k]:
                        twoHopTogtNode[k].append(i)
        # i->j->k
        if i in adjSourceToTarget.keys():
            for j in adjSourceToTarget[i]:
                gtNode2HopSet.add(j)
                if not j in adjSourceToTarget.keys(): 
                    continue
                for k in adjSourceToTarget[j]:
                    gtNode2HopSet.add(k)
    gtNode2Hop = list(gtNode2HopSet)
    #gtNode: GroundTruth Node
    #gtNode2Hop 是一个List，用于存储gtNode两跳内的节点, 包括gtNode本身
    #twoHopTogtNode是一个字典，它的键是两跳内可以到达gtNode的节点, k->j->i(包括gtNode本身)，值是一个列表，里面是它可以到达的gtNode中的节点
    if with_anomaly:
       malicious_node_list=[]
       for item in malicious_node_dict.keys():
           if malicious_node_dict[item]>0 and item in node_id2index_map:
            malicious_node_list.append(node_id2index_map[item]) 
       return [data1], feature_num, label_num, adjTargetToSource, adjSourceToTarget, gtNode, gtNode2Hop, twoHopTogtNode, malicious_node_list,provenance
    
    return [data1], feature_num, label_num, adjTargetToSource, adjSourceToTarget, gtNode, gtNode2Hop, twoHopTogtNode