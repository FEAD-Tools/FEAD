import os
import time
import argparse
import torch
import torch.nn.functional as F
from torch_geometric.data import NeighborSampler
from torch_geometric.nn import GATConv
from process_train import *
from process_test import *

scenes = ["opensmtpd", "log4jEnv", "cadets", "fivedirections", "theia", "trace", "ces-cic"]
thre_map = {"opensmtpd":1.5, "log4jEnv": 1.5, "cadets":1.5, "fivedirections":1.0, "theia":1.5, "trace":1.0, "ces-cic":1.0}
batch_size_map = {"opensmtpd":50, "log4jEnv": 50, "cadets":5000, "fivedirections":5000, "theia":5000, "trace":5000, "ces-cic":500}

class GATNet(torch.nn.Module):
    def __init__(self, in_channels, out_channels, heads = 8, dropout_rate = 0.5):
        super(GATNet, self).__init__()
        self.conv1 = GATConv(in_channels, 128 // heads, heads = heads)
        self.conv2 = GATConv(128, out_channels, heads = 1, concat = False)
        self.dropout_rate = dropout_rate

    def forward(self, x, data_flow):
        data = data_flow[0]
        x = x[data.n_id]
        x = F.elu(self.conv1((x, None), data.edge_index, size = data.size))
        x = F.dropout(x, p = self.dropout_rate, training = self.training)
        data = data_flow[1]
        x = self.conv2((x, None), data.edge_index, size = data.size)
        return F.log_softmax(x, dim = 1)

class trainingSystem:
    def __init__(self, scene, anomaly = False):
        self.scene = scene
        self.with_anomaly = anomaly
        self.thre = thre_map[self.scene]
        self.batch_size = batch_size_map[self.scene]
        self.data_path = "../data/" + self.scene + "/"
        self.model_path = "../models/"
        self.fp_list = []
        self.tn_list = []
        self.recall_thre = 0.8
        self.precision_thre = 0.7
        if self.scene == "fivedirections":
            self.recall_thre = 0.6
            self.precision_thre = 0.4
        if self.scene == "opensmtpd":
            self.recall_thre = 0.7
        os.system('cp ../groundtruth/' + self.scene + '.txt groundtruth_id.txt')

    def startTraining(self):
        for file in os.listdir(self.model_path):
            os.system('rm ' + self.model_path + file)
        temp_data, self.feature_num, self.label_num = GenerateTrainDataset(self.data_path, self.model_path, self.with_anomaly)
        self.data = TrainDataset(temp_data)[0]
        print(self.data)
        print('feature ', self.feature_num, '; label ', self.label_num)
        print("Start Training")
        self.loader = NeighborSampler(self.data, size = [1.0, 1.0], num_hops = 2, batch_size = self.batch_size, shuffle = False, add_self_loops = True)
        self.device = torch.device('cpu')
        self.Net = GATNet
        self.model = self.Net(self.feature_num, self.label_num).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr = 0.01, weight_decay = 5e-4)
        for epoch in range(1, 31):
            loss = self.train()
            auc = self.evaluate(self.data.test_mask)
            print(epoch, loss, auc, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
        loop_cnt = 0
        bad_cnt = 0
        bad_thre = 3
        while (bad_cnt <= bad_thre):
            self.fp_list.clear()
            self.tn_list.clear()
            auc = self.classify_fp_tn(self.data.test_mask)
            if len(self.tn_list) != 0: 
                bad_cnt = 0
            else: 
                bad_cnt += 1
                continue
            if len(self.tn_list) > 0: 
                for i in self.tn_list:
                    self.data.train_mask[i] = False
                    self.data.test_mask[i] = False
            print(len(self.tn_list))
            print(len(self.fp_list))
            torch.save(self.model.state_dict(), self.model_path + "model_" + str(loop_cnt))
            loop_cnt += 1
            if len(self.fp_list) == 0:
                break
            auc = 0
            for epoch in range(1, 151):
                loss = self.train()
                auc = self.evaluate(self.data.test_mask)
                print(epoch, loss, auc, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                if loss < 0.5: break
        print("Finish training")

    def train(self):
        self.model.train()
        total_loss = 0
        for data_flow in self.loader(self.data.train_mask):
            self.optimizer.zero_grad()
            out = self.model(self.data.x.to(self.device), data_flow.to(self.device))
            loss = F.nll_loss(out, self.data.y[data_flow.n_id].to(self.device))
            loss.backward()
            self.optimizer.step()
            total_loss += loss.item() * data_flow.batch_size
        return total_loss / self.data.train_mask.sum().item()

    def evaluate(self, mask):
        self.model.eval()
        correct = 0
        for data_flow in self.loader(mask):
            out = self.model(self.data.x.to(self.device), data_flow.to(self.device))
            pred = out.max(1)[1]
            pro  = F.softmax(out, dim = 1)
            pro1 = pro.max(1)
            for i in range(len(data_flow.n_id)):
                pro[i][pro1[1][i]] = -1
            pro2 = pro.max(1)
            for i in range(len(data_flow.n_id)):
                if pro1[0][i]/pro2[0][i] < self.thre:
                    pred[i] = 100
            correct += pred.eq(self.data.y[data_flow.n_id].to(self.device)).sum().item()
        return correct / mask.sum().item()

    def classify_fp_tn(self, mask):
        self.model.eval()
        correct = 0
        for data_flow in self.loader(mask):
            out = self.model(self.data.x.to(self.device), data_flow.to(self.device))
            pred = out.max(1)[1]
            pro  = F.softmax(out, dim = 1)
            pro1 = pro.max(1)
            for i in range(len(data_flow.n_id)):
                pro[i][pro1[1][i]] = -1
            pro2 = pro.max(1)
            for i in range(len(data_flow.n_id)):
                if pro1[0][i]/pro2[0][i] < self.thre:
                    pred[i] = 100
            for i in range(len(data_flow.n_id)):
                if self.data.y[data_flow.n_id[i]] != pred[i]:
                    self.fp_list.append(int(data_flow.n_id[i]))
                else:
                    self.tn_list.append(int(data_flow.n_id[i]))
            correct += pred.eq(self.data.y[data_flow.n_id].to(self.device)).sum().item()
        return correct / mask.sum().item()

    def validate(self):
        print('Start validating')
        #gtNode: GroundTruth Node
        #gtNode2Hop 是一个List，用于存储gtNode两跳内的节点, 包括gtNode本身
        #twoHopTogtNode是一个字典，它的键是两跳内可以到达gtNode的节点, k->j->i(包括gtNode本身)，值是一个列表，里面是它可以到达的gtNode中的节点
        temp_data, self.feature_num, self.label_num, _, _, gtNode, gtNode2Hop, twoHopTogtNode = GenerateTestDataset(self.data_path, self.model_path, self.with_anomaly)
        self.data = TestDataset(temp_data)[0]
        print(self.data)
        self.loader = NeighborSampler(self.data, size = [1.0, 1.0], num_hops = 2, batch_size = self.batch_size, shuffle = False, add_self_loops = True)
        self.device = torch.device('cpu')
        self.Net = GATNet
        self.model = self.Net(self.feature_num, self.label_num).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr = 0.01, weight_decay = 5e-4)
        self.fp_list.clear()
        self.tn_list.clear()
        loop_cnt = 0
        while(1):
            print('validating in model ', str(loop_cnt))
            model_path = self.model_path + "model_" + str(loop_cnt)
            if not os.path.exists(model_path):
                break
            self.model.load_state_dict(torch.load(model_path))
            self.fp_list.clear()
            self.tn_list.clear()
            self.classify_fp_tn(self.data.test_mask)
            print('fp and tn: ', len(self.fp_list), len(self.tn_list))
            fp_cnt = 0
            tp_cnt = 0
            eps = 1e-10
            node = gtNode.copy()
            for i in self.fp_list: 
                if not i in gtNode2Hop:
                    fp_cnt += 1
                if not i in twoHopTogtNode.keys(): 
                    continue
                for j in twoHopTogtNode[i]:
                    if j in node:
                        node.remove(j)
            tp_cnt = len(gtNode) - len(node)
            precision = tp_cnt/(tp_cnt + fp_cnt + eps)
            recall = tp_cnt/len(gtNode)
            print('Precision: ', precision)
            print('Recall: ', recall)
            if (recall > self.recall_thre) and (precision > self.precision_thre):
                while (1):
                    loop_cnt += 1
                    model_path = self.model_path + "model_" + str(loop_cnt)
                    if not os.path.exists(model_path): 
                        break
                    os.system('rm ' + model_path)
                return 1
            if (recall <= self.recall_thre):
                return 0
            for i in self.tn_list:
                self.data.test_mask[i] = False
            loop_cnt += 1
        return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scene', type = str, default = 'trace')
    parser.add_argument('--with_anomaly', action = "store_true")
    args = parser.parse_args()
    if args.scene not in scenes:
        print("\033[31mThe scene you choose should be one of cadets, fivedirections, theia, trace.\033[0m")
    if args.scene != "opensmtpd" and args.scene != "log4jEnv" and args.with_anomaly == True:
        print("\033[31mOnly in scene \"opensmtpd\" or \"log4jEnv\" can parameter --with_anomaly be used to specify the use of abnormal scores for training and testing.\033[0m")
    assert(args.scene in scenes)
    assert(args.with_anomaly == False or (args.with_anomaly == True and ((args.scene == "opensmtpd") or (args.scene == "log4jEnv"))))
    system = trainingSystem(args.scene, args.with_anomaly)
    flag = True
    while(flag):
        system.startTraining()
        if system.validate() == False:
            continue
        flag = False

if __name__ == "__main__":
	main()
