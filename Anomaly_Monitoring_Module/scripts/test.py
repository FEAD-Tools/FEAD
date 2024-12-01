import os
import copy
import argparse
import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv
from torch_geometric.data import NeighborSampler
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

class testingSystem:
	def __init__(self, scene, anomaly = False):
		self.scene = scene
		self.with_anomaly = anomaly
		self.thre = thre_map[self.scene]
		self.batch_size = batch_size_map[self.scene]
		self.data_path = "../data/" + self.scene + "/"
		self.model_path = "../models/"
		self.alarm_path = "alarm.txt"
		self.fp_list = []
		self.tn_list = []
		os.system('cp ../groundtruth/' + self.scene + '.txt groundtruth_id.txt')
		
	def startTesting(self):
		print('Start Testing')
		temp_data, self.feature_num, self.label_num, self.adjTargetToSource, self.adjSourceToTarget, _, _, _ = GenerateTestDataset(self.data_path, self.model_path, self.with_anomaly)
		self.data = TestDataset(temp_data)[0]
		print(self.data)
		self.loader = NeighborSampler(self.data, size = [1.0, 1.0], num_hops = 2, batch_size = self.batch_size, shuffle = False, add_self_loops = True)
		self.device = torch.device('cpu')
		self.Net = GATNet
		self.model = self.Net(self.feature_num, self.label_num).to(self.device)
		self.optimizer = torch.optim.Adam(self.model.parameters(), lr = 0.01, weight_decay = 5e-4)
		loop_num = 0
		test_acc = 0
		while(loop_num <= 100):
			model_path = self.model_path + 'model_' + str(loop_num)
			if not os.path.exists(model_path):
				loop_num += 1
				continue
			self.model.load_state_dict(torch.load(model_path))
			self.fp_list.clear()
			self.tn_list.clear()
			loss, test_acc = self.classify_fp_tn(self.data.test_mask)
			print(str(loop_num) + '  loss:{:.4f}'.format(loss) + '  acc:{:.4f}'.format(test_acc) + '  fp:' + str(len(self.fp_list)))
			for i in self.tn_list:
				self.data.test_mask[i] = False
			if test_acc == 1:
				break
			loop_num += 1
		self.alarm()

	def classify_fp_tn(self, mask):
		self.model.eval()
		correct = 0
		total_loss = 0
		for data_flow in self.loader(mask):
			out = self.model(self.data.x.to(self.device), data_flow.to(self.device))
			pred = out.max(1)[1]
			pro  = F.softmax(out, dim=1)
			pro1 = pro.max(1)
			for i in range(len(data_flow.n_id)):
				pro[i][pro1[1][i]] = -1
			pro2 = pro.max(1)
			for i in range(len(data_flow.n_id)):
				if pro1[0][i]/pro2[0][i] < self.thre:
					pred[i] = 100
			for i in range(len(data_flow.n_id)):
				if (self.data.y[data_flow.n_id[i]] != pred[i]):
					self.fp_list.append(int(data_flow.n_id[i]))
				else:
					self.tn_list.append(int(data_flow.n_id[i]))
			correct += pred.eq(self.data.y[data_flow.n_id].to(self.device)).sum().item()
		return total_loss / mask.sum().item(), correct / mask.sum().item()
	
	def post_classify(self,pre_ano_neighbor, benign_neighbor):
		total = pre_ano_neighbor + benign_neighbor
		if total == 0:
			return 1  # 如果总数为0，默认分类为异常
		ratio = benign_neighbor / total
		# 设置阈值
		benign_threshold = 2  # 大于这个值才开始考虑筛选
		ratio_threshold = 0.8  # 高于这个值说明周边都是良性同类，那么自己大概率也是良性的
		if total >= benign_threshold and ratio > ratio_threshold:
			return 0  # 正常
		else:
			return 1  # 异常

	def alarm(self):
		fw = open(self.alarm_path, 'w')
		fw.write(str(len(self.data.test_mask)) + '\n')
		predict_ano_label = []
		for i in range(len(self.data.test_mask)):
			if self.data.test_mask[i] == True:
				predict_ano_label.append(i)
		ano_dict = {}
		redetect_dict = {}
		gtIndex = {}
		with open('groundtruth_index_type_id.txt', 'r') as f_gt:
			for line in f_gt:
				gtIndex[int(line.strip('\n').split(' ')[0])] = 1
		f_fp = open('fp.txt', 'w')
		for i in range(len(self.data.test_mask)):
			if self.data.test_mask[i] == True:
				# fw.write('\n')
				# fw.write(str(i)+':')
				is_ano = False
				if i in gtIndex.keys():
					is_ano = True
					# print(str(i)+": "+"pre_ano,act_ano")
					f_fp.write(str(i) + ": " + "pre_ano,act_ano")
				else:
					# print(str(i)+": "+"pre_ano,act_ben")
					f_fp.write(str(i) + ": " + "pre_ano,act_ben")
				# print(str(i)+": "+"pre_ano,act_"+)
				neibor = set()
				if i in self.adjTargetToSource.keys():
					for j in self.adjTargetToSource[i]:
						neibor.add(j)
						if not j in self.adjTargetToSource.keys(): continue
						for k in self.adjTargetToSource[j]:
							neibor.add(k)
				if i in self.adjSourceToTarget.keys():
					for j in self.adjSourceToTarget[i]:
						neibor.add(j)
						if not j in self.adjSourceToTarget.keys(): continue
						for k in self.adjSourceToTarget[j]:
							neibor.add(k)
				predict_ano_label_count = 0
				for j in neibor:
					if j in predict_ano_label:
						predict_ano_label_count += 1
				benign_count = len(neibor) - predict_ano_label_count
				f_fp.write(
					"pre_ano_neighbor: " + str(predict_ano_label_count) + " benign_neighbor: " + str(benign_count))
				f_fp.write("\n")
				post_res = self.post_classify(predict_ano_label_count, benign_count)
				if post_res == 1:
					ano_dict[i] = []
					for j in neibor:
						ano_dict[i].append(j)
				else:
					redetect_dict[i] = []
					for j in neibor:
						redetect_dict[i].append(j)
		deep_copied_ano_dict = copy.deepcopy(ano_dict)
		for key, value in redetect_dict.items():
			for key1, value1 in deep_copied_ano_dict.items():
				if key in value1 or (set(value) & set(value1)):
					ano_dict[key1].append(key)
					ano_dict[key1].extend(value)
					break
		for key, value in ano_dict.items():
			fw.write('\n')
			fw.write(str(key) + ':')
			for j in value:
				fw.write(' ' + str(j))
		# for j in neibor:
		# 	fw.write(' '+str(j))
		fw.close()
		f_fp.close()

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
    system = testingSystem(args.scene, args.with_anomaly)
    system.startTesting()

if __name__ == "__main__":
	main()