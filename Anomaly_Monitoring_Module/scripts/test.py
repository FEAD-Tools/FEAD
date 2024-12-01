import os
import copy
import argparse
import numpy as np
import networkx as nx
import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv
from torch_geometric.data import NeighborSampler
from sklearn.cluster import SpectralClustering
from process_test import *

scenes = ["opensmtpd", "log4jEnv", "cadets", "fivedirections", "theia", "trace"]
thre_map = {"opensmtpd":1.5, "log4jEnv": 1.5, "cadets":1.5, "fivedirections":1.0, "theia":1.5, "trace":1.0}
batch_size_map = {"opensmtpd":50, "log4jEnv": 50, "cadets":5000, "fivedirections":5000, "theia":5000, "trace":5000}

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
		self.malicious_node_list = []
		self.total_rest = []
		self.provenance = None
		os.system('cp ../groundtruth/' + self.scene + '.txt groundtruth_id.txt')
		
	def startTesting(self):
		print('Start Testing')
		if self.with_anomaly:
			temp_data, self.feature_num, self.label_num, self.adjTargetToSource, self.adjSourceToTarget, _, _, _, self.malicious_node_list,self.provenance = GenerateTestDataset(self.data_path, self.model_path, self.with_anomaly)
		else:
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

		if self.with_anomaly:
			self.total_rest=list(set(self.total_rest))
			self.redect_fp()
			#print(self.total_rest)

	def classify_fp_tn(self, mask):
		self.model.eval()
		correct = 0
		total_loss = 0
		if self.with_anomaly:
			malicious_rest=[x for x in self.malicious_node_list]

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
			
			redetect=[]
			for i in range(len(data_flow.n_id)):
				if (self.data.y[data_flow.n_id[i]] != pred[i]):
					self.fp_list.append(int(data_flow.n_id[i]))
				else:
					if self.with_anomaly and int(data_flow.n_id[i]) in self.malicious_node_list:
						redetect.append(int(data_flow.n_id[i]))
						continue
					self.tn_list.append(int(data_flow.n_id[i]))
			correct += pred.eq(self.data.y[data_flow.n_id].to(self.device)).sum().item()

			if self.with_anomaly:
				for item in redetect:
					for i in self.fp_list:
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
						
						if i in malicious_rest:
							malicious_rest.remove(i)
						for ni in neibor:
							if ni in malicious_rest:
								malicious_rest.remove(ni)

						if item == i or item in neibor:
							if item in malicious_rest:
								# if item == 29:
								# 	print(29)
								malicious_rest.remove(item)
							break
		if self.with_anomaly:
			self.total_rest.extend(malicious_rest)
		return total_loss / mask.sum().item(), correct / mask.sum().item()
	
	def alarm(self):
		fw = open(self.alarm_path, 'w')
		fw.write(str(len(self.data.test_mask))+'\n')
		for i in range(len(self.data.test_mask)):
			if self.data.test_mask[i] == True:
				fw.write('\n')
				fw.write(str(i)+':')
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
				for j in neibor:
					fw.write(' '+str(j))
				
		fw.close()
	
	def redect_anomy(self,alarm_node_dict):
		ano_dict = {}
		for item in self.total_rest:
			ano_dict[item]=[]
			if item in self.adjTargetToSource.keys():
				ano_dict[item].extend(self.adjTargetToSource[item])
			if item in self.adjSourceToTarget.keys():
				ano_dict[item].extend(self.adjSourceToTarget[item])

		can_found = False
		alarm_node_list=[]
		for redetect_item in ano_dict.keys():
			for redetect_neighbor in ano_dict[redetect_item]:
				if can_found: break
				for alarm_node in alarm_node_dict.keys():
					if redetect_neighbor== alarm_node or redetect_neighbor in alarm_node_dict[alarm_node]:
						alarm_node_dict[alarm_node].append(redetect_item)
						alarm_node_list.append(alarm_node)
						can_found=True
						break
		
		return alarm_node_dict,alarm_node_list

	def redect_fp(self):
		# 创建图
		G = nx.Graph()  # 或者 nx.DiGraph() 来创建有向图
		for edge in self.provenance:
			source = edge[0]
			target = edge[2]
			G.add_edge(source, target)  # 假设边的权重都是1
		f_alarm = open(self.alarm_path, 'r')
		nodes = []
		alarm_node_dict={}
		num = 0
		for line in f_alarm:
			if line == '\n': continue
			if not ':' in line:
				num = int(line.strip('\n'))
				continue
			line = line.strip('\n')
			node = int(line.split(':')[0])
			nodes.append(node)
			neibor = line.split(':')[1].strip(' ').split(' ')
			alarm_node_dict[node]=neibor

		f_alarm.close()
		# 计算距离矩阵
		# 使用try-except处理无路径的情况
		try:
			distance_matrix = np.array([
				[
					nx.shortest_path_length(G, source=n1, target=n2) if n1 != n2 else 0
					for n2 in nodes
				]
				for n1 in nodes
			])
		except nx.NetworkXNoPath:
			# 如果没有路径，设置为无穷大
			distance_matrix = np.array([
				[
					nx.shortest_path_length(G, source=n1, target=n2) if n1 != n2 and nx.has_path(G, n1, n2) else 100
					for n2 in nodes
				]
				for n1 in nodes
			])
		# 使用谱聚类
		sc = SpectralClustering(n_clusters=2, affinity='precomputed', assign_labels='kmeans')
		labels = sc.fit_predict(1 / (1 + distance_matrix))  # 使用距离的倒数作为相似度
		# 检验是否能有效地分为两类
		if len(set(labels)) != 2:
			pass
			# print("提示：无法明显分为两类。")
		else:
				class_1 = []
				class_2 = []
				for i, label in enumerate(labels):
					if label == 0:
						class_1.append(nodes[i])
					else:
						class_2.append(nodes[i])
				similarity_1 = self.jaccard_similarity(class_1, self.malicious_node_list)
				similarity_2 = self.jaccard_similarity(class_2, self.malicious_node_list)
				# 判断哪个类别更接近
				fp_class=[]
				if similarity_1 > similarity_2:
					fp_class=class_2
				else:
					fp_class=class_1
				rest_fp_class=copy.deepcopy(fp_class)
				ano_dict={}
				for item in self.malicious_node_list:
						ano_dict[item]=[]
						if item in self.adjTargetToSource.keys():
							ano_dict[item].extend(self.adjTargetToSource[item])
						if item in self.adjSourceToTarget.keys():
							ano_dict[item].extend(self.adjSourceToTarget[item])
				for item in fp_class:
					is_malicious=False
					for m_item in self.malicious_node_list:
						if item== m_item:
							is_malicious=True
						
						if is_malicious==True:
							break

						for m_item_neighbor in ano_dict[m_item]:
							if m_item_neighbor in alarm_node_dict[item]:
								is_malicious=True
								break
					if is_malicious:
						rest_fp_class.remove(item)
				new_alarm_node_dict,alarm_node_list=self.redect_anomy(alarm_node_dict)
				for al_node in alarm_node_list:
					if al_node in rest_fp_class:
						rest_fp_class.remove(al_node)
				for r_m_node in rest_fp_class:
					for n_la_node in new_alarm_node_dict:
						if n_la_node in rest_fp_class:
							continue
						n_la_neighbor=new_alarm_node_dict[n_la_node]
						n_la_neighbor.append(n_la_node)
						r_m_nighbor=new_alarm_node_dict[r_m_node]
						r_m_nighbor.append(r_m_node)
						common_items = set(n_la_neighbor) & set(r_m_nighbor)
						if common_items:
							new_alarm_node_dict[n_la_node].extend(r_m_nighbor)
				fw = open(self.alarm_path, 'w')
				fw.write(str(num)+'\n')
				for node in new_alarm_node_dict.keys():
					if node in rest_fp_class:
						continue
					fw.write('\n')
					fw.write(str(node)+':')
					neibor = alarm_node_dict[node]
					for j in neibor:
						fw.write(' '+str(j))
				fw.close()

	# 计算 Jaccard 相似度
	def jaccard_similarity(self,set1, set2):
		intersection = len(set(set1).intersection(set2))
		union = len(set(set1).union(set2))
		return intersection / union

	def average_distance_from_ground_truth(self,cluster, G, ground_truth):
		total_distance = 0
		for node in cluster:
			distances = [nx.shortest_path_length(G, source=node, target=gt) for gt in ground_truth]
			total_distance += min(distances)
		return total_distance / len(cluster)

	def bfs_shortest_path(G, source, target):
		if source == target:
			return 0
		queue = [(source, 0)]
		visited = set([source])
		while queue:
			current_node, depth = queue.pop(0)
			for neighbor in G.neighbors(current_node):
				if neighbor not in visited:
					if neighbor == target:
						return depth + 1
					visited.add(neighbor)
					queue.append((neighbor, depth + 1))
		return 100  # 如果没有路径存在

	def compute_pairwise_shortest_path(self,G, pair):
		n1, n2 = pair
		if nx.has_path(G, n1, n2):
			res=nx.shortest_path_length(G, source=n1, target=n2)
			# print(str(n1)+"_"+str(n2)+"_"+str(res))
			return res
		else:
			return 100

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--scene', type = str, default = 'opensmtpd')
	parser.add_argument('--with_anomaly', action = "store_true")
	args = parser.parse_args()
	if args.scene not in scenes:
		print("\033[31mThe scene you choose should be one of opensmtpd, log4jEnv, cadets, fivedirections, theia, trace.\033[0m")
	if args.scene != "opensmtpd" and args.scene != "log4jEnv" and args.with_anomaly == True:
		print("\033[31mOnly in scene \"opensmtpd\" or \"log4jEnv\" can parameter --with_anomaly be used to specify the use of abnormal scores for training and testing.\033[0m")
	assert(args.scene in scenes)
	assert(args.with_anomaly == False or (args.with_anomaly == True and ((args.scene == "opensmtpd") or (args.scene == "log4jEnv"))))
	system = testingSystem(args.scene, args.with_anomaly)
	system.startTesting()

if __name__ == "__main__":
	main()