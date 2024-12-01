nodeIndextoId = {}
with open('index_to_id.txt', 'r') as f:
	for line in f:
		line = line.strip('\n').split(' ')
		nodeIndextoId[int(line[0])] = line[1]
gtIndex = {}
with open('groundtruth_index_type_id.txt', 'r') as f_gt:
	for line in f_gt:
		gtIndex[int(line.strip('\n').split(' ')[0])] = 1

ans = []
f_alarm = open('alarm.txt', 'r')
for line in f_alarm:
	if line == '\n': continue
	if not ':' in line:
		num = int(line.strip('\n'))
		for i in range(num):
			ans.append('tn')
		for i in gtIndex:
			ans[i] = 'fn'
		continue
	line = line.strip('\n')
	node = int(line.split(':')[0])
	neibor = line.split(':')[1].strip(' ').split(' ')
	flag = 0
	for i in neibor:
		if i == '': continue
		if int(i) in gtIndex.keys():
			ans[int(i)] = 'tp'
			flag = 1
	if node in gtIndex.keys():
		ans[node] = 'tp'
	else:
		if flag == 0:
			ans[node] = 'fp'

eps = 1e-10
tn = 0
tp = 0
fn = 0
fp = 0
for i in ans:
	if i == 'tp': tp += 1
	if i == 'tn': tn += 1
	if i == 'fp': fp += 1
	if i == 'fn': fn += 1
print("tp:", tp, ", fp:", fp, ", tn:", tn, ", fn:", fn)
acc=(tn+tp)/(tp+fp+tn+fn+eps)
precision = tp/(tp+fp+eps)
recall = tp/(tp+fn+eps)
fscore = 2*precision*recall/(precision+recall+eps)
print("Accuracy: ", acc)
print('Precision: ', precision)
print('Recall: ', recall)
print('F-Score: ', fscore)