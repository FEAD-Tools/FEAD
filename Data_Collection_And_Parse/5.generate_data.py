import csv
import time
import json

proc_id_type = {}
proc_id_index = {}
base_path = "./audibeat-log-full_log4j"
with open(base_path + "/edges_with_encode_reduce_index.csv", "r") as r:
    reader = csv.reader(r)
    for line in reader:
        if line[2] not in proc_id_type and line[2] not in proc_id_index:
            proc_id_type[id] = line[3]
            proc_id_index[id] = line[4]
        else:
            if proc_id_type[id] != line[3]:
                print(id + " error!")
                exit()
            if proc_id_index[id] != line[4]:
                print(id + " error!")
                exit()
        if line[5] not in proc_id_type and line[5] not in proc_id_index:
            proc_id_type[id] = line[6]
            proc_id_index[id] = line[7]
        else:
            if proc_id_type[id] != line[6]:
                print(id + " error!")
                exit()
            if proc_id_index[id] != line[7]:
                print(id + " error!")
                exit()
print("check ok")
with open(base_path + "/edges_with_encode_reduce_index.csv", "r") as r:
    with open(base_path + "/test.txt", "w") as w: 
            reader = csv.reader(r)
            flag = 0
            for line in reader:
                if flag == 0:
                    flag = 1
                    continue
                id=int(line[0])
                lst = [line[2], line[3], line[5], line[6], line[9], line[8]]
                w.write('\t'.join(lst) + '\n')
print("generate test.txt")
with open(base_path + "/nodes_with_encode_reduce_index_deldup.csv", "r") as r:
    with open(base_path + "/ground_truth.txt", "w") as w: 
        reader = csv.reader(r)
        flag = 0
        for line in reader:
            if flag == 0:
                flag = 1
                continue
            if int(line[19]) == 1:
                w.write(line[2] + '\n')
print("generate ground_truth.txt")
