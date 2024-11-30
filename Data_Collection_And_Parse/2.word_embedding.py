from gensim import corpora
from pprint import pprint
import re
import csv
import json
import time

def get_malicious_edge_nodes(edge_file, node_file):
    #keywords=["192.168.17.133","212.64.63.215","/bin/wget","infect.py","woot.sh","apt-get update","apt-get install python3 -y","apt-get install wget -y","apt-get install nmap -y","apt-get install net-tools -y"]
    keywords = ["/tmp/ps","PATH","echo","/home/script/demo","find / -perm -u=s -type f","localhost:1389","localhost:8000","Exploit.class","127.0.0.1:9001"];
    malicious_nodes=[]
    malicious_edges=[]
    with open(node_file,"r") as nodes:
        reader = csv.reader(nodes)
        for line in reader:
            # print(line)
            # time.sleep(0.5)
            for i in range(len(line)):
                if i == 0 or i == 1 or i == 2: #这里额外需要跳过type了
                    continue
                for item in keywords:
                    if item in line[i]:
                        malicious_nodes.append(line[1])
                        break
    malicious_nodes = list(set(malicious_nodes))
    return malicious_edges, malicious_nodes

def gen_dict():
    max_len = -1
    text_tokens=[]
    with open("./audibeat-log-full/edges.csv","r") as edges:
        reader = csv.reader(edges)
        flag = 0
        for line in reader:
                if flag==0:
                    flag+=1
                    continue
                res=re.split('[-|_|/|:|.|+| ]', line[5])
                cnt_len=0
                for item in res:
                    if item !="":
                        cnt_len+=1
                        text_tokens.append(item)
                if cnt_len>max_len:
                    max_len=cnt_len
    with open("./audibeat-log-full/nodes.csv","r") as nodes:
        reader = csv.reader(nodes)
        tags = ["proc_exe","args","file_path","ip","port","env_name","env_all"]
        flag = 0
        index_list = []
        for line in reader:
                if flag == 0:
                    flag += 1
                    for item in tags:
                        index_list.append(line.index(item))
                    continue
                #print(index_list)[3,4,5,6,7]
                for index in index_list:
                    if len(line[index]) >= 2 and line[index][0]=="[" and line[index][-1]=="]":
                        line[index]=line[index][1:-1]
                    if index == 4:  #proc_cmdline
                        res=[]
                        split_str=line[index].split(" ")
                        res.append(split_str[0])
                        if len(split_str) > 1:
                            for item in split_str[1:]:
                                    res.append(item)
                    else:
                        res=re.split('[-|_|/|:|.|+| ]', line[index])
                    cnt_len = 0
                    for item in res:
                        if item !="":
                            cnt_len += 1
                            text_tokens.append(item)
                    if cnt_len > max_len:
                        max_len=cnt_len
                    if cnt_len > 100:
                        print(line)
    print(max_len)
    dict_LoS = corpora.Dictionary([text_tokens])
    with open("./audibeat-log-full/token2id_dict_reduce_test.json","w") as f:
        f.write(json.dumps(dict_LoS.token2id))
    return max_len

def encode_file(padding_len,mes_list,mns_list):
    token2id={}
    with open("./audibeat-log-full/token2id_dict_reduce_test.json","r") as f:
        token2id = json.load(f)
    cnt = 0
    with open("./audibeat-log-full/nodes.csv","r") as nodes:
        with open("./audibeat-log-full/nodes_with_encode_reduce.csv","w") as nodes_w:
            reader = csv.reader(nodes)
            writer = csv.writer(nodes_w)
            tags=["proc_exe","args","file_path","ip","port","env_name","env_all"]
            flag=0
            index_list=[]
            for line in reader:
                if flag==0:
                    flag+=1
                    for item in tags:
                        line.append(item+"_encoding")
                        index_list.append(line.index(item))
                    line.append("label")
                    writer.writerow(line)
                    continue
                for index in index_list:
                    if len(line[index])>=2 and line[index][0]=="[" and line[index][-1]=="]":
                        line[index]=line[index][1:-1]
                    if index==4:  #args
                        res=[]
                        split_str=line[index].split(" ")
                        res.append(split_str[0])
                        if len(split_str)>1:
                            for item in split_str[1:]:
                                res.append(item)
                    else:
                        res=re.split('[-|_|/|:|.|+| ]', line[index])
                    encode_list=[]
                    for item in res:
                        if item !="":
                            encode_list.append(token2id[item])
                    while len(encode_list) <padding_len:
                        encode_list.append(0)
                    line.append(json.dumps(encode_list))
                if line[1] in mns_list:
                    line.append(1)
                else:
                    line.append(0)
                writer.writerow(line)
    
    with open("./audibeat-log-full/edges.csv","r") as edges:
        with open("./audibeat-log-full/edges_with_encode_reduce.csv","w") as edges_w:
            reader = csv.reader(edges)
            writer = csv.writer(edges_w)
            flag=0
            for line in reader:
                if flag==0:
                    flag+=1
                    line.append("e_type_encoding")
                    line.append("label")
                    writer.writerow(line)
                    continue
                res=re.split('[-|_|/|:|.|+| ]', line[5])
                encode_list=[]
                for item in res:
                        if item !="":
                            encode_list.append(token2id[item])    
                while len(encode_list) <padding_len:
                    encode_list.append(0)
                line.append(json.dumps(encode_list))
                if [line[2],line[3]] in mes_list:
                    line.append(1)
                else:
                    line.append(0)
                writer.writerow(line)


mes_list, mns_list = get_malicious_edge_nodes("./audibeat-log-full/edges.csv","./audibeat-log-full/nodes.csv")       
max_len = gen_dict()
encode_file(max_len,mes_list,mns_list)