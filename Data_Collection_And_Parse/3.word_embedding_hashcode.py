import csv
import json

node_edge_index=0
node_edge_dict={}
node_type_dict={}
with open("./audibeat-log-full/nodes_with_encode_reduce.csv","r") as nodes_r:
    with open("./audibeat-log-full/nodes_with_encode_reduce_index.csv","w") as nodes_w:
        reader = csv.reader(nodes_r)
        writer = csv.writer(nodes_w)
        pre_tags=["id","obj_subj","obj_subj_type","proc_exe","args","file_path","ip","port","env_name","env_all","proc_exe_encoding","args_encoding","file_path_encoding","ip_encoding","port_encoding","env_name_encoding","env_all_encoding","label"]
        post_tags=["id","obj_subj","obj_subj_type", "obj_subj_index","proc_exe","args","file_path","ip","port","env_name","env_all","proc_exe_encoding","args_encoding","file_path_encoding","ip_encoding","port_encoding","env_name_encoding","env_all_encoding","label"]
        flag=0
        index_list=[]
        for line in reader:
                if flag==0:
                    flag+=1
                    writer.writerow(post_tags)
                    continue
                new_line= []
                for i in range(len(line)):
                    new_line.append(line[i])
                    if i == 2:
                        node_type_dict[line[1]] = line[2]
                        if line[1] in node_edge_dict:
                            new_line.append(node_edge_dict[line[1]])
                        else:
                             node_edge_dict[line[1]]=node_edge_index
                             new_line.append(node_edge_dict[line[1]])
                             node_edge_index+=1
                writer.writerow(new_line)


with open("./audibeat-log-full/edges_with_encode_reduce.csv","r") as edges_r:
        with open("./audibeat-log-full/edges_with_encode_reduce_index.csv","w") as edges_w:
            reader = csv.reader(edges_r)
            writer = csv.writer(edges_w)

            pre_tags=["id","e_id","sub","obj","timestamp","e_type","e_type_encoding","label"]
            post_tags=["id","e_id","sub","sub_type","sub_index","obj","obj_type","obj_index","timestamp","e_type","e_type_encoding","label"]
            flag=0
            for line in reader:
                if flag==0:
                    flag+=1
                    writer.writerow(post_tags)
                    continue
                new_line=[]
                for i in range(len(line)):
                    new_line.append(line[i])
                    if i==2 or i==3:
                         if line[i] not in node_edge_dict:
                            print("error!")
                            exit()
                         else:
                            new_line.append(node_type_dict[line[i]])
                            new_line.append(node_edge_dict[line[i]])
                writer.writerow(new_line)

with open("./audibeat-log-full/edge_node_2_id_test.json","w") as f:
        f.write(json.dumps(node_edge_dict))
