import json
import hashlib
import datetime
from datetime import timedelta
import csv

is_benign=False
Edge_dict={}
Node_dict={}
File_Related={}
Proc_Related={}
Noise_Edge=[]
Noise_Node=[]
KGNodeTable={}
NoiseTable={}
PidTable={}
ProcNodeTable={}

NoiseProc=[]#噪声进程
NoiseFile=[]#噪声文件
ProcFdMap={}
ProcEnvMap={}
SocketNodeTable={}
FileNodeTable={}
EnvNodeTable={}

# // List procs and files that may trigger dependency explosion problem
noise_proc = ["firefox", "command-not-fou","code","LarkShell"]
noise_file = [".so.",".cfg","/tmp", "/proc", "/dev", "bash_completion.d","/run/motd.dynamic", ".bash_logout"]

for proc in noise_proc:
    NoiseProc.append(proc)

for file in noise_file:
    NoiseFile.append(file)

#接收一个字符串参数 item，然后使用 hashlib 库中的 MD5 算法对该字符串进行摘要计算。
#最后，函数返回计算得到的摘要的十六进制表示，作为字符串
def gen_md5_id(item):
    md5_machine = hashlib.md5()
    md5_machine.update(item.encode('utf-8'))
    return md5_machine.hexdigest()

#更新 Edge_dict 和 Node_dict 这两个全局字典。
def Insert_Dict(seq, sess, sub_id, obj_id, e_id, timestamp, syscall_str):
    #向 item_dict 添加键值对，分别是 "sub_id"、"obj_id"、"e_id"、"e_type"、"timestamp"、"sess" 和 "seq"，它们对应传递给函数的参数
    item_dict={}
    item_dict["sub_id"]=sub_id
    item_dict["obj_id"]=obj_id
    item_dict["e_id"]=e_id
    item_dict["e_type"]=syscall_str
    item_dict["timestamp"]=timestamp
    item_dict["sess"]=sess
    item_dict["seq"]=seq

    Edge_dict[e_id]=item_dict

    #检查 sub_id 是否在 Node_dict 中，如果存在则更新其属性sub_id node_type，否则创建一个新的节点字典并添加到 Node_dict。
    if sub_id in Node_dict:
        if not Node_dict[sub_id].get("sub_id"):
            Node_dict[sub_id]["sub_id"]=sub_id

        if not Node_dict[sub_id].get("node_type"):
            Node_dict[sub_id]["node_type"]=""
    else:
        node_item_dict={}
        node_item_dict["sub_id"]=sub_id
        node_item_dict["node_type"]=""
        Node_dict[sub_id]=node_item_dict
    #检查 obj_id 是否在 Node_dict 中，如果存在则更新其属性obj_id node_type，否则创建一个新的节点字典并添加到 Node_dict。
    if obj_id in Node_dict:
        if not Node_dict[obj_id].get("obj_id"):
            Node_dict[obj_id]["obj_id"]=obj_id

        if not Node_dict[obj_id].get("node_type"):
            Node_dict[obj_id]["node_type"]=""
    else:
        node_item_dict={}
        node_item_dict["obj_id"]=obj_id
        node_item_dict["node_type"]=""
        Node_dict[obj_id]=node_item_dict

#这个类的主要目的是表示进程节点，通过 pid、exe、args 组成的字符串作为唯一标识符，使用 MD5 散列算法进行生成
class NodeProc:
    def __init__(self,pid=" ",exe=" ",args=" ",ppid=" "):
        # // identifier: pid + exe + args
        self.pid=pid
        self.exe=exe
        self.args=args
        self.ppid=ppid
        self.id=gen_md5_id(pid + exe + args)

    def UpdateID(self,_exe,_args):
        self.exe = _exe
        self.args = _args
        str = self.pid + self.exe + self.args
        self.id = gen_md5_id(str)

event_analyzed = 0
# 创建表

#这个类的主要目的是表示套接字节点，使用套接字名称作为唯一标识符，同样使用 MD5 散列算法进行生成
class NodeSocket:
        def __init__(self,name=" ",id=" "):
        # // identifier: pid + exe + args
            self.name=name
            if id==" ":
                self.id=gen_md5_id(name)
            else:
                self.id=id

#这个类的主要目的是表示文件节点，使用文件名称和版本组成的字符串作为唯一标识符，同样使用 MD5 散列算法进行生成
class NodeFile:
    def __init__(self,name=" ",version=" ",id=" "):
        self.name = name
        if version=="":
            self.version = " "
        else:
            self.version=version

        if id==" " or id=="":
            str = name + version
            self.id=gen_md5_id(str)
        else:
            self.id=id
        # // hash(name + version) ==> id

#这个类的主要目的是表示进程对应的环境变量，使用进程pid和环境变量名字(包括是否为全部环境变量)作为唯一标识符，同样使用 MD5 散列算法进行生成
class NodeEnv:
    def __init__(self, name=" ", pid=" ", all=0, id=" "):
        self.name=name
        self.all=all
        if id == " " or id == "":
            str_tmp = name + pid + str(all)
            self.id = gen_md5_id(str_tmp)
        else:
            self.id = id
'''
将时间戳转换为字符串形式 timeNum。
检查时间戳字符串的长度, 如果是19位, 则将其除以1000000000以转换为秒; 否则, 将其直接转换为浮点数。
将时间戳转换为 UTC 时间, 并减去5个小时(timedelta(hours=5))以得到东部时间(Eastern Time)。
使用 strftime 方法将时间戳格式化为字符串，最终返回格式为 "%Y-%m-%d %H:%M:%S.%f" 的日期时间字符串。
'''
def parse_timestamp(ts):
    timeNum = str(ts)
    if len(timeNum)==19:
        timeStamp = float(timeNum)/1000000000# - timedelta(hours=5)
    else:
        timeStamp=float(timeNum)
    timeStamp_et=datetime.datetime.utcfromtimestamp(timeStamp)-timedelta(hours=5)
    ret_datetime = timeStamp_et.strftime("%Y-%m-%d %H:%M:%S.%f")
    return ret_datetime

#用于列出指定目录下所有包含 "ndjson" 的文件路径
def list_all_ndjson_files(rootdir):
    import os
    _files = []
    #列出文件夹下所有的目录与文件
    list_file = os.listdir(rootdir)
    for i in range(0,len(list_file)):
        # 构造路径
        path = os.path.join(rootdir,list_file[i])
        # 判断路径是否是一个文件目录或者文件
        # 如果是文件目录，继续递归
        if os.path.isdir(path):
             pass
             #files.extend(list_all_files(path))
        if os.path.isfile(path) and "ndjson" in path:
             _files.append(path)
    return _files

#用于列出指定目录下所有包含 "log.txt" 的文件路径
def list_all_log_files(rootdir):
    import os
    _files = []
    #列出文件夹下所有的目录与文件
    list_file = os.listdir(rootdir)
    for i in range(0,len(list_file)):
        # 构造路径
        path = os.path.join(rootdir,list_file[i])
        # 判断路径是否是一个文件目录或者文件
        # 如果是文件目录，继续递归
        if os.path.isdir(path):
             pass
             #files.extend(list_all_files(path))
        if os.path.isfile(path) and "log.txt" in path:
             _files.append(path)
    return _files

#用于列出指定目录下所有文件的路径，无论文件的类型或扩展名如何
def list_all_comm_files(rootdir):
    import os
    _files = []
    #列出文件夹下所有的目录与文件
    list_file = os.listdir(rootdir)
    for i in range(0,len(list_file)):
        # 构造路径
        path = os.path.join(rootdir,list_file[i])
        # 判断路径是否是一个文件目录或者文件
        # 如果是文件目录，继续递归
        if os.path.isdir(path):
             pass
             #files.extend(list_all_files(path))
        if os.path.isfile(path):
             _files.append(path)
    return _files

#向全局字典 ProcFdMap 中插入一个空列表
def InsertEmptyFd(_p_id):
    fd_vec = []
    ProcFdMap[_p_id] = fd_vec

#ID-Type, KGNodeTable
def InsertNode(_id, type) :
    KGNodeTable[_id] = type

def InsertNoisyNode(_id, type) :
    NoiseTable[_id] = type

def InsertPid(_id, p) :
    PidTable[_id] = p

def InsertSocket(s):
    s_id = s.id
    if s_id in SocketNodeTable:
        return SocketNodeTable[s_id]
    else:
        SocketNodeTable[s_id] = s
        InsertNode(s_id, "Socket")
        return s

'''
向全局字典 FileNodeTable 中插入一个键值对，其中键是文件对象 f 的 ID, 值是对应的文件对象 f。
如果 f 的 ID 已经存在于字典中，函数直接返回现有的文件对象；
否则，将 f 添加到字典中，并调用 InsertNode 函数将该文件节点标记为类型 "File"。
同时，检查文件名是否包含在噪声文件列表中，如果是，则调用 InsertNoisyNode 函数将该文件节点标记为噪声节点。
'''
def InsertFile(f):
    f_hash = f.id
    if f_hash in FileNodeTable:
        return FileNodeTable[f_hash]
    FileNodeTable[f_hash] = f
    InsertNode(f_hash, "File")
    #Noisy nodes are used as termination condition in Tracker
    name = f.name
    for file in NoiseFile:
        if name.find(file) != -1:
            InsertNoisyNode(f_hash,"File")
            break
    return f

'''
向全局字典 ProcNodeTable 中插入一个键值对，其中键是进程对象 p 的 ID, 值是对应的进程对象 p。
如果 p 的 ID 已经存在于字典中，函数直接返回现有的进程对象；
否则，将 p 添加到字典中，并调用 InsertNode 函数将该进程节点标记为类型 "Proc"。
同时，检查进程的执行文件是否包含在噪声进程列表中，如果是，则调用 InsertNoisyNode 函数将该进程节点标记为噪声节点
'''
def InsertProc(p):
    p_hash = p.id
    if p_hash=="110f005dec91c77a3ab29f38f34a7f9f":
        print(p_hash)
    if p_hash in ProcNodeTable:
        return ProcNodeTable[p_hash]

    ProcNodeTable[p_hash] = p
    InsertNode(p_hash, "Proc")
    # // Noisy nodes are used as termination condition in Tracker
    exe = p.exe
    for proc in NoiseProc:
        if exe.find(proc) !=-1:
            InsertNoisyNode(p_hash, proc)
            break

    return p

'''
向全局字典 ProcFdMap 中插入一个键值对，其中键是进程 ID _p_id, 值是一个文件描述符列表。
如果 _p_id 已经存在于字典中，将文件描述符 _fd 映射到相应的文件对象 _file, 并返回 True。
如果 _p_id 不存在于字典中，返回 False。
'''
def InsertFd(_p_id, _fd, _file):
    # auto it = ProcFdMap.find(_p_id);
    if _p_id in ProcFdMap:
        #proc was created in ProcFdMap
        fd_vec = ProcFdMap[_p_id]
        fd_vec_size = len(fd_vec)
        fd_idx = int(_fd)
        if (fd_idx < fd_vec_size):
            fd_vec[fd_idx] = _file
            return True
        for i in range(fd_idx - fd_vec_size):
            fd_vec.append(0)
        fd_vec.append(_file)
        return False
    else:
        return False

'''
向全局字典 EnvNodeTable 中插入一个键值对，其中键是文件对象 env 的 ID, 值是对应的文件对象 env。
如果 env 的 ID 已经存在于字典中，函数直接返回现有的文件对象；
否则，将 env 添加到字典中，并调用 InsertNode 函数将该文件节点标记为类型 "Env"。
同时，检查文件名是否包含在噪声文件列表中，如果是，则调用 InsertNoisyNode 函数将该环境变量节点标记为噪声节点。
'''
def InsertEnv(env):
    env_hash = env.id
    if env_hash in EnvNodeTable:
        return EnvNodeTable[env_hash]
    EnvNodeTable[env_hash] = env
    InsertNode(env_hash, "Env")
    #Noisy nodes are used as termination condition in Tracker
    name = env.name
    for file in NoiseFile:
        if name.find(file) != -1:
            InsertNoisyNode(env_hash,"Env")
            break
    return env

'''
用于交换字典 map 中的两个键 id_old 和 id_new。
如果 id_old 存在于字典中，将其对应的值弹出（pop），然后将键改为 id_new，并将原来的值重新插入字典
'''
def ExchangeMapKey (map, id_old, id_new):
    if id_old in map:
        nh = map.pop(id_old)
        # nh.key = id_new
        map[id_new] = nh

'''
用于复制进程 _p_id 的文件描述符。
首先，通过调用 SearchFd(_p_id) 获取进程对应的文件描述符列表 fd_vec。
然后，将十六进制表示的 _f_old_str 和十进制表示的 _f_new_str 转换为整数 _f_old 和 _f_new。
接下来，根据 _f_old 获取对应的文件 _file，然后将 _file 复制到 _f_new 的位置，并根据需要扩展文件描述符列表。
如果 _p_id 对应的文件描述符列表不存在，或者 _f_old 超出了文件描述符列表的范围，函数返回 False。否则，返回 True
'''
def CopyFd(_p_id, _f_old_str, _f_new_str):
    fd_vec = SearchFd(_p_id)
    if (fd_vec == None):
        return False
    _f_old = int(_f_old_str,16)
    _f_new = int(_f_new_str, 10)
    # // Todo: Auditbeat don't record syscalls for sshd
    # hash_t _file
    fd_vec_size = len(fd_vec)#->size();
    if (_f_old < fd_vec_size):
        _file = fd_vec[_f_old]
    else:
        _file = 0

    if (_f_new < fd_vec_size):
        fd_vec[_f_new] = _file
    # // Todo: fd_vector should include _f_new
    for i in range(_f_new - fd_vec_size):
        fd_vec.append(0)
    fd_vec.append(_file)
    return True

'''
用于克隆父进程 _pp_id 的文件描述符列表到子进程 _p_id。
首先，通过调用 SearchFd(_pp_id) 获取父进程对应的文件描述符列表 pp_fd_vec。
然后，将 pp_fd_vec 复制到新的列表 p_fd_vec 中，并将其存储在全局字典 ProcFdMap 中，以与子进程 _p_id 关联
'''
def CopyFd_clone(_pp_id, _p_id):
    # p_fd_vec =[]
    # ProcFdMap[_p_id] = p_fd_vec
    pp_fd_vec = SearchFd(_pp_id)
    if (pp_fd_vec == None):
        return False
    p_fd_vec = [i for i in pp_fd_vec]
    # p_fd_vec = pp_fd_vec.clone()
    ProcFdMap[_p_id] = p_fd_vec
    return True

def SearchProc( _pid ) :
    if _pid in PidTable:
        return PidTable[_pid]
    else:
        return None

def SearchSocket(_id):
    if (_id in SocketNodeTable):
        return SocketNodeTable[_id]
    else:
        return None

def SearchSocket_d(_device):
    for (key,value) in SocketNodeTable.items():
        name=value.name
        start = name.find("[") + 1
        end = name.find("]")
        device = name[start:end]
        if (device == _device):
            return value
    return None

def SearchFd(_p_id):
    # auto it = ProcFdMap.find(_p_id);
    if _p_id in ProcFdMap:
        return ProcFdMap[_p_id]
    else:
        # std::cerr << "Cannot find proc " << _p_id << " when searching ProcFdMap" << std::endl;
        return None

def SearchFile(_id):
    # auto it = FileNodeTable.find(_id);
    if _id in FileNodeTable:
        return FileNodeTable[_id]
    else:
        # // std::cerr << "Cannot find this File when doing SearchFile" << _id << std::endl;
        return None

#从procinfo加载Proc信息
def LoadProc(procPath):
    generalPath = procPath + "/general.txt"
    pidPath = procPath + "/pid.txt"
    exePath = procPath + "/exe.txt"
    argsPath = procPath + "/args.txt"
    ppidPath = procPath + "/ppid.txt"

    generalPathFlag=True
    pidPathFlag=True
    exePathFlag=True
    argsPathFlag=True
    ppidPathFlag=True

    generalPathLine=""
    pidPathLine=""
    exePathLine=""
    argsPathLine=""
    ppidPathLine=""

    with open(generalPath,"r") as g_f:
        with open(pidPath,"r") as p_f:
            with open(exePath,"r") as e_f:
                with open(argsPath,"r") as a_f:
                    with open(ppidPath,"r") as pp_f:

                            pid=p_f.readline()
                            exe=e_f.readline()
                            args=a_f.readline()
                            ppid=pp_f.readline()

                            while pid and exe and args and ppid:
                                pid=p_f.readline().replace("\n","").strip()
                                exe=e_f.readline().replace("\n","").strip()
                                args=a_f.readline().replace("\n","").strip()
                                ppid=pp_f.readline().replace("\n","").strip()
                                p_temp = NodeProc(pid, exe, args, ppid)
                                p = InsertProc(p_temp)
                                InsertPid(pid, p)
    return True

#从fdinfo加载Fd信息
def LoadFd(fd_path):
    files = list_all_comm_files(fd_path)
    for fd_file_path in files:
        pid=fd_file_path.split("/")[-1].strip()
        p = SearchProc(pid)
        # // Cannot find process pid in ProcNodeMap
        if not p:
            continue

        with open(fd_file_path,"r") as f_r:
            fd_vec=[]
            f_r.readline()
            f_r.readline()
            f_r.readline()

            fd_line=f_r.readline()
            fd_line=str(fd_line).replace('\n',"").replace("\\n","").rstrip("\n").rstrip("\r\n")
            while (fd_line) :
                # // example: 0 -> /dev/null
                loc = fd_line.rfind("-> ")
                loc_ = fd_line.rfind(" ",0, loc-2)

                f_name = fd_line[loc + 3:]
                fd = int(fd_line[loc_ + 1: loc_ + 1+ loc - loc_ - 1])
                fd_vec_size = len(fd_vec)
                if (fd >= fd_vec_size):
                    for  i in range(fd - fd_vec_size+1) :
                        fd_vec.append(0)

                if (f_name.find("socket") != -1):
                    s_tmp = NodeSocket (f_name.replace('\n',"").replace("\\n","").rstrip("\n").rstrip("\r\n"));
                    s = InsertSocket(s_tmp)
                    fd_id = s.id
                else:
                    # // Todo: add i_version for file
                    f_tmp = NodeFile (f_name.replace('\n',"").replace("\\n","").rstrip("\n").rstrip("\r\n"));
                    f = InsertFile(f_tmp)
                    fd_id = f.id

                fd_vec[fd] = fd_id
                fd_line=f_r.readline()
        p_id = p.id
        # // delete previous process fd map
        if p_id in ProcFdMap:
            dict.pop(p_id)
        ProcFdMap[p_id] = fd_vec
    return True

#从socketinfo加载Socket信息
def LoadSocket(socket_path):
    generalPath = socket_path + "/general.txt"
    devicePath = socket_path + "/device.txt"
    namePath = socket_path + "/name.txt"

    with open(generalPath,"r") as g_f:
        with open(devicePath,"r") as d_f:
            with open(namePath,"r") as n_f:
                g_f.readline()
                d_f.readline()
                n_f.readline()

                socket_line=g_f.readline()
                while socket_line:
                    device=d_f.readline().replace("\n","")
                    name=n_f.readline().replace("\n","")
                    s = SearchSocket_d(device)

                    if s==None:
                        socket_line=g_f.readline()
                        continue
                    # print("尚未测试，重新试一下")
                    s_id_old = s.id
                    # // Parse IP address and port for sockets
                    # std::string new_name;
                    # // find -> in socket name
                    found_1 = name.find("->")
                    # // find * in socket name
                    found_2 = name.find("*", found_1 + 1)
                    # // Todo: we consider [::] as localhost
                    found_3 = name.find("]")
                    if (found_2 != -1) :
                        # // find pos of : for port
                        pos = name.find(":", found_1 + 1)
                        new_name = "127.0.0.1" + name[pos:]
                    else:
                        if (found_3 != -1):
                            # // find pos of : for port
                            pos = name.find(":", found_3 + 1)
                            new_name = "127.0.0.1" + name[pos:]

                        elif (found_1 != -1):
                            new_name = name[found_1 + 2:]

                        else:
                            new_name = name
                    # // Update SocketNodeTable and KGNodeTable maps
                    # // (1) delete old socket named socket[xxxx]
                    KGNodeTable.pop(s_id_old)
                    nh_socket = SocketNodeTable[s_id_old]
                    SocketNodeTable.pop(s_id_old)
                    # s = nh_socket
                    # delete(s);
                    # // (2) create a socket with new name
                    s_tmp = NodeSocket (new_name)
                    s = InsertSocket(s_tmp)
                    s_id_new = s.id
                    for (key,value) in ProcFdMap.items():
                        fd_vec = value
                        if s_id_old in fd_vec:
                            index = fd_vec.index(s_id_old)
                            fd_vec[index] = s_id_new
                    socket_line=g_f.readline()
    return True

def ParseAuditdEvent(event,sess):
        # event_analyzed=0
    global event_analyzed
    syscall_str =event["auditd"]["data"]["syscall"]

    if syscall_str=="execve":
        pid = str(event["process"]["pid"])
        ppid = str(event["process"]["parent"]["pid"])
        exe = str(event["process"]["executable"])
        # std::string args;
        if (event["process"].get("args")):
            args = str(event["process"]["args"]);
            args=args.replace('"',"")
            args=args.replace('\'',"")
            args=args.replace('\\',"")
            args=args.replace(',',"")
        else:
            args = "null"
        seq = int(event["auditd"]["sequence"])

        # // pp_id and p_id are used to create KG edge
        pp_id = None
        p_id = None

        p = SearchProc(pid)

        if (p == None):

            # // the process does not exist:
            # // add new proc into infotable: ProcNodeTable, PidTable, and ProcFdMap
            pp = SearchProc(ppid)
            if (not pp):
                # db_print("Sequence: " << uint128tostring(seq) << " execve cannot find parent proc " << ppid);
                return

            p_temp = NodeProc(pid, exe, args, ppid)
            p_new = InsertProc(p_temp)
            InsertPid(pid, p_new)
            p_id = p_new.id
            pp_id = pp.id
            CopyFd_clone(pp_id, p_id)
        elif p.args == " ":

            # // the process has been created (e.g., cloned) but never executed
            p_id_old = p.id

            p.UpdateID(exe, args)

            # // update ProcNodeTable, KGNodeTable, ProcFdMap, and PidTable
            p_new_id = p.id

            # if p_id_old=="110f005dec91c77a3ab29f38f34a7f9f":
            # 	print("110f005dec91c77a3ab29f38f34a7f9f")
            ExchangeMapKey(KGNodeTable, p_id_old, p_new_id);
            ExchangeMapKey(ProcNodeTable, p_id_old, p_new_id);
            ExchangeMapKey(ProcFdMap, p_id_old, p_new_id);
            ExchangeMapKey(Proc_Related, p_id_old, p_new_id);

            for item in ProcFdMap.keys():
                for item_j in ProcFdMap[item]:
                    if item_j==p_id_old:
                        item_j_index=ProcFdMap[item].index(item_j)
                        ProcFdMap[item][item_j_index]=p_new_id

            for item in Proc_Related.keys():
                for item_j in Proc_Related[item]:
                    if item_j==p_id_old:
                        item_j_index=Proc_Related[item].index(item_j)
                        Proc_Related[item][item_j_index]=p_new_id

            for item in Edge_dict.keys():
                items=Edge_dict[item]
                if items["sub_id"]==p_id_old:
                    Edge_dict[item]["sub_id"]=p_new_id
                if items["obj_id"]==p_id_old:
                    Edge_dict[item]["obj_id"]=p_new_id


            # return
            pp = SearchProc(ppid)
            if (not pp):
                # db_print("Sequence: " << uint128tostring(seq) << " execve cannot find parent proc " << ppid);
                return
            p_id = p.id
            pp_id = pp.id
        else:
            # // the process has been executed
            p_temp = NodeProc(pid, exe, args, ppid)
            p_new = InsertProc(p_temp)
            p_id = p_new.id
            pp_id = p.id

            # // update PidTable and insert ProcFdMap
            PidTable[pid]=p_new
            # it = PidTable.find(pid)
            # it->second = p_new;
            CopyFd_clone(pp_id, p_id)

        # // add new file into NodeFileTable
        fileID=[]

        # std::string name;
        # std::string version;
        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            name = str(file["name"])
            version=""
            if file.get("version"):
                version = str(file["version"])

            if (name[0] == '.'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])

                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + "/" + name

            f_tmp = NodeFile (name, version)
            f = InsertFile(f_tmp)
            f_id = f.id
            fileID.append(f_id)

        # // Todo: add new attr into NodeAttrTable

        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])

        for f_id_ptr in fileID:
            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id))
            # Insert_Dict(seq, sess,p_id ,f_id_ptr , e_id, timestamp,"Load")
            Insert_Dict(seq, sess,f_id_ptr,p_id , e_id, timestamp,"Load")
            event_analyzed+=1

            if f_id_ptr in File_Related:
                File_Related[f_id_ptr].append(e_id)
            else:
                File_Related[f_id_ptr]=[e_id]

            if p_id in Proc_Related:
                    Proc_Related[p_id].append(e_id)
            else:
                    Proc_Related[p_id]=[e_id]
            # KGEdge *e = new KGEdge (f_id_ptr, p_id, EdgeType_t::Load, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id, e);

        e_id= gen_md5_id(str(seq)+str(sess)+str(p_id)+str(pp_id))
        Insert_Dict(seq, sess,pp_id,p_id , e_id, timestamp,"Execve")
        # event_analyzed+=1
        # KGEdge *e = new KGEdge (pp_id, p_id, EdgeType_t::Execve, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # SyscallType_t::Execve
    elif syscall_str=="clone" or syscall_str=="fork":
            pid = str(event["auditd"]["data"]["exit"])
            ppid = str(event["process"]["pid"])
            # pid = str(event["process"]["pid"])
            # ppid = str(event["process"]["parent"]["pid"])
            seq = int(event["auditd"]["sequence"])
            sess = int(event["auditd"]["session"])
            timestamp = str(event["@timestamp"])
            # if timestamp=="2023-04-26T07:47:54.043Z":
            # 	print("hhh")

            p_temp = NodeProc(pid=pid)
            p_temp.ppid = ppid

            # if pid=="110f005dec91c77a3ab29f38f34a7f9f" or ppid=="110f005dec91c77a3ab29f38f34a7f9f":
            # 	print(pid)
            # // add new proc into infotable: ProcNodeTable, PidTable, and ProcFdMap
            p = InsertProc(p_temp)
            InsertPid(pid, p)

            p_id = p.id
            pp = SearchProc(ppid)
            if (pp):
                pp_id = pp.id
                # // create fd list to ProfFdMap
                CopyFd_clone(pp_id, p_id)
                # // add new edge into KGEdge
                e_id= gen_md5_id(str(seq)+str(sess)+str(p_id)+str(pp_id))
                # if e_id=="832cfb146a12db9a01ba06bb2f2df2a3":
                # 	print(e_id)
                Insert_Dict(seq, sess, pp_id,p_id , e_id, timestamp,syscall_str)
                event_analyzed+=1
                # KGEdge *e = new KGEdge (pp_id, p_id, EdgeType_t::Clone, seq, sess, timestamp);
                # infotbl->InsertEdge(e);
            else:
                InsertEmptyFd(p_id)
                # db_print("Sequence: " << uint128tostring(seq) << " clone cannot find parent proc " << ppid);
    # SyscallType_t::Clone;
    elif syscall_str=="vfork":
        pid = str(event["auditd"]["data"]["exit"])
        ppid = str(event["process"]["pid"])
        # pid = str(event["process"]["pid"])
        # ppid = str(event["process"]["parent"]["pid"])
        seq = int(event["auditd"]["sequence"])
        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])

        # // search for parent process
        pp = SearchProc(ppid)
        if (not pp):
            # db_print("Sequence: " << uint128tostring(seq) << " vfork cannot find parent proc " << ppid);
            return

        pp_id = pp.id

        p = SearchProc(pid)
        # hash_t *p_id;
        if (p != None):
            # // vforked process exists before vfork syscall -> no need to create new process
            p_id = p.id
        else:
            # // add new proc into infotable: ProcNodeTable, PidTable, and ProcFdMap
            p_temp = NodeProc(pid=pid)
            p_temp.ppid = ppid
            p = InsertProc(p_temp)
            p_id = p.id
            # // pidtable in Insertpid is deisgned for internal proc lookup
            InsertPid(pid, p)
            # // create fd list to ProcFdMap
            CopyFd_clone(pp_id, p_id)

        # // add new edge into KGEdge
        e_id= gen_md5_id(str(seq)+str(sess)+str(p_id)+str(pp_id))

        Insert_Dict(seq, sess,pp_id ,p_id , e_id, timestamp,syscall_str)
        event_analyzed+=1
        # KGEdge *e = new KGEdge (pp_id, p_id, EdgeType_t::Vfork, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
    # SyscallType_t::Vfork;
    # elif syscall_str=="fork":
    # 	pass
    # SyscallType_t::Clone;
    elif syscall_str=="open" or syscall_str=="openat" or syscall_str=="mq_open":
        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd = str(event["auditd"]["data"]["exit"]);

        # // create new file into FileNodeTable
        # std::string name;
        # std::string version;

        create_flag = 0
        # std::string nametype;
        name=""
        version=""

        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            nametype = str(file["nametype"])
            if (nametype=="PARENT"):
                continue
            if (not file.get("name")):
                continue
            name = str(file["name"])
            if (name[0] == '.'):
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"])
                dir=""
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                elif event["process"].get("working_directory"):
                    dir=str(event["process"]["working_directory"])

                if dir!="":
                    name = dir + "/" + name

            version=""
            if file.get("version"):
                version = str(file["version"])
            if (nametype=="CREATE"):
                create_flag = 1

        if name=="" and version=="":
            return

        f_tmp = NodeFile (name, version)
        f = InsertFile(f_tmp)
        fd_id = f.id
        InsertFd(p_id, fd, fd_id)

        # // add create edge into KGEdge
        if (create_flag):
            seq = int(event["auditd"]["sequence"])
            sess = int(event["auditd"]["session"])
            timestamp = str(event["@timestamp"])

            p_id_ptr = p.id
            f_id_ptr = f.id

            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
            Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,syscall_str+"_create")
            event_analyzed+=1

            if f_id_ptr in File_Related:
                File_Related[f_id_ptr].append(e_id)
            else:
                File_Related[f_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]
            # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Create, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);

        # SyscallType_t::Open;
    elif syscall_str=="pipe" or syscall_str=="pipe2":
        pid = str(event["process"]["pid"])
        seq = int(event["auditd"]["sequence"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        # // pipe does not specify fd
        if ( not event["auditd"]["data"].get("fd0") or not event["auditd"]["data"]["fd0"]):
            return

        p_id = p.id
        fd_1 = str(event["auditd"]["data"]["fd0"])
        fd_2 = str(event["auditd"]["data"]["fd1"])

        # // create new pipe into FileNodeTable
        name = "pipe" + str(seq)
        f_tmp = NodeFile (name)
        f = InsertFile(f_tmp)
        f_id = f.id

        InsertFd(p_id, fd_1, f_id)
        InsertFd(p_id, fd_2, f_id)
        # SyscallType_t::Pipe;
    elif syscall_str=="dup" or syscall_str=="dup2":
        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd_old = str(event["auditd"]["data"]["a0"])
        fd_new = str(event["auditd"]["data"]["exit"])

        # // copy new fd into PidTable
        CopyFd(p_id, fd_old, fd_new)
    elif syscall_str=="close":
        pass
    # SyscallType_t::Close;
    elif syscall_str=="connect":
        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id

        # // obtain old file id
        fd_str = str(event["auditd"]["data"]["a0"]);
        fd_idx = int(fd_str, 16);

        fd_vec = SearchFd(p_id);
        # // hash_t f_id = (*fd_vec)[fd_idx];

        # // to update the socket name
        if event.get("destination") and event["destination"].get("ip"):
            ip = str(event["destination"]["ip"]);
            port = str(event["destination"]["port"])
            new_name = ip + ":" + port
        else:
            return

        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"];
        if (event["auditd"]["data"].get("socket") and (event["auditd"]["data"]["socket"].get("saddr") or event["auditd"]["data"]["socket"].get("path"))):
            fd_vec[fd_idx] = -1
            return

        s_tmp = NodeSocket (new_name)
        s = InsertSocket(s_tmp)

        fd_vec[fd_idx] = s.id

        # // Todo: We assume that there is no edge (e.g., sendto, recvefrom) including old socket before connect
        # // infotbl->SocketNodeTable.extract(f_id);
        # // infotbl->KGNodeTable.extract(f_id);

        # // add new edges into KGEdge (debug)
        sess = int(event["auditd"]["session"])
        seq = int(event["auditd"]["sequence"])
        timestamp = str(event["@timestamp"])

        p_id_ptr = p.id
        s_id_ptr = s.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,s_id_ptr , e_id, timestamp,syscall_str)
        event_analyzed+=1

        if s_id_ptr in File_Related:
                File_Related[s_id_ptr].append(e_id)
        else:
                File_Related[s_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
        else:
                Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (p_id_ptr, s_id_ptr, EdgeType_t::Connect, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*s_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Connect;
    elif syscall_str=="unlink" or syscall_str=="unlinkat":
            pid = str(event["process"]["pid"])
            p = SearchProc(pid)

            # // magic proc is never created
            if (p == None):
                return

            # std::string name;
            # std::string version;
            # std::string nametype;
            if not event["auditd"].get("paths"):
                return

            name=""
            version=""
            for file in event["auditd"]["paths"]:
                nametype = str(file["nametype"]);

                if (nametype=="PARENT"):
                    continue

                name = str(file["name"])
                if (name[0] == '.'):
                    # dir = str(event["process"]["cwd"])
                    if event["process"].get("cwd"):
                        dir = str(event["process"]["cwd"])
                    else:
                        dir=str(event["process"]["working_directory"])
                    name = dir + name[1:]
                elif (name[0] != '/'):
                    # dir = str(event["process"]["cwd"])
                    if event["process"].get("cwd"):
                        dir = str(event["process"]["cwd"])
                    else:
                        dir=str(event["process"]["working_directory"])
                    name = dir + "/" + name

                version=""
                if file.get("version"):
                    version = str(file["version"])


            if name=="" and version=="":
                return

            f_tmp = NodeFile(name, version)
            f = InsertFile(f_tmp)

            # // add new edges into KGEdge
            sess = str(event["auditd"]["session"])
            seq = int(event["auditd"]["sequence"])
            timestamp = str(event["@timestamp"])

            p_id_ptr = p.id
            f_id_ptr = f.id

            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
            Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,syscall_str+"_delete")
            event_analyzed+=1

            if f_id_ptr in File_Related:
                File_Related[f_id_ptr].append(e_id)
            else:
                File_Related[f_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]
            # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Delete, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Delete;
    elif syscall_str=="socket":
        pid = str(event["process"]["pid"])
        p = SearchProc(pid);

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd =str(event["auditd"]["data"]["exit"])

        # // create new socket into SocketNodeTable
        seq = int(event["auditd"]["sequence"])
        name = "socket" + str(seq)

        s_tmp =NodeSocket (name)
        s = InsertSocket(s_tmp)
        fd_id = s.id
        InsertFd(p_id, fd, fd_id)
    # SyscallType_t::Socket;
    elif syscall_str=="read":
        # Don't track read system with 0 bytes return
        read_bytes = str(event["auditd"]["data"]["exit"])
        if (read_bytes == "0"):
            return
        # event sequence
        seq = int(event["auditd"]["sequence"])
        pid = str(event["process"]["pid"])
        p = SearchProc(pid)
        # // magic proc is never created
        if (p == None):
            return
        p_id = p.id
        fd_vec = SearchFd(p_id)
        fd_str = str(event["auditd"]["data"]["a0"])
        fd_idx = int(fd_str,16)
        fd_vec_size = len(fd_vec)
        # // Todo: we don't record syscalls for sshd as events with auid=-1 is
        # // filtered. As a result, we might miss pipe syscalls for IPC between sshd and new
        # // ssh session
        if (fd_idx >= fd_vec_size):
            # db_print("Sequence: " << uint128tostring(seq) << " unexpected fd: " << fd_idx << " in read syscall");
            return

        f_id = fd_vec[fd_idx]
        # // Todo: we don't record syscalls for sshd as events with auid=-1 is
        # // filtered. As a result, we might miss pipe syscalls for IPC between sshd and new
        # // ssh session
        if (f_id == 0 and fd_idx != 0) :
            # db_print("Sequence: " << uint128tostring(seq) << " read closed fd: " << fd_idx << " in read syscall");
            return;


        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"]);

        p_id_ptr = p.id
        f = SearchFile(f_id)

        if (f == None):
            s = SearchSocket(f_id)
            if (s == None):
                return

            s_id_ptr = s.id
            e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
            # Insert_Dict(seq, sess,p_id_ptr ,s_id_ptr , e_id, timestamp,"recv")
            Insert_Dict(seq, sess,s_id_ptr , p_id_ptr ,e_id, timestamp,"recv")
            event_analyzed+=1

            if s_id_ptr in File_Related:
                File_Related[s_id_ptr].append(e_id)
            else:
                File_Related[s_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]
            # e = new KGEdge (s_id_ptr, p_id_ptr, EdgeType_t::Recv, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*s_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id_ptr, e);

        else:
            f_id_ptr = f.id

            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
            #exchange the source and target of Read
            #Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"read")
            Insert_Dict(seq, sess, f_id_ptr ,p_id_ptr , e_id, timestamp,"read")
            event_analyzed+=1

            if f_id_ptr in File_Related:
                File_Related[f_id_ptr].append(e_id)
            else:
                File_Related[f_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]
            # KGEdge *e = new KGEdge (f_id_ptr, p_id_ptr, EdgeType_t::Read, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Read;
    elif syscall_str=="write":
        # // Don't track write system with 0 bytes return
        write_bytes = event["auditd"]["data"]["exit"]
        if (str(write_bytes) == "0"):
            return

        # // event sequence
        seq = int(event["auditd"]["sequence"])

        pid = str(event["process"]["pid"]);
        p = SearchProc(pid);

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd_vec = SearchFd(p_id)

        fd_str = str(event["auditd"]["data"]["a0"]);
        fd_idx = int(fd_str, 16)
        fd_vec_size = len(fd_vec)
        # // Todo: Auditbeat don't record syscalls for sshd
        if (fd_idx >= fd_vec_size):
            # db_print("Sequence: " << uint128tostring(seq) << " unexpected fd: " << fd_idx << " in write syscall");
            return

        f_id = fd_vec[fd_idx];
        # // Todo: Auditbeat don't record syscalls for sshd
        if (f_id == 0 and fd_idx != 1 and fd_idx != 2) :
            # db_print("Sequence: " << uint128tostring(seq) << " write closed fd: " << fd_idx << " in write syscall");
            return;


        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])

        p_id_ptr = p.id
        f = SearchFile(f_id);
        if (f == None):
            s = SearchSocket(f_id);
            if (s == None):
                return
            s_id_ptr = s.id

            e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
            Insert_Dict(seq, sess,p_id_ptr ,s_id_ptr , e_id, timestamp,"send")
            event_analyzed+=1

            if s_id_ptr in File_Related:
                File_Related[s_id_ptr].append(e_id)
            else:
                File_Related[s_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]

            # e = new KGEdge (p_id_ptr, s_id_ptr, EdgeType_t::Send, seq, sess, timestamp);
        # 	infotbl->InsertEdge(e);
        # 	infotbl->InsertFileInteraction(*s_id_ptr, e);
        # 	infotbl->InsertProcInteraction(*p_id_ptr, e);
        # }
        else:
            f_id_ptr = f.id
            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
            Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"write")
            event_analyzed+=1

            if f_id_ptr in File_Related:
                File_Related[f_id_ptr].append(e_id)
            else:
                File_Related[f_id_ptr]=[e_id]

            if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
            else:
                Proc_Related[p_id_ptr]=[e_id]

            # e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
            # Insert_Dict(seq, sess,p_id_ptr , s_id_ptr, e_id, timestamp,syscall_str)
            # event_analyzed+=1

            # if s_id_ptr in File_Related:
            # 	File_Related[s_id_ptr].append(e_id)
            # else:
            # 	File_Related[s_id_ptr]=[e_id]

            # if p_id_ptr in Proc_Related:
            # 	Proc_Related[p_id_ptr].append(e_id)
            # else:
            # 	Proc_Related[p_id_ptr]=[e_id]
            # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Write, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Write;
    elif syscall_str=="recvfrom":
        # // Don't track recvefrom system with 0 bytes return
        recvfrom_bytes = str(event["auditd"]["data"]["exit"]);
        if (recvfrom_bytes== "0"):
            return

        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"];
        if event["auditd"]["data"].get("socket") and ( event["auditd"]["data"]["socket"].get("saddr") or  event["auditd"]["data"]["socket"].get("path")):
            return

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd_vec = SearchFd(p_id)

        fd_str = str(event["auditd"]["data"]["a0"])
        fd_idx = int(fd_str, 16)
        fd_vec_size = len(fd_vec)

        seq = int(event["auditd"]["sequence"])
        # // Todo: Auditbeat don't record syscalls for sshd
        if (fd_idx >= fd_vec_size):
            # db_print("Sequence: " << uint128tostring(seq) << " Unexpected fd: " << fd_idx << " in recvfrom syscall");
            return

        f_id = fd_vec[fd_idx]
        # // Todo: Auditbeat don't record syscalls for sshd
        if (f_id == 0 and fd_idx != 0):
            # db_print("Sequence: " << uint128tostring(seq) << " read closed fd: " << fd_idx << " in recvfrom syscall");
            return

        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])

        s = SearchSocket(f_id)
        if (s == None):
            return

        s_id_ptr = s.id
        p_id_ptr = p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        # Insert_Dict(seq, sess,p_id_ptr , s_id_ptr, e_id, timestamp,"recv")
        Insert_Dict(seq, sess, s_id_ptr,p_id_ptr , e_id, timestamp,"recv")
        event_analyzed+=1

        if s_id_ptr in File_Related:
            File_Related[s_id_ptr].append(e_id)
        else:
            File_Related[s_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
            Proc_Related[p_id_ptr].append(e_id)
        else:
            Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (s_id_ptr, p_id_ptr, EdgeType_t::Recv, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*s_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Recvfrom;
    elif syscall_str=="sendto":
        # // Don't track sendto system with 0 bytes return
        sendto_bytes = str(event["auditd"]["data"]["exit"])
        if (sendto_bytes == "0"):
            return

        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"];
        if (event["auditd"]["data"].get("socket") and (event["auditd"]["data"]["socket"].get("saddr") or event["auditd"]["data"]["socket"].get("path"))):
            return

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd_vec = SearchFd(p_id)

        fd_str = str(event["auditd"]["data"]["a0"])
        fd_idx = int(fd_str, 16)
        fd_vec_size = len(fd_vec)

        # // Todo: Auditbeat don't record syscalls for sshd
        seq = int(event["auditd"]["sequence"])
        if (fd_idx >= fd_vec_size):
            # db_print("Sequence: " << uint128tostring(seq) << " Unexpected fd: " << fd_idx << " in sendto syscall");
            return

        f_id = fd_vec[fd_idx];
        # // Todo: Auditbeat don't record syscalls for sshd
        if (f_id == 0 and fd_idx != 1):
            # db_print("Sequence: " << uint128tostring(seq) << " send closed fd: " << fd_idx << " in sendto syscall");
            return
        # }

        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp =str(event["@timestamp"])

        s = SearchSocket(f_id)
        if (s == None):
            return

        s_id_ptr = s.id
        p_id_ptr = p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr , s_id_ptr, e_id, timestamp,"send")
        event_analyzed+=1

        if s_id_ptr in File_Related:
            File_Related[s_id_ptr].append(e_id)
        else:
            File_Related[s_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
            Proc_Related[p_id_ptr].append(e_id)
        else:
            Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (p_id_ptr, s_id_ptr, EdgeType_t::Send, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*s_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Sendto;
    elif syscall_str=="recvmsg":
        # // Don't track recvmsg system with 0 bytes return
        recvmsg = event["auditd"]["data"]["exit"]
        if (int(recvmsg)== 0) :
            return

        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"]
        if  event["auditd"]["data"].get("socket") and (event["auditd"]["data"]["socket"].get("saddr") or event["auditd"]["data"]["socket"].get("path")):
            return


        pid = str(event["process"]["pid"])
        p = SearchProc(pid)
        # p=PidTable[str(pid)]

        # // magic proc is never created
        if not p :
            return

        p_id = p.id
        fd_vec = ProcFdMap[p_id]

        fd_str = event["auditd"]["data"]["a0"]
        fd_idx = int(fd_str, 16)
        fd_vec_size = len(fd_vec)

        # // Todo: Auditbeat don't record syscalls for sshd
        seq = int(event["auditd"]["sequence"])
        if (fd_idx >= fd_vec_size) :
            # db_print("Sequence: " << uint128tostring(seq) << " Unexpected fd: " << fd_idx << " in recvmsg syscall");
            return


        f_id = fd_vec[fd_idx]
        # // Todo: Auditbeat don't record syscalls for sshd
        if (f_id == 0 and fd_idx != 0) :
            # print("Sequence: " + str(seq) + " recv closed fd: " + str(fd_idx) + " in recvmsg syscall");
            return


        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        timestamp = event["@timestamp"]

        # // Recvmsg could happen before Connect Syscall
        s =SearchSocket(f_id) #SocketNodeTable[f_id]
        if (s == None):
            return


        if (s.name.find("socket") != -1) :
            if (event["auditd"]["data"].get("socket") and event["auditd"]["data"]["socket"].get("addr")) :
                new_ip = str(event["auditd"]["data"]["socket"]["addr"])
                new_port = str(event["auditd"]["data"]["socket"]["port"])
                s.name = new_ip + ":" + new_port



        s_id_ptr = s.id
        p_id_ptr = p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        # Insert_Dict(seq, sess,p_id_ptr , s_id_ptr, e_id, timestamp,"recv")
        Insert_Dict(seq, sess, s_id_ptr,p_id_ptr , e_id, timestamp,"recv")
        event_analyzed+=1

        if s_id_ptr in File_Related:
            File_Related[s_id_ptr].append(e_id)
        else:
            File_Related[s_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
            Proc_Related[p_id_ptr].append(e_id)
        else:
            Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (s_id_ptr, p_id_ptr, EdgeType_t::Recv, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*s_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);

        # pass
    # SyscallType_t::Recvmsg;
    elif syscall_str=="sendmsg":
            # // Don't track sendmsg system with 0 bytes return
        sendmsg_bytes = str(event["auditd"]["data"]["exit"]);
        if (sendmsg_bytes =="0"):
            return

        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"];
        if (event["auditd"]["data"].get("socket") and (event["auditd"]["data"]["socket"].get("saddr") or event["auditd"]["data"]["socket"].get("path"))):
            return

        pid = str(event["process"]["pid"]);
        p = SearchProc(pid);

        # // magic proc is never created
        if (p == None) :
            return

        p_id = p.id
        fd_vec = SearchFd(p_id)

        fd_str = str(event["auditd"]["data"]["a0"]);
        fd_idx = int(fd_str, 16)
        fd_vec_size = len(fd_vec)

        # // Todo: Auditbeat don't record syscalls for sshd
        seq = int(event["auditd"]["sequence"])
        if (fd_idx >= fd_vec_size):
            # db_print("Sequence: " << uint128tostring(seq) << " Unexpected fd: " << fd_idx << " in sendmsg syscall");
            return


        f_id = fd_vec[fd_idx]

        # // Todo: Auditbeat don't record syscalls for sshd
        if (f_id == 0 and fd_idx != 1):
            # db_print("Sequence: " << uint128tostring(seq) << " send closed fd: " << fd_idx << " in sendmsg syscall");
            return


        # // add new edges into KGEdge
        sess = int(str(event["auditd"]["session"]))
        timestamp = str(event["@timestamp"])

        s = SearchSocket(f_id)
        if (s == None):
            return

        # // Sendmsg could happen before Connect Syscall
        if (s.name.find("socket") != -1):
            if (event["auditd"]["data"].get("socket") and event["auditd"]["data"]["socket"].get("addr")):
                new_ip = str(event["auditd"]["data"]["socket"]["addr"]);
                new_port = str(event["auditd"]["data"]["socket"]["port"]);
                s.name = new_ip + ":" + new_port;

        s_id_ptr = s.id
        p_id_ptr = p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,s_id_ptr , e_id, timestamp,"send")
        event_analyzed+=1

        if s_id_ptr in File_Related:
                File_Related[s_id_ptr].append(e_id)
        else:
                File_Related[s_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
                Proc_Related[p_id_ptr].append(e_id)
        else:
                Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (p_id_ptr, s_id_ptr, EdgeType_t::Send, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*s_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # # SyscallType_t::Sendmsg;
    elif syscall_str=="mkdir":
        # std::string name;
        # std::string version;

        # // If it is a relative path (1) or absolute path (2)
        # std::string nametype;

        name=""
        version=""

        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            nametype = str(file["nametype"])

            if (nametype=="PARENT"):
                continue

            if not file.get("name"):
                return
            name = str(file["name"])
            if (name[0] == '.'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + "/" + name

            if file.get("version"):
                version = str(file["version"])

        if name=="":
            return


        f_tmp = NodeFile (name, version)
        f = InsertFile(f_tmp)

        pid = str(event["process"]["pid"]);
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        seq = int(event["auditd"]["sequence"])
        sess = str(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])

        p_id_ptr = p.id
        f_id_ptr = f.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"mkdir")
        event_analyzed+=1

        if f_id_ptr in File_Related:
                    File_Related[f_id_ptr].append(e_id)
        else:
                    File_Related[f_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
                    Proc_Related[p_id_ptr].append(e_id)
        else:
                    Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Mkdir, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*f_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Mkdir;
    elif syscall_str=="rmdir":
        # std::string name;
        # std::string version;
        # std::string nametype;

        name=""
        version=""

        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            nametype = str(file["nametype"])

            if (nametype=="PARENT"):
                continue

            name = str(file["name"])
            if (name[0] == '.') :
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + "/" + name

            if file.get("version"):
                version = str(file["version"])

        if name=="":
            return

        f_tmp = NodeFile(name, version)
        f = InsertFile(f_tmp)

        # // add new edges into KGEdge
        sess = int(event["auditd"]["session"])
        seq = int(event["auditd"]["sequence"])
        timestamp = str(event["@timestamp"])

        pid = str(event["process"]["pid"])
        p =SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        f_id_ptr = f.id
        p_id_ptr = p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"rmdir")
        event_analyzed+=1

        if f_id_ptr in File_Related:
                    File_Related[f_id_ptr].append(e_id)
        else:
                    File_Related[f_id_ptr]=[e_id]

        if p_id_ptr in Proc_Related:
                    Proc_Related[p_id_ptr].append(e_id)
        else:
                    Proc_Related[p_id_ptr]=[e_id]
        # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Rmdir, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
        # infotbl->InsertFileInteraction(*f_id_ptr, e);
        # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Rmdir;
    elif syscall_str=="getpeername":
        # // We dont track internel socket
        # socket = event["auditd"]["data"]["socket"]
        if event["auditd"]["data"].get("socket") and (event["auditd"]["data"]["socket"].get("saddr") or event["auditd"]["data"]["socket"].get("path")):
            return

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        # // obtain old file id
        fd_str = str(event["auditd"]["data"]["a0"])
        fd_idx = int(fd_str, 16)
        fd_vec = SearchFd(p_id)
        # // hash_t f_id = (*fd_vec)[fd_idx];

        # // to update the socket name
        if event["auditd"]["data"].get("socket") and event["auditd"]["data"]["socket"].get("addr"):
            ip = str(event["auditd"]["data"]["socket"]["addr"])
            port = str(event["auditd"]["data"]["socket"]["port"])
            new_name = ip + ":" + port
        else:
            return

        s_tmp = NodeSocket (new_name)
        s = InsertSocket(s_tmp)

        fd_vec[fd_idx] = s.id

        # // Todo: We assume that there is no edge (e.g., sendto, recvefrom) including old socket before getpeername
        # // infotbl->SocketNodeTable.extract(f_id);
        # // infotbl->KGNodeTable.extract(f_id);

        # // add new edges into KGEdge (debug)
        sess = str(event["auditd"]["session"])
        seq = int(event["auditd"]["sequence"])
        timestamp = str(event["@timestamp"])

        p_id_ptr = p.id
        s_id_ptr = s.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(s_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,s_id_ptr , e_id, timestamp,syscall_str)
        event_analyzed+=1
        # KGEdge *e = new KGEdge (p_id_ptr, s_id_ptr, EdgeType_t::Getpeername, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
    # SyscallType_t::Getpeername;
    elif syscall_str=="fcntl":
        # // F_DUPFD = 0
        args = str(event["auditd"]["data"]["a1"])
        if (args != "0"):
            return

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return

        p_id = p.id
        fd_old = str(event["auditd"]["data"]["a0"])
        fd_new = str(event["auditd"]["data"]["exit"])

        # // copy new fd into PidTable
        CopyFd(p_id, fd_old, fd_new)
    # SyscallType_t::Fcntl;
    elif syscall_str=="rename":
        # std::string name;
        # std::string version;
        # std::string nametype;

        sess = int(event["auditd"]["session"])
        seq = int(event["auditd"]["sequence"])
        timestamp = str(event["@timestamp"])

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        if (p == None):
            return

        p_id_ptr = p.id

        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            nametype = str(file["nametype"])

            if (nametype=="PARENT"):
                continue

            name = str(file["name"])
            version=""
            if file.get("version"):
                version = str(file["version"])

            if (name[0] == '.'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"]);
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + "/" + name

            f_tmp = NodeFile (name, version)
            f = InsertFile(f_tmp)

            f_id_ptr = f.id

            if (nametype=="CREATE"):
                e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
                Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"rename_create")
                event_analyzed+=1

                if f_id_ptr in File_Related:
                    File_Related[f_id_ptr].append(e_id)
                else:
                    File_Related[f_id_ptr]=[e_id]

                if p_id_ptr in Proc_Related:
                    Proc_Related[p_id_ptr].append(e_id)
                else:
                    Proc_Related[p_id_ptr]=[e_id]
                # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Create, seq, sess, timestamp);
                # infotbl->InsertEdge(e);
                # infotbl->InsertFileInteraction(*f_id_ptr, e);
                # infotbl->InsertProcInteraction(*p_id_ptr, e);
            else:
                e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
                Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,"rename_delete")
                event_analyzed+=1

                if f_id_ptr in File_Related:
                    File_Related[f_id_ptr].append(e_id)
                else:
                    File_Related[f_id_ptr]=[e_id]

                if p_id_ptr in Proc_Related:
                    Proc_Related[p_id_ptr].append(e_id)
                else:
                    Proc_Related[p_id_ptr]=[e_id]
                # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Delete, seq, sess, timestamp);
                # infotbl->InsertEdge(e);
                # infotbl->InsertFileInteraction(*f_id_ptr, e);
                # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Rename;
    elif syscall_str=="kill":
        pid = str(event["process"]["pid"])
        p = SearchProc(pid)
        seq = int(event["auditd"]["sequence"])

        # // magic proc is never created
        if (p == None):
            return

        delete_pid_hex = str(event["auditd"]["data"]["a0"])
        delete_pid_int = int(delete_pid_hex, 16)

        # // Todo: We do not consider the situation that pid in kill is not positive
        # // 2147483647 = 2^31 - 1
        if (delete_pid_int > 2147483647):
            return

        delete_pid_str = str(delete_pid_int)

        delete_p = SearchProc(delete_pid_str)
        if (delete_p == None):
            # db_print("Sequence: " << uint128tostring(seq) << "cannot find killed proc: " << delete_pid_str);
            return

        sess = int(event["auditd"]["session"])
        timestamp = str(event["@timestamp"])
        p_id_ptr = p.id
        delete_p_id_ptr = delete_p.id

        e_id= gen_md5_id(str(seq)+str(sess)+str(delete_p_id_ptr)+str(p_id_ptr))
        Insert_Dict(seq, sess,p_id_ptr ,delete_p_id_ptr , e_id, timestamp,"kill")
        event_analyzed+=1
        # KGEdge *e = new KGEdge (p_id_ptr, delete_p_id_ptr, EdgeType_t::Kill, seq, sess, timestamp);
        # infotbl->InsertEdge(e);
    # SyscallType_t::Kill;
    elif syscall_str=="link" or syscall_str=="linkat":
        # std::string name;
        # std::string version;
        # std::string nametype;

        sess = int(event["auditd"]["session"])
        seq = int(event["auditd"]["sequence"])
        timestamp = str(event["@timestamp"])

        pid = str(event["process"]["pid"])
        p = SearchProc(pid)

        # // magic proc is never created
        if (p == None):
            return


        p_id_ptr = p.id

        if not event["auditd"].get("paths"):
            return

        for file in event["auditd"]["paths"]:
            nametype = str(file["nametype"])

            if (nametype=="CREATE"):
                continue

            name = str(file["name"])
            version = ""
            if file.get("version"):
                version=str(file["version"])

            if (name[0] == '.'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                        dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + name[1:]
            elif (name[0] != '/'):
                # dir = str(event["process"]["cwd"])
                if event["process"].get("cwd"):
                    dir = str(event["process"]["cwd"])
                else:
                    dir=str(event["process"]["working_directory"])
                name = dir + "/" + name

            f_tmp = NodeFile (name, version)
            f = InsertFile(f_tmp)

            f_id_ptr = f.id
            e_id= gen_md5_id(str(seq)+str(sess)+str(f_id_ptr)+str(p_id_ptr))
            Insert_Dict(seq, sess,p_id_ptr ,f_id_ptr , e_id, timestamp,syscall_str+"_create")
            event_analyzed+=1
            # KGEdge *e = new KGEdge (p_id_ptr, f_id_ptr, EdgeType_t::Create, seq, sess, timestamp);
            # infotbl->InsertEdge(e);
            # infotbl->InsertFileInteraction(*f_id_ptr, e);
            # infotbl->InsertProcInteraction(*p_id_ptr, e);
    # SyscallType_t::Link;
    else:
            pass

def ParseEbpfEvent(event):
    proc = SearchProc(event["pid"])
    if proc == None:
        return
    timestamp = event["timestamp"]
    seq = event["seq"]
    log_type = event["log_type"]
    if log_type == "bash_readline:":
        log_strs = event["log"].split()
        command = log_strs[0]
        args = log_strs[1:]
        if command == "export":
            option_f = 0
            option_n = 0
            option_p = 0
            for arg in args:
                if arg[0] == '-':
                    if "f" in arg:
                        option_f = 1
                    if "n" in arg:
                        option_n = 1
                    if "p" in arg:
                        option_p = 1
                    args.remove(arg)

            if len(args) == 0: #export
                env_tmp = NodeEnv("",event["pid"],1)
                env = InsertEnv(env_tmp)
                env_id_ptr = env.id
                p_id_ptr = proc.id
                sess = 0

                e_id = gen_md5_id(str(seq) + str(sess) + str(env_id_ptr) + str(p_id_ptr))
                Insert_Dict(seq, sess, env_id_ptr, p_id_ptr, e_id, timestamp, "readEnv")

            elif len(args) == 1:
                arg = args[0]
                if "=" in arg: #export ENV=Var
                    pos = arg.index("=")
                    env_tmp = NodeEnv(arg[0:pos], event["pid"],0)
                    env = InsertEnv(env_tmp)
                    env_id_ptr = env.id
                    p_id_ptr = proc.id
                    sess = 0

                    e_id = gen_md5_id(str(seq) + str(sess) + str(env_id_ptr) + str(p_id_ptr))
                    Insert_Dict(seq, sess, p_id_ptr, env_id_ptr, e_id, timestamp, "writeEnv")
                else: #export ENV
                    env_tmp = NodeEnv(arg, event["pid"], 0)
                    env = InsertEnv(env_tmp)
                    env_id_ptr = env.id
                    p_id_ptr = proc.id
                    sess = 0

                    e_id = gen_md5_id(str(seq) + str(sess) + str(env_id_ptr) + str(p_id_ptr))
                    Insert_Dict(seq, sess, p_id_ptr, env_id_ptr, e_id, timestamp, "createEnv")
        elif command == "echo":
            option_e = 0
            option_n = 0
            for arg in args:
                if arg[0] == '-':
                    if "e" in arg:
                        option_e = 1
                    if "n" in arg:
                        option_n = 1
                    args.remove(arg)
            if len(args) == 1:
                arg = args[0]
                if arg.startswith("$"): #echo $VAR
                    env_tmp = NodeEnv(arg[1:], event["pid"], 0)
                    env = InsertEnv(env_tmp)
                    env_id_ptr = env.id
                    p_id_ptr = proc.id
                    sess = 0

                    e_id = gen_md5_id(str(seq) + str(sess) + str(env_id_ptr) + str(p_id_ptr))
                    Insert_Dict(seq, sess, p_id_ptr, env_id_ptr, e_id, timestamp, "readEnv")




#用于标记一些与加载库相关的边（edges）为噪声边，并将这些边的 ID 添加到 Noise_Edge 列表中
'''
创建一个空列表 lib 用于存储已经标记为噪声的库文件节点。
遍历全局字典 Proc_Related，其中包含了进程节点与相关边的映射关系。
对于每个进程节点，遍历与之相关的边（e_ids）。
如果边的类型是 "Load"，则提取边的信息，包括源节点（sub_id，表示进程）和目标节点（obj_id，表示文件）。
检查目标文件节点（obj_id）是否已经在 lib 中，如果是，则将当前边的 ID 添加到 Noise_Edge 列表中。
如果目标文件节点不在 lib 中，则遍历与该文件相关的边（f_e_ids）。
对于每个文件相关的边，检查目标文件节点是否与当前文件节点一致，并且源节点与当前进程节点不一致，
如果是，则说明有其他进程也与该文件节点相关，因此不将当前边标记为噪声。
'''
def Noise_Lib():
    lib=[]
    for sub_id,e_ids in Proc_Related.items():
        for e_id in e_ids:
            e_item=Edge_dict[e_id]
            if e_item["e_type"]=="Load":
                sub_id=e_item["sub_id"]#file
                obj_id=e_item["obj_id"]#proc
                if sub_id in lib:
                    Noise_Edge.append(e_id)
                else:
                    f_e_ids=File_Related[sub_id]
                    flag=True
                    for f_e_id in f_e_ids:
                        f_e_item=Edge_dict[f_e_id]
                        target_sub_id=f_e_item["sub_id"]
                        target_obj_id=f_e_item["obj_id"]
                        # if target_obj_id==obj_id and target_sub_id!=sub_id:
                        if (target_obj_id==sub_id and target_sub_id!=obj_id) or (target_obj_id==obj_id and target_sub_id!=sub_id):
                            flag=False
                            break
                    if flag:
                        Noise_Edge.append(e_id)
                        lib.append(obj_id)

#标记一些缺失的边为噪声边，并将这些边的 ID 添加到 Noise_Edge 列表中
def Missing_Edge():
    for e_id,edge_item in Edge_dict.items():
        sub_id=edge_item["sub_id"]
        obj_id=edge_item["obj_id"]

        if sub_id not in Node_dict or obj_id not in Node_dict:
            Noise_Edge.append(e_id)

#用于标记一些与临时文件相关的边为噪声边，并将这些边的 ID 添加到 Noise_Edge 列表中
def Tmp_File():
    # sorted(Edge_dict,key=lambda x:x["seq"])
    # 26145	ca77a93fd698473ef0cc483f5117aa21	b614681646de6aaf75b91976fdc890d5	Proc	4032	d67e3381cc0c5aab4e4d229cc9b91346	File	4033	2023-05-23T14:37:36.098Z	openat_create	[2053, 1069, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]	0
    # 26146	f1aff100b4e5dfa76e2d598ded9b6efa	b614681646de6aaf75b91976fdc890d5	Proc	4032	d67e3381cc0c5aab4e4d229cc9b91346	File	4033	2023-05-23T14:37:36.098Z	write	[3141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]	0
    for obj_id,e_ids in File_Related.items():
        sorted(e_ids,key=lambda x:Edge_dict[x]["seq"])
        is_temporary = False
        s_sub_id=""
        s_obj_id=""
        same_flag=False
        end_flag=False

        # if obj_id in FileNodeTable:
        # 	file_info=FileNodeTable[obj_id]
        # 	file_name=file_info.name
        # 	is_ok=True
        # 	for item in noise_file:
        # 		if item in file_name or file_name.endswith(".c") or file_name.endswith(".h"):
        # 			is_ok=False
        # 			for index,e_id in enumerate(e_ids):
        # 				Noise_Edge.append(e_id)
        # 			break
        # 	if not is_ok:
        # 		continue

        for index,e_id in enumerate(e_ids):
            if index==0:
                type=Edge_dict[e_id]["e_type"]
                if type!="rename_create" and type!="open_create" and type!="openat_create" and type!="mq_open_create" and type!="link_create" and type!="linkat_create":
                    break
                s_sub_id=Edge_dict[e_id]["sub_id"]
                s_obj_id=Edge_dict[e_id]["obj_id"]
                continue
            type=Edge_dict[e_id]["e_type"]
            sub_id=Edge_dict[e_id]["sub_id"]
            obj_id=Edge_dict[e_id]["obj_id"]
            if s_sub_id!=sub_id:
                break
            if s_sub_id==sub_id:
                same_flag=True
            if type=="unlink_delete" or type=="unlinkat_delete":
                end_flag=True
            if same_flag and end_flag:
                Noise_Edge.append(e_id)
                break

def Remove_Attack(keywords):
    # keywords=["192.168.17.133","212.64.63.215","/bin/wget","infect.py","woot.sh","apt-get update","apt-get install python3 -y","apt-get install wget -y","apt-get install nmap -y","apt-get install net-tools -y"]
    for node,node_info in ProcNodeTable.items():
        for item in keywords:
            if item in node_info.exe or item in node_info.args:
                if node in Proc_Related:
                    e_ids=Proc_Related[node]
                    for e_id in e_ids:
                        Noise_Edge.append(e_id)

    for node, node_info in FileNodeTable.items():
        for item in keywords:
            if item in node_info.name:
                if node in File_Related:
                    e_ids=File_Related[node]
                    for e_id in e_ids:
                        Noise_Edge.append(e_id)

    # for node, node_info in SocketNodeTable.items():
    # 	for item in keywords:
    # 		if item in node_info.name:
    # 			if node in



'''
对于每个文件节点，获取与之相关的边的列表 e_ids。
对 e_ids 进行排序，按照边的 seq 属性升序排列。
遍历排序后的边列表，对每条边进行处理。
如果当前边的类型为 "write" 或 "send"，尝试查找后续的边中是否有相同源节点、相同目标节点，并且类型也为 "write" 或 "send" 的边。
如果找到这样的边，并且当前边与找到的边不同，将当前边的 ID 添加到 Noise_Edge 列表中。这表示可能存在影子文件的写入行为。
'''
def Shadow_File():
    # test  d67e3381cc0c5aab4e4d229cc9b91346
    # 26145	ca77a93fd698473ef0cc483f5117aa21	b614681646de6aaf75b91976fdc890d5	Proc	4032	d67e3381cc0c5aab4e4d229cc9b91346	File	4033	2023-05-23T14:37:36.098Z	openat_create	[2053, 1069, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]	0
    # 26146	f1aff100b4e5dfa76e2d598ded9b6efa	b614681646de6aaf75b91976fdc890d5	Proc	4032	d67e3381cc0c5aab4e4d229cc9b91346	File	4033	2023-05-23T14:37:36.098Z	write	[3141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]	0
    # sorted(Edge_dict,key=lambda x:x["seq"])
    print(len(File_Related.items()))
    count=0
    for obj_id,e_ids in File_Related.items():
        count+=1
        if count%100==0:
            print(count)
        sorted(e_ids,key=lambda x:Edge_dict[x]["seq"])
        for index,e_id in enumerate(e_ids):
            type=Edge_dict[e_id]["e_type"]
            sub_id=Edge_dict[e_id]["sub_id"]
            obj_id=Edge_dict[e_id]["obj_id"]
            is_shadow_flag=False
            if type=="write" or type=="send":#type=="EVENT_READ" or type=="EVENT_RECVMSG":
                try_index=index+1
                for index_j,e_id_j in enumerate(e_ids):
                    if index_j<try_index:
                        continue
                    type_j=Edge_dict[e_id_j]["e_type"]
                    sub_id_j=Edge_dict[e_id_j]["sub_id"]
                    obj_id_j=Edge_dict[e_id_j]["obj_id"]
                    if sub_id==sub_id_j and (type_j=="write" or type_j=="send"):
                        is_shadow_flag=True
                        break
                    elif sub_id==sub_id_j and (type_j!="write" and type_j!="send"):
                        break
                if is_shadow_flag and e_id !=e_id_j:
                    Noise_Edge.append(e_id)

'''
对于每个进程节点，获取与之相关的边的列表 e_ids。
对 e_ids 进行排序，按照边的 seq 属性升序排列。
遍历排序后的边列表，对每条边进行处理。
如果当前边的类型为 "read" 或 "recv"，尝试查找后续的边中是否有相同源节点、相同目标节点，并且类型也为 "read" 或 "recv" 的边。
如果找到这样的边，并且当前边与找到的边不同，将当前边的 ID 添加到 Noise_Edge 列表中。这表示可能存在影子进程的读取行为。
'''
def Shadow_Proc():
    print(len(Proc_Related.items()))
    count = 0
    for sub_id,e_ids in Proc_Related.items():
        count+=1
        if count%10==0:
            print(count)
        sorted(e_ids,key=lambda x:Edge_dict[x]["seq"])
        for index,e_id in enumerate(e_ids):
            type=Edge_dict[e_id]["e_type"]
            sub_id=Edge_dict[e_id]["sub_id"]
            obj_id=Edge_dict[e_id]["obj_id"]
            is_shadow_flag=False
            if type=="read" or type=="recv":
                try_index=index+1
                for index_j,e_id_j in enumerate(e_ids):
                    if index_j<try_index:
                        continue
                    type_j=Edge_dict[e_id_j]["e_type"]
                    sub_id_j=Edge_dict[e_id_j]["sub_id"]
                    obj_id_j=Edge_dict[e_id_j]["obj_id"]
                    if sub_id==sub_id_j and (type_j=="read" or type_j=="recv"):
                        is_shadow_flag=True
                        break
                    elif sub_id==sub_id_j and (type_j!="read" and type_j!="recv"):
                        break
                if is_shadow_flag and e_id !=e_id_j:
                    Noise_Edge.append(e_id)


# 写入文件
def Insert_SQL(base_path=""):
    with open(base_path+"/edges.csv","w") as csvfile_e:
        with open(base_path+"/nodes.csv","w") as csvfile_n:
            writer_e = csv.writer(csvfile_e)
            writer_e.writerow(["id","e_id","sub","obj","timestamp","e_type"])
            writer_n = csv.writer(csvfile_n)
            writer_n.writerow(["id","obj_subj", "obj_subj_type", "proc_exe","args","file_path","ip","port","env_name","env_all"])
            for e_id in Noise_Edge:
                if e_id in Edge_dict:
                        del(Edge_dict[e_id])
            print("comming")
            index=0
            n_index=0
            for e_id,e_item in Edge_dict.items():
                if index%10000==0:
                    print(index)
                node_info=[]
                node_info.append(str(index))
                node_info.append(e_item["e_id"])
                node_info.append(e_item["sub_id"])
                node_info.append(e_item["obj_id"])
                node_info.append(e_item["timestamp"])
                node_info.append(e_item["e_type"])
                writer_e.writerows([node_info])
                index+=1
                sub_type=KGNodeTable[e_item["sub_id"]]
                Node=None
                if sub_type=="Proc":
                    Node=ProcNodeTable[e_item["sub_id"]]
                elif sub_type=="File":
                    Node=FileNodeTable[e_item["sub_id"]]
                elif sub_type=="Socket":
                    Node=SocketNodeTable[e_item["sub_id"]]
                elif sub_type=="Env":
                    Node = EnvNodeTable[e_item["sub_id"]]
                node_sub_item=Node

                node_info=[]
                node_info.append(n_index)
                n_index+=1
                node_info.append(node_sub_item.id)
                node_info.append(sub_type)
                if sub_type=="Proc":
                        node_info.append(node_sub_item.exe)
                else:
                        node_info.append("")
                if sub_type=="Proc":
                        node_info.append(node_sub_item.args)
                else:
                        node_info.append("")
                if sub_type=="File":
                        node_info.append(node_sub_item.name)
                else:
                        node_info.append("")
                if sub_type=="Socket":
                        name=node_sub_item.name
                        if "socket" in name:
                            node_info.append(name)
                            node_info.append("")
                        else:
                            name=name.split(":")
                            ip=name[0]
                            port=name[1]
                            node_info.append(ip)
                            node_info.append(port)
                else:
                    node_info.append("")
                    node_info.append("")
                if sub_type=="Env":
                    node_info.append(node_sub_item.name)
                    node_info.append(node_sub_item.all)
                else :
                    node_info.append("")
                    node_info.append("")
                writer_n.writerows([node_info])
                sub_type=KGNodeTable[e_item["obj_id"]]
                Node=None
                if sub_type=="Proc":
                    Node=ProcNodeTable[e_item["obj_id"]]
                elif sub_type=="File":
                    Node=FileNodeTable[e_item["obj_id"]]
                elif sub_type=="Socket":
                    Node=SocketNodeTable[e_item["obj_id"]]
                elif sub_type=="Env":
                    Node=EnvNodeTable[e_item["obj_id"]]

                node_sub_item=Node
                node_info=[]
                node_info.append(n_index)
                n_index+=1
                node_info.append(node_sub_item.id)
                node_info.append(sub_type)
                if sub_type=="Proc":
                        node_info.append(node_sub_item.exe)
                else:
                        node_info.append("")
                if sub_type=="Proc":
                        node_info.append(node_sub_item.args)
                else:
                        node_info.append("")
                if sub_type=="File":
                        node_info.append(node_sub_item.name)
                else:
                        node_info.append("")
                # socket开头的是进程之间的通信，IP的话是远程的
                if sub_type=="Socket":
                        name=node_sub_item.name
                        if "socket" in name:
                            node_info.append(name)
                            node_info.append("")
                        else:
                            name=name.split(":")
                            ip=name[0]
                            port=name[1]
                            node_info.append(ip)
                            node_info.append(port)
                else:
                    node_info.append("")
                    node_info.append("")
                if sub_type=="Env":
                    node_info.append(node_sub_item.name)
                    node_info.append(node_sub_item.all)
                else:
                    node_info.append("")
                    node_info.append("")
                writer_n.writerows([node_info])

def Loadmetainfo(beat_dir):
    proc_path = beat_dir + "procinfo"
    fd_path = beat_dir + "fdinfo"
    socket_path = beat_dir + "socketinfo"
    LoadProc(proc_path)
    LoadFd(fd_path)
    LoadSocket(socket_path)

#读取指定目录下的 JSON 文件，逐行解析文件中的 JSON 行，并对每个事件调用 ParseAuditdEvent 函数进行解析
def HandleJsonFiles(files):
    for file in files:
        print(file)
        with open(file, "r", encoding="utf-8") as f:
            json_line = f.readline()
            sess = 0
            while json_line:
                event = json.loads(json_line)
                sess += 1

                if sess % 100000 == 0:
                    print(sess)

                if not event.get("auditd"):
                    json_line = f.readline()
                    continue

                if event["auditd"]["result"] == "fail" and event["auditd"]["data"].get("exit") and \
                        event["auditd"]["data"]["exit"] != "EINPROGRESS":
                    json_line = f.readline()
                    continue
                if event["auditd"]["data"].get("syscall"):
                    ParseAuditdEvent(event, sess)
                elif event["auditd"]["data"].get("acct"):
                    pass
                json_line = f.readline()


#读取指定目录下的 txt 文件，逐行解析文件中的每一行，并对每个事件调用 ParseEbpfEvent 函数进行解析
def HandleTxtFiles(files):
    for file in files:
        with open(file, "r") as f:
            txt_line = f.readline()
            while txt_line:
                line_strs = txt_line.split()
                event = {"pid": line_strs[6], "log_type":line_strs[7], "log": " ".join(line_strs[8:]), "timestamp":line_strs[3][:-1], "seq":line_strs[1][1:-1]}
                ParseEbpfEvent(event)
                txt_line = f.readline()

src_dir = r'./log4j_double_logs/'      # 源文件目录地址
Loadmetainfo(src_dir)
ndjson_files = list_all_ndjson_files(src_dir)
HandleJsonFiles(ndjson_files)
txt_files = list_all_log_files(src_dir)
HandleTxtFiles(txt_files)



print('TMP File')
Tmp_File()
print('Shadow File')
Shadow_File()
print('Shadow Proc')
Shadow_Proc()
print('Shadow Edge')
Missing_Edge()
print('Noise Lib')
Noise_Lib()

print("Insert Data")
Insert_SQL("./audibeat-log-full_log4j")