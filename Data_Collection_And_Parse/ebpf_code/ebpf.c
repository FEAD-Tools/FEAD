/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
//ROP攻击例子
SEC("uretprobe//root/Downloads/ret2text/pwn1:vuln")
int BPF_KRETPROBE(exit_time_stamp)
{
    u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("PID %d exit", pid);
    return 0;
}

SEC("uprobe//root/Downloads/ret2text/pwn1:vuln")
int BPF_KPROBE(entry_time_stamp)
{
    u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("PID %d entry", pid);
    return 0;
}
*/

/*
//监控脚本中的命令行
#define MAX_LINE_SIZE 64

SEC("uprobe//usr/bin/bash:main")
int BPF_KPROBE(printArgv, int argc, char** argv)
{
 char str1[MAX_LINE_SIZE];
 char str2[MAX_LINE_SIZE];
 char str3[MAX_LINE_SIZE];
 u32 pid;

 if (!argv)
  return 0;

 void* addr;
 bpf_printk("bash got %d argv", argc - 1);
 argv++;
 bpf_probe_read_user(&addr, sizeof(addr), argv);
 bpf_probe_read_user_str(str1, sizeof(str1), addr);
 bpf_printk("bash first: %s", str1);
 argv++;
 bpf_probe_read_user(&addr, sizeof(addr), argv);
 bpf_probe_read_user_str(str2, sizeof(str2), addr);
 bpf_printk("bash second: %s", str2);
 argv++;
 bpf_probe_read_user(&addr, sizeof(addr), argv);
 bpf_probe_read_user_str(str3, sizeof(str2), addr);
 bpf_printk("bash third: %s", str3);

 return 0;
};
*/


//监控输入命令行

#define MAX_LINE_SIZE 128
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
    char str[MAX_LINE_SIZE];
    u32 pid;

    if (!ret)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d bash_readline: %s", pid, str);

    return 0;
};


/*
SEC("uprobe//usr/lib64/libc.so.6:getenv")
int BPF_KPROBE(getenvName, const char* __name)
{
    char comm[16];
    char str[64];
    u32 pid;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user(str, sizeof(__name), __name);

    bpf_printk("PID %d getenv name: %s", pid, __name);
    return 0;
}
*/

/*
SEC("uprobe//root/Downloads/clion-2023.3.4/projects/test/cmake-build-debug/test:func")
int BPF_KPROBE(getName, const char* __name)
{

    bpf_printk("getenv name: %s", __name);
    return 0;
}
*/
