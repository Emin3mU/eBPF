# BCC开发代码分析
## 代码示例
helle_word.py
```python
from bcc import BPF

prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
```
### 代码结构分为两部分：
1. 字符串prog定义的是C程序，可以理解为探测点的回调函数;
2. python部分是对BPF对象的声明以及对探测结果的整理输出；
## C语言代码用法
```c
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(count);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid(); //获取执行该命令的进程ID
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```
+ 结构体data_t:  将数据从内核空间传递到用户空间的C结构体;
+ BPF_PERF_OUTPUT(events): 
    + 定义输出channel为events；
    + 将探测的数据写入data_t后通过events.perf_submit(ctx, &data, sizeof(data))将数据交给用户空间；
+ 辅助函数 int hello(struct pt_regs *ctx): 
  + 上下文信息struct pt_regs*是C程序固定的首个参数;
  + 如需获取探针处更多数据，可添加探针所属函数的参数，如hello()需要在tcp_sendmsg()处添加probe，tcp_sendmsg函数原型为：  
    `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);`  
    回调函数hello可定义为:  
    `int hello(struct pt_regs *ctx,struct sock *sk, struct msghdr *msg, size_t size);`
  + 如果辅助函数hello不是在probe上调用，需定义为static inline;
  + 辅助函数可直接声明为 kprobe__tcp_sendmsg(),使用kprobe__或kreprobe__的前缀,会将剩余部分作为内核函数名来处理，此用法python部分无需调用attach_kprobe方法;
+ BPF_HASH(count):初始化一个全局哈希映射，可保存多个键值对。该宏定义:
  ```c
  //BPF_HASH(name,key_type=u64,leaf_type=u64,size=1024)
  #define BPF_HASH1(_name) BPF_TABLE("hash",u64,64,_name,1024)
  #define BPF_HASH2(_name,_key_type) BPF_TABLE("hash",_jey_type,u64,_name,1024)
  ...
  ``` 
  用法为`u64 key;  count.lookup(&key); count.update(&key);count.delete(&key)`;
  更多的数据结构可参照 [github-bcc-maps](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps)
+ TRACEPOINT：TRACEPOINT是已预埋至内核中的追踪点，若TRACEPOINT能满足监测需求，则无需翻阅kernel相关模块的代码查看数据结构。
  + 可通过perf list查看内核中已预埋的所有tracepoint;
  + 以tcp_send为例使用tracepoint：
    ```c
    TRACEPOINT_PROBE(tcp,tcp_send_reset) {
    return hello(args, args->saddr);
    }
    ```
    参数tcp,tcp_send_reset分别为事件类别和事件名，通过perf list查找到所需即可;
    args是bcc生成的,对于args中数据可通过下面的命令进行获取:  
    `sudo cat /sys/kernel/debug/tracing/events/tcp/tcp_send_reset/format`  
    返回示例
    ```
    name: tcp_send_reset
    ID: 1312
    format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:const void * skbaddr;	offset:8;	size:8;	signed:0;
	field:const void * skaddr;	offset:16;	size:8;	signed:0;
	field:int state;	offset:24;	size:4;	signed:1;
	field:__u16 sport;	offset:28;	size:2;	signed:0;
	field:__u16 dport;	offset:30;	size:2;	signed:0;
	field:__u16 family;	offset:32;	size:2;	signed:0;
	field:__u8 saddr[4];	offset:34;	size:4;	signed:0;
	field:__u8 daddr[4];	offset:38;	size:4;	signed:0;
	field:__u8 saddr_v6[16];	offset:42;	size:16;	signed:0;
	field:__u8 daddr_v6[16];	offset:58;	size:16;	signed:0;

    ```
  + bpf_get_current_comm()、bpf_get_current_pid_tgid():  
    BPF提供的方法，更多函数及说明参照 [Linux manual page](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
## Python代码用法
```python
# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        "Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
```
+ attach_kprobe(event=b.get_syscall_fnname("clone"),fn_name="hello")
  + 添加探针到系统调用，参数分别是系统调用函数名clone,自定义回调函数名hello;
  +  attach_kprobe 内核打点函数入口调用回调、attach_kreprobe 内核打点函数返回时调用回调、attach_uprobe/attach_uprobe用户态的函数。用户态加探针：  
  ```python
  attach_uprobe(name="c", sym="strlen", fn_name="do_strlen")
  attach_uprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
  ```
+ b["events"].open_perf_buffer(print_event): 将数据从内核传到用户空间，函数原型`table.open_perf_buffers(callback, page_cnt=N, lost_cb=None)`
+ event = b["events"].event(data): 将自定义的数据结构从C转为python对象
+ b.perf_buffer_poll()：阻塞等待事件，将对perf环形缓冲区进行轮询，有数据则会调用open_perf_buffer指定的回调;


   
  
