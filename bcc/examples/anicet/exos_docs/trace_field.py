#!usr/bin/python
from bcc import BPF

prog = ''' 
	int greetings(void *ctx){
		bpf_trace_printk("Hello, boss, its very late");
		return 0;
	}
'''

b = BPF(text=prog)

b.attach_kprobe(event=b.get_syscall_fnname("clone"),fn_name="greetings")