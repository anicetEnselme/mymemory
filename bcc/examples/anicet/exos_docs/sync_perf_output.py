#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = '''
	#include <uapi/linux/ptrace.h>
	#include <linux/sched.h>

	BPF_HASH(last);

	//define data structure here
	struct data_t {
		u64 ts;
		u64 count;
		u64 ms;
	};

	BPF_PERF_OUTPUT(events);

	int sync_perf(struct pt_regs *ctx) {
		struct data_t data = {};
		u64 *tsp, *countp, delta, key = 0, count_key = 1;

		// syscall counter
		countp = last.lookup(&count_key);
		if(countp == 0)
		{
			data.count = 1;
		}
		else
		{
			data.count = ++*countp;
			last.delete(&count_key);
		}
		last.update(&count_key,&data.count);

		//time
		data.ts = bpf_ktime_get_ns();
		tsp = last.lookup(&key);
		if(tsp != 0)
		{
			delta = data.ts - *tsp; 
			if(delta < 1000000000)
			{
				data.ms = delta;
			}
			last.delete(&key);
		}

		last.update(&key,&data.ts);
		events.perf_submit(ctx, &data, sizeof(data));
		return 0;

	}


'''

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name = "sync_perf")
print("Tracing sync with BPF-perf-output...ctrl-C to end")

start = 0
def print_event(cpu,data,size):
	global start
	event = b["events"].event(data)
	if start == 0:
		start = event.ts 
	time = (float(event.ts - start))/1000000000 
	print(b"At time {}s {} syncs detected, last {} ms ago ".format(time,event.count,event.ms/1000000))

b["events"].open_perf_buffer(print_event)
while 1:
	b.perf_buffer_poll()