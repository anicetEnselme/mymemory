#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, *count, yo, delta, key = 0, key1 = 1;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    count = last.lookup(&key1);
    if(count == 0){
        yo = 1;
    }
    else{
        yo = *count; 
        last.increment(key1);                                                  
    }
    //last.update(&key1,&yo);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d,%d \\n", yo, delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
   // bpf_trace_printk("%s\\n", "Je suis venu ici\\n");
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        [yo,ms] = msg.split(",")
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: %s syncs detected, last %s ms ago" % (ts, yo, ms))
    except KeyboardInterrupt:
        exit()
