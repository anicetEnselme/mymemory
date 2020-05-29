#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.
# Modified by Enselme AGUIDIGODO

from __future__ import print_function
from bcc import BPF

from bcc.utils import printb
from time import sleep, strftime
import argparse
import signal
import re
from sys import argv

REQ_WRITE = 1		# from include/linux/blk_types.h // runqueu

#======================== cache stats ==================>
# signal handler
def signal_ignore(signal, frame):
    print()

# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = dict()

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result

# set global variables
mpa = 0
mbd = 0
apcl = 0
apd = 0
total = 0
misses = 0
hits = 0
debug = 0

# arguments
parser = argparse.ArgumentParser(
    description="Count cache kernel function calls",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=-1,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
count = int(args.count)
tstamp = args.timestamp
interval = int(args.interval)

#=================End cache stats ====>

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct key_t {
    u64 ip;
};

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();

	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;

	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %x %d\\n", req->__data_len,
		    req->cmd_flags, delta / 1000);
		start.delete(&req);
	}
}

BPF_HASH(counts, struct key_t);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 ip;

    key.ip = PT_REGS_IP(ctx);
    counts.increment(key); // update counter
    return 0;
}
""")

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
#b = BPF(text=bpf_text)
b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")
b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")
b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")
b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")

# header
if tstamp:
    print("%-8s " % "TIME", end="")
# print("" %
#      ("BUFFERS_MB", "CACHED_MB"))

loop = 0
exiting = 0

#======end cache stats====>


if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")

# header
print("%-18s %-2s %-7s %8s %10s" % ("TIME(s)", "bi", "bo", "BUFFERS_MB", "CACHED_MB"))

# format output
nb_write = nb_read = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()
        if int(bflags_s, 16) & REQ_WRITE:
            nb_write += 1
        elif bytes_s == "0":
            type_s = b"M"
        else:
            nb_read += 1
        ms = float(int(us_s)) / 1000
        # printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, nb_write, nb_read))
    except KeyboardInterrupt:
        exit()

    mem = get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    if tstamp:
        print("%-8s " % strftime("%H:%M:%S"), end="")
    # print(" %8.0f %10.0f" %
    #     ( buff, cached))
    print("%-18.9f %-2s %-7s %8.2f %10.0f" % (ts, nb_write, nb_read, buff, cached))

   # mpa = mbd = apcl = apd = total = misses = hits = cached = buff = 0

    if exiting:
        print("Detaching...")
        exit()

