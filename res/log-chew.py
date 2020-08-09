#!/usr/bin/env python

# gdb$ rwatch *0x400258
# gdb$ g AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD
# gdb$ bc
# gdb$ bp *$pc
# gdb$ bp commands
# >x/xb op_ptr
# >print/x stack_elt
# >x/6gx &stack[stack_elt-6]
# >continue
# >end
# gdb$ continue

import json
from pprint import pprint

with open('log.txt', 'r') as h:
    data = h.read()

# Breakpoint 2, execute_stack_op (op_ptr=0x40025d "\b\b\"\006\022\006\026\b\b\"\022\006\026\b\b\"\022\006\026\b\b\"\022\006\026\b\b\"\224\001(D", op_end=0x403216 "", context=context@entry=0x7fffffe110, initial=initial@entry=0x7ffffff400) at ../../../src/libgcc/unwind-dw2.c:536
# 536     in ../../../src/libgcc/unwind-dw2.c
# 0x40025d:       0x08
# $3 = 0x2
# 0x7fffffde90:   0x0000007ffffff400      0x0000007ffffff488
# 0x7fffffdea0:   0x00000000000000a8      0x0000000000000001
# 0x7fffffdeb0:   0x0000000000000000

res = []

state = -1
rec = {}

for line in data.split('\n'):
    # scan to the first bp hit
    if state == -1 and 'Breakpoint 2, execute_stack_op' not in line: continue

    #print(line)

    if 'Breakpoint 2' in line:
        rec = {}
        rec['stack'] = []
        state = 0
        continue

    # skip linenumber
    if state == 0:
        state += 1
        continue

    # get pc
    if state == 1:
        rec['pc'] = int(line.split(':')[0], 0) - 1
        state += 1
        continue

    # get stack size
    if state == 2:
        rec['stack_sz'] = int(line.split(' = ')[1], 0) - 1
        state += 1
        continue

    # get the first 4 stack elements
    if state in [3, 4, 5]:
        vals = line.split(':')[1].split('\t')
        rec['stack'].append(int(vals[1], 0))
        rec['stack'].append(int(vals[2], 0))

        state += 1
        continue

    # trim and commit
    if state == 6:
        # trim the stack if needed
        rec['stack'] = list(reversed(rec['stack']))
        if len(rec['stack']) > rec['stack_sz']:
            rec['stack'] = list(reversed(rec['stack'][:rec['stack_sz']]))
        else:
            rec['stack'] = list(reversed(rec['stack'][:5]))

        #pprint(rec)
        res.append(rec)
        continue

print('chewed up %d records' % len(res))

with open('states.json', 'w') as h:
    json.dump(res, h)
