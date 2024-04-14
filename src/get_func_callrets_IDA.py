from pprint import pprint

from idc import *
from idaapi import *
from idautils import *


calls = []
rets = []
# for funcea in idautils.Functions():
    # if funcea > 0x80000:
        # break

# Get the list of all functions
functions = Functions()

# Loop through each function
for funcea in functions: 
    for (starea, endea) in Chunks(funcea):
        for head in Heads(starea, endea):
            inst_asm = GetDisasm(head)
            inst_len = get_item_size(head)
            inst_parts = inst_asm.split()
            # caller
            if inst_parts[0] == "BLX": 
                callees = None # dynamic call
                calls.append({
                    "addr": head,
                    "caller": funcea,
                    "callees": callees,
                })
            elif inst_parts[0] == "BL":
                callees = list(CodeRefsFrom(head, 0))
                calls.append({
                    "addr": head,
                    "caller": funcea,
                    "callees": callees,
                })
            elif inst_parts == ['BX', 'LR']: # BX LR
                rets.append({
                    "addr": head
                })
            elif inst_parts[0].startswith('POP') and "PC" in inst_parts[1]:
                rets.append({
                    "addr": head
                })

pprint(len(calls))
pprint(len(rets))

# pprint(calls)
# pprint(rets)