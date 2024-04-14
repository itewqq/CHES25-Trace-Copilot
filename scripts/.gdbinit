target extended-remote localhost:3333

# load symbol file
# file ../binaries/nrf52840_xxaa_4algo_O3.out

# file ../binaries/cbmxecdsa.axf

# reset the target
monitor reset halt
layout asm
focus cmd

# file /home/itemqq/SDKs/nRF52/nRF5_SDK_17.1.0_ddde560/examples/crypto/nrf_crypto/test_app/pca10056/armgcc/_build/nrf52840_xxaa.out

# b main
# b uart_recv

# source ../src/get_pc_trace.py

b *0x08003c70
# b *0x2662
# b *0xb738 if $my_bp_func()

# x/8wx 0x20008ce0

# ########### python script
# python

# import gdb

# class StepBeforeNextCall (gdb.Command):
#     def __init__ (self):
#         super (StepBeforeNextCall, self).__init__ ("sbnc",
#                                                    gdb.COMMAND_OBSCURE)

#     def invoke (self, arg, from_tty):
#         arch = gdb.selected_frame().architecture()

#         while True:
#             current_pc = addr2num(gdb.selected_frame().read_register("pc"))
#             disa = arch.disassemble(current_pc)[0]
#             if disa["asm"].startswith('bl'): # or startswith ?
#                 break

#             SILENT=True
#             gdb.execute("stepi", to_string=SILENT)

#         print("step-before-next-call: next instruction is a call.")
#         print("{}: {}".format(hex(int(disa["addr"])), disa["asm"]))

# def addr2num(addr):
#     try:
#         return int(addr)  # Python 3
#     except:
#         return long(addr) # Python 2

# StepBeforeNextCall()

# def callstack_depth():
#     depth = 1
#     frame = gdb.newest_frame()
#     while frame is not None:
#         frame = frame.older()
#         depth += 1
#     return depth

# class StepToNextCall (gdb.Command):
#     def __init__ (self):
#         super (StepToNextCall, self).__init__ ("stnc", 
#                                                gdb.COMMAND_OBSCURE)

#     def invoke (self, arg, from_tty):
#         start_depth = current_depth =callstack_depth()

#         # step until we're one step deeper
#         while current_depth == start_depth:
#             SILENT=True
#             gdb.execute("step", to_string=SILENT)
#             current_depth = callstack_depth()

#         # display information about the new frame
#         gdb.execute("frame 0")

# StepToNextCall() 

# end