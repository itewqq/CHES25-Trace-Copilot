import random

from pifer import *

# loop_start_addrs =[
#     0x7572
# ]

loop_start_addrs_4algo_O3 = [

0x460a,
0xbe18,
0xaa1a,
0xb21c,
0x4a1e,
0x9c1e,
0xba20,
0xb822,
0xb424,
0xc036,
0x10c42,
0x6a44,
0x9c48,
0xa64c,
0x524e,
0xbe52,
0xe856,
0xa65a,
0x8e5a,
0x6e5c,
0x5066,
0x7266,
0xe868,
0xa46c,
0x7a6e,
0xa86e,
0x9c70,
0xaa70,
0xbe78,
0xac7a,
0xae82,
0xba88,
0x608a,
0x9292,
0x729a,
0x5e9a,
0xba9a,
0x11ca4,
0xbca8,
0xb4a8,
0x5aaa,
0x8cac,
0x62b0,
0x50b4,
0xc6ba,
0x112ba,
0xacbc,
0x88bc,
0x5ebe,
0xc6c2,
0xb8c6,
0xa8ce,
0xaace,
0x64d0,
0xfad6,
0xc6e4,
0x3eea,
0x4cf0,
0x64f8,
0xaefa,
0x74fe,
0xa500,
0x4902,
0xef04,
0x7508,
0x890c,
0x8f0c,
0x3b10,
0x7514,
0x8f14,
0xa918,
0x5526,
0xa526,
0xad26,
0xe126,
0x7128,
0xbf2a,
0xc32e,
0xe336,
0x7538,
0x10b3c,
0xf140,
0x7542,
0x5148,
0xb748,
0x754e,
0xa34e,
0xed4e,
0xdf52,
0xb754,
0x10754,
0xab5a,
0x6f64,
0xa968,
0x7b6a,
0x896e,
0xb372,
0xc37c,
0xbd7e,
0xab82,
0x9988,
0x6988,
0x11188,
0x518e,
0xbb98,
0xff98,
0x7b9a,
0xa59c,
0xe5a8,
0xa5aa,
0xb5aa,
0x37ae,
0xa9b2,
0x5fbc,
0xb3bc,
0xbdc4,
0xbfca,
0x51ce,
0x63d2,
0xc3d4,
0x7bd6,
0xf1d8,
0x6fda,
0x9ddc,
0xb7dc,
0x9fde,
0xabe0,
0xb1e0,
0xa9e6,
0x67e8,
0x85e8,
0x51f0,
0xb3f0,
0x41f6,
0xaff6,
0x79fc,
0x11dfc,
0x63fe,

]

if __name__ == "__main__":
    bin_path = "/home/itemqq/fault/trace_copilot/binaries/nrf52840_xxaa_4algo_O3.bin"

    # bin_path = "/home/itemqq/fault/trace_copilot/binaries/nrf52840_xxaa.pintest.bin"

    img_base = 0
    mcpu = "cortex-m4"
    compile_options = ""
    p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu, compile_options=compile_options)

#     nop_payload = '''MOV   R1, #0x50000000
#     MOV R0, #3
#     STR   R0, [R1,#0x768]
#     MOV.W   R0, #0x4000000
#     STR.W   R0, [R1,#0x508]
#     STR.W   R0, [R1,#0x50C]
# '''
#     # ~3.5us delay, 224 cycles
#     nop_payload = '''MOV   R1, #0x50000000
#     MOV R0, #3
#     STR   R0, [R1,#0x768]
#     NOP
#     NOP
#     NOP
#     NOP
#     NOP
#     NOP
#     NOP
#     NOP
# '''

#     # still ~3.5us, so this will not affect the perfomance too much
#     nop_payload = '''
#     NOP
# '''


    target_addrs = sorted(list(set(loop_start_addrs_4algo_O3)))
    total_num = len(target_addrs)

    # for debug
    offset = 0
    hook_num = len(target_addrs)
    target_list = target_addrs[offset:offset+hook_num] # + [0x7572]
    # target_list = target_addrs[:hook_num]
    # target_list = random.sample(target_addrs, total_num)
    target_list = [0x42F6] # aes loop addr, just for debugging

    for addr in target_list:
        p.add_addr(addr)
    
    trigger_up = '''
'''
    
    trigger_down = '''
    // save the cpu context
    PUSH {R4-R11, LR}
    MRS R1, APSR
    PUSH {R1}

    // prepare the prameters
    // R0 still points to oroginal PC
    MOV R2, R0 // the oroginal address
    LDR R1, =0x001C // format string address
    LDR R0, =0x10003 // needed by nrf_log
    // call the logger function
    LDR R3, =0x2CF5 // printer function address, change this manually
    BLX R3

    // restore the cpu context
    POP {R1}
    MSR APSR_nzcvq, R1	
    POP {R4-R11, LR}
'''

    # inject the triggers
    p.add_pre_code(trigger_up)
    p.add_post_code(trigger_down)

    p.patch()

    print(f"Hooks: {len(target_list)}/{len(target_addrs)}")