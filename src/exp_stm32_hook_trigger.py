import random
import argparse
import os
import subprocess
import json
import logging
import pprint


from find_loops import *
from pifer import *


def int_or_int_list(string):
    if ',' in string:
        return [int(x, 16) for x in string.split(',')]
    else:
        return [int(string, 16)]

if __name__ == "__main__":
    '''
        modling firmware:
            python exp_stm32_hook_trigger.py ../binaries/GPIO_IOToggle.bin  --log-level=DEBUG --target-func 0x080012bc 
        target firmware: 
            SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256
            ground truth trigger:
                    TRACE("\r\n\t  FW Decryption start.");
                    // PIN D1 up
                    asm volatile (
                        "push {r0-r1}\n\t"
                        "ldr r0, =0x40021400\n\t"
                        "mov r1, #0x80\n\t"
                        "str r1, [r0, #0x18]\n\t"
                        "pop {r0-r1}\n\t"
                    );
                    // my code ends
                e_ret_status =  DecryptImageInDwlSlot(DwlSlot, pFwImageHeader);
                    // my code starts
                    // PIN D1 down
                    asm volatile (
                        "push {r0-r1}\n\t"
                        "ldr r0, =0x40021400\n\t"
                        "mov r1, #0x80\n\t"
                        "lsls  r1, r1, #0x10\n\t"
                        "str r1, [r0, #0x18]\n\t"
                        "pop {r0-r1}\n\t"
                    );
                    TRACE("\r\n\t  FW Decryption end.");
                    // my code ends

        0x08003e22 Binary_DoublePointMul
        Inject code:
        PINA: D0
            # up:
            ldr r0, =0x40021400
            mov r1, 0x40
            str r1,[r0,#0x18]
            # down
            ldr r0, =0x40021400
            mov r1, 0x40
            lsls r1,r1,#0x10
            str r1,[r0,#0x18]

        PINB: D1
            # up
            ldr r0, =0x40021400
            mov r1, 0x80
            str r1,[r0,#0x18]
            # down
            ldr r0, =0x40021400
            mov r1, 0x80
            lsls r1,r1,#0x10
            str r1,[r0,#0x18]
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('bin_path', help='path of the binary firmware to process')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='set the logging level')
    parser.add_argument('--patch-only', nargs='?', default=argparse.SUPPRESS, help='only do the patch from existing cfg.json')
    parser.add_argument('--target-func', type=int_or_int_list, help='function address(hex int) to focus on')

    args = parser.parse_args()

    # setup the logger
    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)

    # target info
    bin_path = os.path.abspath(args.bin_path)
    logging.info(bin_path)

    with open('target_funcs.py', "w") as f:
        if args.target_func is None:
            f.write("target_functions=None")
        else:
            f.write(f"target_functions={args.target_func}")

    

    # binary analysis
    ## automatically extract all loops 
    if 'patch_only' not in dir(args):
        ## extract the cfg with ghidra script
        ghidra_script = 'cortex-m_headless.py'
        cmd = f'/opt/ghidra/support/analyzeHeadless . test_project -deleteProject -import {bin_path} -postScript {ghidra_script} -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr 08000000'
        output_bytes = subprocess.check_output(cmd, shell=True)
        # print(output_bytes.decode('utf-8'))

    ## find all loops automatically
    with open(f"{bin_path}.cfg.json", "r") as f:
        import json
        function_list = json.loads(f.read())

    funcs_loops = {}
    loop_ends = []

    # ## filter only the focusing functions
    # if args.target_func is not None:
    #     function_list = [func for func in function_list if func['address'] in args.target_func]

    # find loops for each function
    for function in function_list:
        # filter the abnormal functions
        if len(function["blocks"]) == 0:
            continue
        funcs_loops[function["address"]] = find_function_loops(function["address"], function["blocks"])
        for loop in funcs_loops[function["address"]]:
            loop_ends.append(int(loop['end'], 16))

    logging.info("Total loops in the binary: {}".format(sum([len(v) for _,v in funcs_loops.items()])))

    if log_level == logging.DEBUG:
        for func,loops in funcs_loops.items():
            if len(loops) != 0:
                logging.debug(f"In function {hex(func)}\n"+pprint.pformat(loops))

    # instrumentation
    ## binary configuration
    img_base = 0x08000000
    mcpu = "cortex-m4"
    compile_options = ""
    p = PIFER(bin_path=bin_path, img_base_va=img_base, arch=mcpu, compile_options=compile_options)

    # sort the addresses for binary search
    target_addrs = sorted(list(set(loop_ends)))
    # target_addrs = [0x8000eae]

    if log_level ==  logging.DEBUG:
        # for debug
        offset = 0
        hook_num = 1 # len(target_addrs)
        target_list = target_addrs[offset:offset+hook_num]
        # target_list = [0x4158] # aes round loop end, this is for debug only
    else:
        target_list = target_addrs


    for addr in target_list:
        p.add_addr(addr)
    
    # init the GPIO trigger
    reset_hook = '''
    '''

    # hook the reset handler
    p.add_reset_hook(reset_hook)

    # PINA: 508/50C, 0x40000000
    # PINB: 508/50C, 0x80000000
#     trigger_up = '''
#     nop
# '''
    trigger_up = '''
    ldr r0, =0x40021400
    mov r1, #0x40
    str r1,[r0,#0x18]
'''

#     trigger_down = '''
#     nop
# '''

    trigger_down = '''
    ldr r0, =0x40021400
    mov r1, #0x40
    lsls r1,r1,#0x10
    str r1,[r0,#0x18]
'''

    ## inject the triggers
    p.add_pre_code(trigger_up)
    p.add_post_code(trigger_down)

    p.patch()

    print(f"Hooks: {len(target_list)}/{len(target_addrs)}")