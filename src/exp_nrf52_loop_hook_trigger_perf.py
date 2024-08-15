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
        python exp_nrf52_loop_hook_trigger_perf.py ../binaries/nrf52840_xxaa_all_mbedtls_functions.bin  --log
-level=DEBUG
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('bin_path', help='path of the binary firmware to process')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='set the logging level')
    parser.add_argument('--patch-only', nargs='?', default=argparse.SUPPRESS, help='only do the patch from existing cfg.json')
    parser.add_argument('--target-func', type=int_or_int_list, help='function address(hex int) to focus on')

    args = parser.parse_args()

    with open('target_funcs.py', "w") as f:
        if args.target_func is None:
            f.write("target_functions=None")
        else:
            f.write(f"target_functions={args.target_func}")

    # setup the logger
    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)

    # target info
    bin_path = os.path.abspath(args.bin_path)
    logging.info(bin_path)

    # binary analysis
    ## automatically extract all loops 
    if 'patch_only' not in dir(args):
        ## extract the cfg with ghidra script
        ghidra_script = 'cortex-m_headless.py'
        cmd = f'/opt/ghidra/support/analyzeHeadless . test_project -deleteProject -import {bin_path} -postScript {ghidra_script} -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr 0'
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
    img_base = 0
    mcpu = "cortex-m4"
    compile_options = ""
    p = PIFER(bin_path=bin_path, img_base_va=img_base, arch=mcpu, compile_options=compile_options)

    # sort the addresses for binary search
    target_addrs = sorted(list(set(loop_ends)))

    if log_level ==  logging.DEBUG:
        # for debug
        offset = 0
        hook_num =  len(target_addrs)
        target_list = target_addrs[offset:offset+hook_num]
        # target_list = [0x4158] # aes round loop end, this is for debug only
    else:
        target_list = target_addrs


    for addr in target_list:
        p.add_addr(addr)
    
    # init the GPIO trigger
    reset_hook = '''
    MOV R0, #3
    STR   R0, [R1,#0x768]
    '''

    # hook the reset handler
    p.add_reset_hook(reset_hook)

    # PINA: 508/50C, 0x40000000
    # PINB: 508/50C, 0x80000000
    trigger_up = '''
    MOV   R1, #0x50000000
    MOV.W   R0, #0x4000000
    STR.W   R0, [R1,#0x508]
'''

    trigger_down = '''
    MOV   R1, #0x50000000
    MOV.W   R0, #0x4000000
    STR.W   R0, [R1,#0x50C]
'''

    ## inject the triggers
    p.add_pre_code(trigger_up)
    p.add_post_code(trigger_down)

    p.patch()

    print(f"Hooks: {len(target_list)}/{len(target_addrs)}")