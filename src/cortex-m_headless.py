'''
# run
/opt/ghidra/support/analyzeHeadless . test_project -deleteProject -import ../binaries/nrf52840_xxaa.bin -postScript cortex-m_headless.py -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr 0
'''

import logging
import argparse

from get_func_cfg import *
from get_func_callrets import *

if __name__ == "__main__":
    init_logger(logging.INFO)
    # read target function
    from target_funcs import target_functions
    logging.info("target functions are {} (None means all)".format(target_functions))
    logging.debug("Base addr: {}".format(hex(currentAddress.getOffset())))

    # get cfg of all functions
    functions = parse_all_functions(target_functions)

    data_folder = "/home/itemqq/fault/trace_copilot/binaries/"

    filepath = data_folder + currentProgram.getName() + ".cfg.json"
    dump_json_wrapper(functions, filepath)
    logging.info("CFG saved in {}".format(filepath))

    filepath = data_folder + currentProgram.getName() + ".callsrets.json"
    calls, rets = get_func_callrets()
    dump_json_wrapper({"calls": calls, "rets": rets}, filepath)
    logging.info("Call&Rets saved in {}".format(filepath))

    # addr = currentProgram.getAddressFactory().getAddress(hex(start_ea))
    # func = getFunctionContaining(addr)
    #
    # print("[+] Find {} at {}".format(func, func.getName()))
    # fcfg = function_control_flow_graph(func)
    # print("[+] Got CFG")
    # # print_func_cfg(start_ea, fcfg)
    #
    # dump_path = dump_func_cfg(fcfg, hex(func.getEntryPoint().getOffsetAsBigInteger())[:-1])
    # print("[+] Dump CFG at {}".format(dump_path))

