import logging
import ghidra

# try to make the IDE and the ghidra interpreter happy at the same time
try:
    from ghidra.ghidra_builtins import *
except:
    pass
from __main__ import *

# from ghidra.ghidra_builtins import *

from ghidra.graph import GraphFactory
from ghidra.program.model.block import BasicBlockModel

from ghidra.program.model.address import *
from ghidra.program.model.data import Pointer32DataType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import Memory
from ghidra.program.model.address import AddressFactory
from ghidra.app.script import *
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.base.project import GhidraProject
from ghidra.program.model.data import *


def init_logger(log_level=logging.DEBUG):
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    rootLogger.setLevel(log_level)

    # fileHandler = logging.FileHandler("{0}/{1}.log".format(logPath, fileName))
    # fileHandler.setFormatter(logFormatter)
    # rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)


def dump_json_wrapper(obj, filepath):
    # python2 is stupid..
    import json
    # Make it work for Python 2+3 and with Unicode
    import io
    try:
        to_unicode = unicode
    except NameError:
        to_unicode = str
    with open(filepath, mode="w") as outfile:
        s = json.dumps(obj,
                       indent=4, sort_keys=True,
                       separators=(',', ': '), ensure_ascii=False)
        outfile.write(to_unicode(s))


def int2addr(addr):
    addr_hex_str = hex(addr)
    if addr_hex_str.endswith('L'):
        addr_hex_str = addr_hex_str[:-1]
    return currentProgram.getAddressFactory().getAddress(addr_hex_str)


def addr2int(addr):
    return addr.getOffset()


def get_all_functions():
    """ get all functions address"""
    functions = []
    logging.info("Get All Functions")
    function = getFirstFunction()
    # iterate through all functions
    while function is not None:
        functions.append(function)
        function = getFunctionAfter(function)
    return functions


def get_func_insts(function):
    insts = []
    cur = function.getEntryPoint()
    while cur:
        inst = getInstructionAt(cur)
        insts.append(inst)
        cur = cur.next()
    return insts


def get_bb_insts(block):
    rg = [block.getMinAddress(), block.getMaxAddress()]
    logging.debug("blk rgs: {}".format(rg))
    all_insts = []
    cur = rg[0]
    while cur <= rg[1]:
        inst = getInstructionAt(cur)
        all_insts.append(inst)
        cur = cur.add(inst.getLength())
    return all_insts

def bb_has_call(block):
    rg = [block.getMinAddress(), block.getMaxAddress()]
    logging.debug("blk rgs: {}".format(rg))
    cur = rg[0]
    while cur <= rg[1]:
        inst = getInstructionAt(cur)
        inst_asm = inst.toString()
        inst_parts = inst_asm.split()
        # branch to label or register
        if inst_parts[0] == "blx":
            return True
        elif inst_parts[0] == "bl":
            return True
        cur = cur.add(inst.getLength())
    return False

def get_block_last_inst_addr(block):
    # stupid but it works
    return currentProgram.getListing().getCodeUnitContaining(block.getMaxAddress()).getAddress().getOffset()

