import logging

from my_ghidra_utils import *

def is_black_list_func(function):
    # extract the prior handlers in the binary
    memory = currentProgram.getMemory()
    # img_base = currentProgram.imageBase.getOffset()
    img_base = currentAddress.getOffset() # ghidra is stupid
    logging.debug("img_base {}".format(img_base))
    priority_handlers = []
    for offset in range(0x4, 0x18, 0x4):
        priority_handlers.append(
            memory.getInt(int2addr(img_base + offset)) - 1
        )

    logging.debug("Priority handlers: {}".format([hex(x) for x in priority_handlers]))
    # check if this function has instruction of prior handlers
    addrSet = function.getBody()
    # logging.debug("addrSet: {} for function {}".format(addrSet, function.getEntryPoint()))
    for addr_range in addrSet:
        for ban_addr in priority_handlers:
            if addr_range.contains(int2addr(ban_addr)):
                return True
    return False

def function_control_flow_graph(function):
    '''
    Creates a control flow graph for the input function
    :param function: target function
    :return: 'blocks':[
                        {'start_addr':xxxx,
                        'end_addr':xxxx,
                        'in_edges': [startEA1 , startEA2 .. ],
                        'out_edges': [startEA1 , startEA2 .. ]
                        },
                        ..other blocks
                     ]
    '''
    # if the code cannot be preempted by PIFER (reset, nmi), we ignore them
    func_start_va = function.getEntryPoint().getOffset()
    if is_black_list_func(function):
        logging.debug("Un-preemptable function found: {}".format(hex(func_start_va)))
        return []

    blocks = []
    block_model_iterator = ghidra.program.model.block.BasicBlockModel(currentProgram)
    function_addresses = function.getBody()
    code_blocks_iterator = block_model_iterator.getCodeBlocksContaining(function_addresses, monitor)

    # go through each block and populate the addresses, sources and destinations
    while code_blocks_iterator.hasNext():
        new_block = dict()
        block = code_blocks_iterator.next()

        # # debug output
        # logging.info("Block at {}, type: {}, isTerminal: {}".format(
        #     hex(block.getFirstStartAddress().getOffset()),
        #     block.getFlowType(),
        #     block.getFlowType().isTerminal()
        # ))

        # FIXME: block might have multiple start addresses, we ignore that here
        new_block['start_addr'] = block.getFirstStartAddress().getOffset()
        # # wrong way to get address of the last instruction in a basic block
        # new_block['end_addr'] = block.getMaxAddress().getOffset()
        # correct way:
        new_block['end_addr'] = currentProgram.getListing().getCodeUnitContaining(block.getMaxAddress()).getAddress().getOffset()

        # # get the instruction count
        # new_block['inst_len'] = len(get_bb_insts(block))
        # # does the block has call instruction?
        # new_block['has_call'] = bb_has_call(block)

        rg = [block.getMinAddress(), block.getMaxAddress()]
        logging.debug("blk rgs: {}".format(rg))
        all_insts = []
        has_call = False
        cur = rg[0]
        while cur <= rg[1]:
            inst = getInstructionAt(cur)
            inst_asm = inst.toString()
            inst_parts = inst_asm.split()
            # branch to label or register
            if inst_parts[0] == "blx":
                has_call = True
            elif inst_parts[0] == "bl":
                has_call = True
            all_insts.append(inst)
            cur = cur.add(inst.getLength())
        new_block['inst_len'] = len(all_insts)
        new_block['has_call'] = has_call

        logging.debug("{} has call? {}".format(block.getFirstStartAddress(), new_block['has_call']))


        new_block['in_edges'] = []
        source_iterator = block.getSources(monitor)

        # collect all sources
        while source_iterator.hasNext():
            source = source_iterator.next()
            # debug
            logging.debug("IN: Block at {}, to {}, type: {}, isUnCond: {}".format(
                hex(block.getFirstStartAddress().getOffset()),
                hex(source.getSourceAddress().getOffset()),
                source.getFlowType(),
                source.getFlowType().isUnConditional()
            ))

            # check whether the source is in the same function
            src_addr = source.getSourceAddress()
            src_func = getFunctionContaining(src_addr)

            if src_addr.getOffset() == new_block['start_addr'] and source.getFlowType().isUnConditional():
                # inf loop
                continue
            elif src_func is None:
                continue
            elif src_func != function:
                # FIXME we ignore calls from other functions
                continue
            elif source.getFlowType().isCall():
                continue
            else:
                # same function
                new_block['in_edges'].append([src_addr.getOffset(), str(source.getFlowType())])

        new_block['out_edges'] = []
        dest_iterator = block.getDestinations(monitor)

        # collect all destinations
        while dest_iterator.hasNext():
            dest = dest_iterator.next()
            # debug
            logging.debug("OUT: Block at {}, to {}, type: {}, isUnCond: {}".format(
                hex(block.getFirstStartAddress().getOffset()),
                hex(dest.getDestinationAddress().getOffset()),
                dest.getFlowType(),
                dest.getFlowType().isUnConditional()
            ))
            # check whether the destination is in the same function
            dest_addr = dest.getDestinationAddress()
            dest_func = getFunctionContaining(dest_addr)

            if dest_addr.getOffset() == new_block['start_addr'] and dest.getFlowType().isUnConditional():
                # inf loop
                continue
            elif dest_func is None:
                continue
            elif dest.getFlowType().isCall():
                continue
            elif dest_func != function:
                # FIXME we ignore call other functions
                continue
            else:
                # same function
                new_block['out_edges'].append([dest_addr.getOffset(), str(dest.getFlowType())])

        blocks.append(new_block)

    return blocks


def parse_all_functions(target_functions = None):
    """ get all functions address"""
    functions = []

    if target_functions is None:
        # iterate through all functions
        logging.info("Get All Functions")
        function = getFirstFunction()
        while function is not None:
            logging.debug("{} found at {}".format(function.getName(), function.getEntryPoint()))
            function_dict = {'name': function.getName(), 'address': function.getEntryPoint().getOffset(),
                             'blocks': function_control_flow_graph(function)}
            functions.append(function_dict)
            function = getFunctionAfter(function)
    else:
        # only the target functions
        logging.info("Get target Functions")
        for func_addr in target_functions:
            # function = getFunctionAt(int2addr(func_addr))
            logging.debug("Get function at {}".format(func_addr))
            function = getFunctionContaining(int2addr(func_addr))
            if function is None:
                # force make a function here
                function = createFunction(int2addr(func_addr), "custom_func_{}".format(hex(func_addr)))
            logging.debug("{} found at {}".format(function.getName(), function.getEntryPoint()))
            function_dict = {'name': function.getName(), 'address': function.getEntryPoint().getOffset(),
                             'blocks': function_control_flow_graph(function)}
            functions.append(function_dict)

    return functions


def populate_functions():
    """ populates the functions attribute of the class """
    functions = []
    logging.info("Populating Functions")
    function = getFirstFunction()
    # iterate through all functions
    while function is not None:
        logging.debug("{} found at {}".format(function.getName(), function.getEntryPoint()))
        function_dict = {'address': function.getEntryPoint(), 'blocks': function_control_flow_graph(function)}
        functions.append(function_dict)
        function = getFunctionAfter(function)
    return functions


def print_func_cfg(addr, blocks):
    logging.debug("Function address {}".format(addr))
    for b in blocks:
        logging.debug("----> Block address: start: {} end: {}".format(hex(b['start_addr']), hex(b['end_addr'])))
        for s in b['in_edges']:
            logging.debug("---------> Source of this block: {}".format(hex(s[0])))
        for d in b['out_edges']:
            logging.debug("---------> Destination of this block: {}".format(hex(d[0])))


def print_cfg(functions):
    logging.debug('Printing CFG')
    for f in functions:
        logging.debug("Function address {}".format(f['address']))
        for b in f['blocks']:
            logging.debug("----> Block address: start: {} end: {}".format(hex(b['start_addr']), hex(b['end_addr'])))
            for s in b['in_edges']:
                logging.debug("---------> Source of this block: {}".format(hex(s[0])))
            for d in b['out_edges']:
                logging.debug("---------> Destination of this block: {}".format(hex(d[0])))


def dump_func_cfg(fcfg, func_addr, data_path="/home/itemqq/fault/trace_copilot/binaries/"):
    # import pickle
    # filepath = data_path + "func_" + func_addr + "_cfg.pickle"
    # with open(filepath, mode="wb") as fileObj:
    #     pickle.dump(fcfg, fileObj, protocol=2)

    filepath = data_path + "func_" + func_addr + "_cfg.json"
    dump_json_wrapper(fcfg, filepath)
    return filepath


if __name__ == "__main__":
    init_logger()
    # start_ea = 0x0294
    start_ea = 0x0b60

    addr = currentProgram.getAddressFactory().getAddress(hex(start_ea))
    print(addr)
    func = getFunctionContaining(addr)

    print(func)

    fcfg = function_control_flow_graph(func)

    # print("fcfg: ", fcfg)

    print_func_cfg(start_ea, fcfg)

    # dump_func_cfg(fcfg, hex(start_ea))
