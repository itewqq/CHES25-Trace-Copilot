from find_loops import *

if __name__ == "__main__":
    with open("../binaries/nrf52840_xxaa_4algo_O3.bin.cfg.json", "r") as f:
        import json
        function_list = json.loads(f.read())
    
    funcs_loops = {}
    loop_ends = []
    for function in function_list:
        # filter the abnormal functions
        if len(function["blocks"]) != 0:
            funcs_loops[function["address"]] = find_function_loops(function["address"], function["blocks"])
            for loop in funcs_loops[function["address"]]:
                loop_ends.append(int(loop['end'], 16))

    from pprint import pprint
    for loop_end in loop_ends:
        print(hex(loop_end)+",")
    