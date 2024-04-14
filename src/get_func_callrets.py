from my_ghidra_utils import *

def get_func_callrets():
    # from binascii import hexlify
    functions = get_all_functions()

    calls = []
    rets = []
    listing = currentProgram.getListing()
    for function in functions:
        funcea = function.getEntryPoint().getOffset()
        addrSet = function.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True)  # true means 'forward'
        for codeUnit in codeUnits:
            # print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))
            head = codeUnit.getAddress().getOffset()
            inst_asm = codeUnit.toString()
            inst_parts = inst_asm.split()
            # caller
            if inst_parts[0] == "blx":
                callees = None  # dynamic call
                calls.append({
                    "addr": head,
                    "caller": funcea,
                    "callees": callees,
                })
            elif inst_parts[0] == "bl":
                # callees = list(CodeRefsFrom(head, 0))
                callees = [ref.getToAddress().getOffset() for ref in getReferencesFrom(codeUnit.getAddress())]
                calls.append({
                    "addr": head,
                    "caller": funcea,
                    "callees": callees,
                })
            elif inst_parts == ['bx', 'lr']:  # BX LR
                rets.append({
                    "addr": head
                })
            elif inst_parts[0].startswith('pop') and "pc" in inst_parts[1]:
                rets.append({
                    "addr": head
                })
    return calls, rets

if __name__ == "__main__":

    # start_ea = 0xaa1c
    # addr = currentProgram.getAddressFactory().getAddress(hex(start_ea))
    # functions = [getFunctionContaining(addr)]

    from binascii import hexlify

    calls, rets = get_func_callrets()

    print(calls)

    print(len(calls))
    print(len(rets))

    # for a in [ hex(y)[:-1] for y in sorted([x["addr"] for x in calls]) ]:
    #     print(a)