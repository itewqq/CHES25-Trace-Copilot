import graph_tool.all as gt

# filter the small loops
SMALL_LOOP_THRESHOLD = 9

entry_times= []
exit_times = []

def debug_draw(g, block_startea, root=None):
    vertex_size = g.new_vertex_property("float")
    vertex_size.set_value(15)
    # pos = gt.fruchterman_reingold_layout(g, r=100, circular=True, n_iter=1000)
    # pos = gt.radial_tree_layout(g, root)
    pos = gt.arf_layout(g)
    gt.graph_draw(g, pos=pos, vertex_text=block_startea, vertex_size=vertex_size, output_size=(1920, 1080), output="tmp.png")

def is_cond_edge(etype):
    # FIXME is all FALL_THROUGH cond branch?
    return etype == "CONDITIONAL_JUMP" or etype == "FALL_THROUGH_ELSE"

def domset_from_idom(idom, root=0):
    domset = []
    # print("[d] idom is", idom)
    for i in range(len(idom)):
        s = set([i]) # itself
        cur = idom[i]
        s.add(cur)
        while cur != root:
            cur = idom[cur]
            s.add(cur)
        domset.append(s)
    return domset

def find_all_backedges(g, domset):
    backedges = []
    # iter_edges: return list, faster method
    for e in g.iter_edges():
        if e[1] in domset[e[0]]:
            backedges.append(e)
    return backedges

def construct_natural_loop(g, e, edge_type):
    '''
        find natural loop and nearest Bcond instruction for a backedge e
    '''
    eid = g.edge(e[0], e[1])
    bcond_blk = None
    if e[0] != e[1]:
        # check e[0]
        if is_cond_edge(edge_type[eid]):
            bcond_blk = e[0]
        # check e[1] because init vis = {e[0], e[1]}
        # so we need to check if there is an edge: e[1]->e[0]
        eid = g.edge(e[1], e[0])
        if eid is not None and is_cond_edge(edge_type[eid]):
            bcond_blk = e[1]
        vis = set(e)
        stack = [e[0]] # n
        while len(stack) != 0:
            u = stack.pop()
            for v in g.iter_in_neighbors(u):
                if v not in vis:
                    vis.add(v)
                    stack.append(v)
                    # check if the edge v->u is Bcond
                    eid = g.edge(v, u)
                    # print(f"[d] eid for u={u}, v={v} is {eid}")
                    # FIXME: Multiple Bcond?
                    if bcond_blk is None and is_cond_edge(edge_type[eid]):
                        bcond_blk = v
    else:
        # print(f"[d] Self loop!")
        bcond_blk = e[0]
        vis = set(e[:1])
        # must be conditional branch
        assert is_cond_edge(edge_type[eid]), f"{bcond_blk}, {eid}, {edge_type[eid]}"
    
    return vis, bcond_blk

def find_natural_loops(g, idom, block_startea, block_endea, edge_type, root=0):
    domset = domset_from_idom(idom, root=root)
    backedges = find_all_backedges(g, domset)

    # print("backedges: ", [(block_startea[e[0]], block_startea[e[1]]) for e in backedges])

    loops = []
    for e in backedges:
        # print(f"[d] {(block_startea[e[0]], block_startea[e[1]])} {e}")
        loop_set, bcond_blk = construct_natural_loop(g, e, edge_type)
        # print(f"[d] {bcond_blk}")
        # print(f"[d] {edge_type[g.edge(e[0], e[1])]} {type(bcond_blk)}, {block_startea[bcond_blk]}")
        if bcond_blk == None:
            # print(f"[d] {(block_startea[e[0]], block_startea[e[1]])} {e}")
            # FIXME: not found any bcond block
            continue
        loops.append({"start": block_startea[e[1]], "end": block_endea[bcond_blk], "blocks": [block_startea[x] for x in loop_set]}) # start, end, blocks

        # print(f"For backedge {(block_startea[e[0]], block_startea[e[1]])}, the loop body is")
        # print(f"\t{[block_startea[u] for u in loop_set]}")

    return loops

def find_function_loops(func_start_ea, fcfg):
    # print(f"[d] Processing function {hex(func_start_ea)}")
    g = gt.Graph()
    block_startea = g.new_vertex_property("string")
    block_endea = g.new_vertex_property("string")
    edge_type = g.new_edge_property("string")
    v_map = {}
    inst_len_map = {}
    has_call_map = {}
    # we have to make sure the start block is the first one
    # this is graph-tools' bug
    root_block_idx = 0
    for idx,block in enumerate(fcfg):
        if block['start_addr'] == func_start_ea:
            root_block_idx = idx
            break
    root_block = fcfg.pop(root_block_idx)
    fcfg = [root_block] + fcfg
    # then the function start must be the root
    for block in fcfg:
        v = g.add_vertex()
        label = block['start_addr'] # address
        block_startea[v] = hex(label)
        block_endea[v] = hex(block['end_addr'])
        # block_startea[v] = label
        # print(f"[d] {hex(label)} block' node id is: {v}")
        v_map[label] = v
        inst_len_map[label] = block['inst_len']
        has_call_map[label] = block['has_call']
    for block in fcfg:
        cb = block['start_addr']
        for nb in block['out_edges']:
            e = g.add_edge(v_map[cb], v_map[nb[0]])
            edge_type[e] = nb[1]
            if nb[1] == "FALL_THROUGH" and len(block['out_edges']) > 1:
                edge_type[e] = "FALL_THROUGH_ELSE"

    root = v_map[func_start_ea]
    dom = gt.dominator_tree(g, root)
    idom = dom.a # It contains for each vertex, the index of its dominator vertex
    # print(f"idom of {root}: {idom}")
    natural_loops = find_natural_loops(g, idom, block_startea, block_endea, edge_type)

    # filter 1: the small loops
    result = []
    for loop in natural_loops:
        loop_inst_len = 0
        has_call = False
        for block_start in loop['blocks']:
            ea = int(block_start, 16)
            loop_inst_len += inst_len_map[ea]
            if has_call_map[ea]:
                has_call = True
        # filter #1: small loops and no sub call
        # FIXME: bottom up filter. example: memcpy
        if loop_inst_len <= SMALL_LOOP_THRESHOLD and not has_call:
            continue
        # # filter #2: has function call
        # if has_call:
        #     continue

        result.append(loop)

    return result


def create_DJ_graph(g, idom, root=0):
    '''
        DFS to create the DJ-graph and get the ancestor relationship by
         entry/exit timing
    '''
    global entry_times, exit_times

    

def find_loops_DJ(g, idom, root=0):
    '''
        Identify loops using DJ-graph. 
        See Sreedhar et al, "Identifying Loops Using DJ Graphs".
    '''
    global entry_times, exit_times
    entry_times = [-1 for _ in range(len(idom))]
    exit_times = [-1 for _ in range(len(idom))]

    raise NotImplementedError


if __name__ == "__main__":
    with open("../binaries/nrf52840_xxaa.bin.cfg.json", "r") as f:
        import json
        function_list = json.loads(f.read())
    
    funcs_loops = {}
    for function in function_list:
        # filter the abnormal functions
        if len(function["blocks"]) != 0:
            funcs_loops[function["address"]] = find_function_loops(function["address"], function["blocks"])

    print("Total loops in the binary: ", sum([len(v) for _,v in funcs_loops.items()]))

    from pprint import pprint
    for func,loops in funcs_loops.items():
        if len(loops) != 0:
            print(f"In function {hex(func)}")
            pprint(loops)

    # with open("../binaries/func_0xaa1c_cfg.json", "r") as f:
    #     import json
    #     fcfg = json.loads(f.read())
    
    # func_start_ea = 0xAA1C
    # g = gt.Graph()
    # block_startea = g.new_vertex_property("string")
    # v_map = {}
    # for block in fcfg:
    #     v = g.add_vertex()
    #     label = block['start_addr'] # address
    #     block_startea[v] = hex(label)
    #     v_map[label] = v
    # for block in fcfg:
    #     cb = block['start_addr']
    #     for nb in block['out_edges']:
    #         # print(f"{hex(cb)}->{hex(nb)}")
    #         g.add_edge(v_map[cb], v_map[nb])

    # # pos = gt.radial_tree_layout(g, v_map[func_start_ea])
    # # pos = gt.arf_layout(g)
    # # gt.graph_draw(g, pos=pos, vertex_text=block_startea, output_size=(1200, 800), output="tmp.png")

    # root = v_map[func_start_ea]

    # dom = gt.dominator_tree(g, root)
    # idom = dom.a # It contains for each vertex, the index of its dominator vertex
    
    # natural_loops = find_natural_loops(g, idom)
    # print(f"Found {len(natural_loops)} natural loops!")

    # build the dom tree graph
    # dom_v_map = {}
    # dom_tree = gt.Graph()
    # dom_tree.add_edge_list([(idom[i], i) for i in range(1, len(idom))])
    # block_dom_startea = dom_tree.new_vertex_property("string")
    # # add the block_startea
    # for i in range(len(idom)):
    #     block_dom_startea[dom_tree.vertex(i)] = block_startea[g.vertex(i)]
    #     dom_v_map[block_startea[g.vertex(i)]] = dom_tree.vertex(i)

    # debug_draw(dom_tree, block_dom_startea, dom_tree.vertex(0))
    
    