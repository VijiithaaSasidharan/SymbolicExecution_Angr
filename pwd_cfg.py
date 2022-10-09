import angr
from angrutils import *

# load your project
p = angr.Project("./pwd_null", load_options={"auto_load_libs": False})
simgr = p.factory.simgr()

# Generate a static CFG
cfg = p.analyses.CFGFast()
print("This is the graph:", cfg.graph)
print("It has %d nodes and %d edges" %
      (len(cfg.graph.nodes()), len(cfg.graph.edges())))
entry_node = cfg.get_any_node(p.entry)
print("There were %d contexts for the entry block" %
      len(cfg.get_all_nodes(p.entry)))
print("Predecessors of the entry point:", entry_node.predecessors)
print("Successors of the entry point:", entry_node.successors)
print(
    "Successors (and type of jump) of the entry point:",
    [
        jumpkind + " to " + str(node.addr)
        for node, jumpkind in cfg.get_successors_and_jumpkind(entry_node)
    ],
)
entry_func = cfg.kb.functions
for x in entry_func.function_addrs_set:
    if cfg.kb.functions[x].name == "main":
        add = cfg.kb.functions[x]
        print(x, cfg.kb.functions[x].name)
plot_func_graph(
    p,
    add.transition_graph,
    "%s_%s_cfg" % ("pwd", add.name),
    # asminst=True,
    # vexinst=False,
)
