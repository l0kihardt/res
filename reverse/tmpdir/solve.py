import angr
import claripy
import logging

logging.getLogger("angr.factory").setLevel(logging.DEBUG)
logging.getLogger("angr.manager").setLevel(logging.DEBUG)
logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

p = angr.Project('./a.out', load_options= {"auto_load_libs": False})

flag = claripy.BVS("f", 8 * 16)
state = p.factory.entry_state(addr = 0x4005af)
state.memory.store(state.regs.rsp, flag)
state.regs.rax = 16
e = p.factory.simulation_manager(state)
e.explore(find = 0x400636, avoid = 0x40064b)
assert len(e.found) == 1
np = e.found[0]

