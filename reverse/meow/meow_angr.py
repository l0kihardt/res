import angr
import claripy
import re

proj = angr.Project('./meow')
state = proj.factory.entry_state(addr = 0x400d1d)
state.regs.rdi = 0x1000000
state.regs.rsi = 0x2000000
state.regs.rdx = 182

for i in range(182):
    v = claripy.BVS('x{}'.format(i), 8)
    state.memory.store(state.regs.rdi + i, v)

for i in range(10):
    v = claripy.BVS('k{}'.format(i), 8)
    state.memory.store(state.regs.rsi + i, v)

path_group = proj.factory.path_group(state)
path_group.explore(find = 0x4013c4)

s = path_group.found[0].state

for i in range(182):
    r = repr(s.memory.load(0x1000000 + i,1))
    matches = re.findall('((x|k)([0-9]+))_', r)
    terms = []
    for _, name, idx in matches:
        terms.append('%s[%s]' % (name, idx))
    line = 'y[%d] = ' % i
    line += ' ^ '.join(terms)
    print line

