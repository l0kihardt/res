import angr

import logging



logging.basicConfig()

#angr.path_group.l.setLevel('DEBUG')

p = angr.Project('./reverse_box', use_sim_procedures=True)



#global values

flag=[149, 238, 175, 149, 239, 148, 35, 73, 153, 88, 47, 114, 47, 73, 47, 114, 177, 154, 122, 175, 114, 230, 231, 118, 181, 122, 238, 114, 47, 231, 122, 181, 173, 154, 174, 177, 86, 114, 150, 118, 174, 122, 35, 109, 153, 177, 223, 74]

value = 0



#define hook functions 

def set_eax(state):

    state.regs.eax = value



#hook unknown functions

p.hook(0x80485ac, func = set_eax, length = 5)



def get_answer():

    print value

    init_state = p.factory.entry_state(args=["reverse_box", "TWCTF"], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})

    pg=p.factory.path_group(init_state, immutable=False)

    pg.explore(find=0x80486e0, avoid=[0x8048756])

    s = pg.found[0].state

    esp = s.regs.esp

    lst = [s.se.any_n_int(s.memory.load(esp + 0x1c + i, 1), 1) for i in range(0, 0x100)]

    print lst

    for j in enumerate("TWCTF"):

        if(lst[ord(j[1])][0] != flag[j[0]]):

            return False

    print '[+] OK ' + hex(value)

    box = []

    for ch in lst:

        box.append(ch[0])

    ans = "".join([chr(box.index(i)) for i in flag])

    print ans

    exit(0)



for k in range(214, 0x100):

    value = k

    ret = get_answer() 
