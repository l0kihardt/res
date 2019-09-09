# didnt solve it at the race
# too many answers ...
x = bytearray(b'12345678901234567890x')
x[0] = ord("f")
x[1] = ord("l")
x[2] = ord("a")
x[3] = ord("g")
x[4] = ord("{")
x[20] = ord("}")
print(x)

import string
# lets try soome bruteforce

seed = None
def rand():
    global seed
    seed = (((seed * 0x343fd) & 0xffffffff) + 0x269ec3) & 0xffffffff
    return (seed >> 16) & 0x7fff

ans_arr = [
        0x21c,
        0x10e,
        0x104,
        0x16c,
        0x3e2,
        0x23c,
        0x2e0,
        0x13c,
        0x2dc,
        0x1f8,
        0x344,
        0x1ea,
        ]

from z3 import *
for i in string.printable:
    for j in string.printable:
        for k in string.printable:
            # get the initial seed
            seed = int((i + j + k).encode('hex'), 16)
            all_ops = []
            for xx in range(12):
                count = rand()
                ops = '0'
                for yy in range(12):
                    if count & 1:
                        ops += '+x[%d]' % yy
                    else:
                        ops = '((%s)^x[%d])' % (ops, yy)
                    count = count >> 1
                all_ops.append(ops)
            s = Solver()
            x = [BitVec('x%s' % h, 8) for h in range(12)]
            for idx, ops in enumerate(all_ops):
                s.add(eval(ops + '==%d' % ans_arr[idx]))

            if s.check() == sat:
                tmp = s.model()
                print(seed)
                print("".join([chr(tmp[each].as_long()) for each in x]))
                break




