def reverse(ch):
    part1 = (ch & 0b01010101) << 1
    part2 = (ch & 0b10101010) >> 1
    ans = (part1 | part2)
    return chr(ans)

s = '82a386a3b7983198313b363293399232349892369a98323692989a313493913036929a303abe'
ans = ''
for i in range(0,len(s),2):
    tmp = (int(s[i:i + 2], 16))
    ans += reverse(tmp)
print ans
