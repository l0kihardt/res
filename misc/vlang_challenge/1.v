import os
// the basic design 
// xtea + rc4

fn rc4_init() []byte {
    key := []byte {len: 8, init: 2}
    mut s := []byte {len: 256, init: 0}
    for i := 0; i < 256; i++ {
        s[i] = byte(i)
    }
    mut j := 0
    for i := 0; i < 256; i++ {
        j = (j + s[i] + key[i % key.len]) % 256
        tmp := s[i]
        s[i] = s[j]
        s[j] = tmp
    }
    return s
}   

fn do_rc4(name []byte, mut s []byte) []byte {
    mut i := 0
    mut j := 0
    mut out := []byte {len: name.len, init: 0}
    for k := 0; k < name.len; k++ {
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        tmp := s[i]
        s[i] = s[j]
        s[j] = tmp
        out[k] = name[k] ^ s[(s[i] + s[j]) % 256]
    }
    return out
}

fn encipher(num_rounds u32, mut v []u32, key []u32) {
    mut v0 := u32(v[0])
    mut v1 := u32(v[1])
    mut sum := u32(0)
    delta := u32(0x9E3779B9)

    for i := 0; i < num_rounds; i++ {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + byte(key[sum & 3]))
        sum += delta
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + byte(key[(sum >> 11) & 3]))
    }
    v[0] = v0
    v[1] = v1
}

fn decipher(num_rounds u32, mut v []u32, key []u32) {
    mut v0 := u32(v[0])
    mut v1 := u32(v[1])
    delta := u32(0x9E3779B9)
    mut sum := delta * num_rounds

    for sum > 0 {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + byte(key[(sum >> 11) & 3]))
        sum -= delta
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + byte(key[sum & 3]))
    }

    v[0] = v0
    v[1] = v1

}

fn encrypt(mut d []byte, key []u32) []byte {
    mut n := int(0)
    mut v := []u32{len: 2}
    mut ret := []byte{}
    for i := 0; i < d.len; i+=4 {
        if (i + 3) < d.len {
            if n == 0 {
                v[0] = d[i + 3] << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                n = 1
            } else if n == 1 {
                v[1] = d[i + 3] << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                n = 0
                encipher(32, mut v, key)
                ret << byte(v[0] & 0x000000ff)
                ret << byte((v[0] & 0x0000ff00) >> 8)
                ret << byte((v[0] & 0x00ff0000) >> 16)
                ret << byte((v[0] & 0xff000000) >> 24)
                ret << byte(v[1] & 0x000000ff)
                ret << byte((v[1] & 0x0000ff00) >> 8)
                ret << byte((v[1] & 0x00ff0000) >> 16)
                ret << byte((v[1] & 0xff000000) >> 24)
            }
        } else {
            empty := (i + 3) - d.len
            match empty {
                0 {
                    if n == 0 {
                        v[0] = 0 << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                    }
                    break
                }
                1 {
                    if n == 0 {
                        v[0] = 0 << 24 | 0 << 16 | d[i + 1] << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | 0 << 16 | d[i + 1] << 8 | d[i]
                    }
                }
                2 {
                    if n == 0 {
                        v[0] = 0 << 24 | 0 << 16 | 0 << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | 0 << 16 | 0 << 8 | d[i]
                    }
                }
                else {
                    v[0] = 0
                    v[1] = 0
                }
            }
            encipher(32, mut v, key)
            ret << byte(v[0] & 0x000000ff)
            ret << byte((v[0] & 0x0000ff00) >> 8)
            ret << byte((v[0] & 0x00ff0000) >> 16)
            ret << byte((v[0] & 0xff000000) >> 24)
            ret << byte(v[1] & 0x000000ff)
            ret << byte((v[1] & 0x0000ff00) >> 8)
            ret << byte((v[1] & 0x00ff0000) >> 16)
            ret << byte((v[1] & 0xff000000) >> 24)
        }
    }
    return ret
}

fn decrypt(mut d []byte, key []u32) []byte {
    mut n := int(0)
    mut v := []u32{len: 2}
    mut ret := []byte{}
    for i := 0; i < d.len; i+=4 {
        if (i + 3) < d.len {
            if n == 0 {
                v[0] = d[i + 3] << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                n = 1
            } else if n == 1 {
                v[1] = d[i + 3] << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                n = 0
                decipher(32, mut v, key)
                ret << byte(v[0] & 0x000000ff)
                ret << byte((v[0] & 0x0000ff00) >> 8)
                ret << byte((v[0] & 0x00ff0000) >> 16)
                ret << byte((v[0] & 0xff000000) >> 24)
                ret << byte(v[1] & 0x000000ff)
                ret << byte((v[1] & 0x0000ff00) >> 8)
                ret << byte((v[1] & 0x00ff0000) >> 16)
                ret << byte((v[1] & 0xff000000) >> 24)
            }
        } else {
            empty := (i + 3) - d.len
            match empty {
                0 {
                    if n == 0 {
                        v[0] = 0 << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | d[i + 2] << 16 | d[i + 1] << 8 | d[i]
                    }
                }
                1 {
                    if n == 0 {
                        v[0] = 0 << 24 | 0 << 16 | d[i + 1] << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | 0 << 16 | d[i + 1] << 8 | d[i]
                    }
                }
                2 {
                    if n == 0 {
                        v[0] = 0 << 24 | 0 << 16 | 0 << 8 | d[i]
                        v[1] = 0
                    } else {
                        v[0] = 0
                        v[1] = 0 << 24 | 0 << 16 | 0 << 8 | d[i]
                    }
                }
                else {
                    v[0] = 0
                    v[1] = 0
                }
            }
            decipher(32, mut v, key)
            ret << byte(v[0] & 0x000000ff)
            ret << byte((v[0] & 0x0000ff00) >> 8)
            ret << byte((v[0] & 0x00ff0000) >> 16)
            ret << byte((v[0] & 0xff000000) >> 24)
            ret << byte(v[1] & 0x000000ff)
            ret << byte((v[1] & 0x0000ff00) >> 8)
            ret << byte((v[1] & 0x00ff0000) >> 16)
            ret << byte((v[1] & 0xff000000) >> 24)
        }
    }
    return ret
}

fn str2bytes(b string) []byte {
    mut data := []byte{}
    for i in 0 .. b.len {
        data << b[i]
    }
    return data
}

fn main() {
    key := [u32(0xaaaaaaaa), 0xbbbbbbbb, 0xcccccccc, 0xdddddddd]
    mut contents := os.read_file("timg.jpg") or {
        println("failed to read file.")
        return
    }

    mut name := str2bytes(contents)
    println(name)

    mut tt := [byte(0x31), 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33]
    println(tt)
    tt = encrypt(mut tt, key)
    tt = decrypt(mut tt, key)
    println(tt)

    mut s := rc4_init()
    name = do_rc4(name, mut s)
    println("rc4 done")
    
    name = encrypt(mut name, key)
    println("encrypt done")

    name = decrypt(mut name, key)
    s = rc4_init()
    name = do_rc4(name, mut s)
    println("decrypt done")
    println(name)

    os.rm("./output.jpg")
    mut file := os.open_file("./output.jpg", "a+", 0o666) or {
        panic(err)
    }
    file.write_bytes(name.data, name.len)
    file.close() 
}
