from z3 import *

allowed_set = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13"
allowed_set += "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24"
allowed_set += "\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36"
allowed_set += "\x37\x38\x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a"
allowed_set += "\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b"
allowed_set += "\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c"
allowed_set += "\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"


#EGGHUNTER
egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"


result = egghunter [::-1]

# Printing stuff in hex
# print ("".join("{:02x}".format(ord(c)) for c in result))
print ("-----------------------------")
n = 4
r = [result[i:i+n] for i in range(0, len(result), n)]
for i in r:
    target =  (int(("".join("{:02x}".format(ord(c)) for c in i)),16))
    s = Solver()

    x,y,z = BitVecs('x y z',32)

    # Annoying part:
    # Check if every byte in x y and z is an allowed byte
    con_x_byte_1 = (x&0xff) ==  ord(allowed_set[0])
    con_y_byte_1 = (y&0xff) ==  ord(allowed_set[0])
    con_z_byte_1 = (z&0xff) ==  ord(allowed_set[0])
    for i in allowed_set[1::]:
        con_x_byte_1 = Or(con_x_byte_1, (x&0xff) == ord(i))
        con_y_byte_1 = Or(con_y_byte_1, (y&0xff) == ord(i))
        con_z_byte_1 = Or(con_z_byte_1, (z&0xff) == ord(i))

    con_x_byte_2 = (x&0xff00) ==  ord(allowed_set[0]) << 8
    con_y_byte_2 = (y&0xff00) ==  ord(allowed_set[0]) << 8
    con_z_byte_2 = (z&0xff00) ==  ord(allowed_set[0]) << 8
    for i in allowed_set[1::]:
        con_x_byte_2 = Or(con_x_byte_2, (x&0xff00) == ord(i) << 8)
        con_y_byte_2 = Or(con_y_byte_2, (y&0xff00) == ord(i) << 8)
        con_z_byte_2 = Or(con_z_byte_2, (z&0xff00) == ord(i) << 8)

    con_x_byte_3 = (x&0xff0000) ==  ord(allowed_set[0]) << 16
    con_y_byte_3 = (y&0xff0000) ==  ord(allowed_set[0]) << 16
    con_z_byte_3 = (z&0xff0000) ==  ord(allowed_set[0]) << 16
    for i in allowed_set[1::]:
        con_x_byte_3 = Or(con_x_byte_3, (x&0xff0000) == ord(i) << 16)
        con_y_byte_3 = Or(con_y_byte_3, (y&0xff0000) == ord(i) << 16)
        con_z_byte_3 = Or(con_z_byte_3, (z&0xff0000) == ord(i) << 16)

    con_x_byte_4 = (x&0xff000000) ==  ord(allowed_set[0]) << 24
    con_y_byte_4 = (y&0xff000000) ==  ord(allowed_set[0]) << 24
    con_z_byte_4 = (z&0xff000000) ==  ord(allowed_set[0]) << 24
    for i in allowed_set[1::]:
        con_x_byte_4 = Or(con_x_byte_4, (x&0xff000000) == ord(i) << 24)
        con_y_byte_4 = Or(con_y_byte_4, (y&0xff000000) == ord(i) << 24)
        con_z_byte_4 = Or(con_z_byte_4, (z&0xff000000) == ord(i) << 24)

    con_x = And(con_x_byte_1, con_x_byte_2, con_x_byte_3, con_x_byte_4)
    con_y = And(con_y_byte_1, con_y_byte_2, con_y_byte_3, con_y_byte_4)
    con_z = And(con_z_byte_1, con_z_byte_2, con_z_byte_3, con_z_byte_4)
    constraint = And(con_x, con_y, con_z)
    constraint = And(constraint, x >= 0, y >= 0, z >= 0)

    # constraint = And(constraint, 0xffffffff - x - y - z + 1 == target)
    constraint = And(constraint, 0xffffffff - x - y - z + 1 == target)
    s.add(constraint)
    print(s.check())
    print(s.model())
    test = s.model()
    print ("solving . . . : " + hex(target))
    print ( hex(int(str(test[x]))) + " - " + hex(int(str(test[y]))) + " - " + hex(int(str(test[z]))) + " = " )
    x = int(str(test[x]))
    y = int(str(test[y]))
    z = int(str(test[z]))
    print ( hex( 0xffffffff - x - y - z + 1 ))
    print ("-----------------------------")
