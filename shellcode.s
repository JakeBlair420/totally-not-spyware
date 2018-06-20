start:
    b go    

dlsym:
    .word 0x1337
    .word 0x1337

go:
    movz x0, 0x6969
    movz x1, 0x6969
    movz x2, 0x6969
    movz x3, 0x6969
    movz x4, 0x6969
    movz x5, 0x6969
    movz x6, 0x6969
    movz x7, 0x6969
    movz x8, 0x6969
    movz x9, 0x6969
    movz x10, 0x6969
    movz x11, 0x6969
    movz x12, 0x6969
    movz x13, 0x6969
    movz x14, 0x6969
    movz x15, 0x6969
    movz x16, 0x6969
    movz x17, 0x6969
    movz x18, 0x6969
    movz x19, 0x6969
    movz x20, 0x6969
    movz x21, 0x6969
    movz x22, 0x6969
    movz x23, 0x6969
    movz x24, 0x6969
    movz x25, 0x6969
    movz x26, 0x6969
    movz x27, 0x6969
    movz x28, 0x6969

    # ldr x1, dlsym

    # adr x8, start
    # ldr x7, =(0x1000+0x7190)
    # add x0, x8, x7
 
    # ldr x7, =0x1000000
    # add x2, x8, x7
 
    # blr x0
