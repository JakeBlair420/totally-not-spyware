# start:
# b go

# dlsym:
# .word 0x1337
# .word 0x1337

# go:
# ldr x1, dlsym

# adr x8, start
# ldr x7, =(0x1000+0x7190)
# add x0, x8, x7

# ldr x7, =0x1000000
# add x2, x8, x7

# blr x0

start: 
  movz x0, 0x1337
  movz x1, 0x1337
  movz x2, 0x1337
  movz x3, 0x1337
  movz x4, 0x1337
  movz x5, 0x1337
  movz x6, 0x1337
  movz x7, 0x1337
  movz x8, 0x1337
  movz x9, 0x1337
  movz x10, 0xdead
  movz x11, 0xdead
  movz x12, 0xdead
  movz x13, 0xdead
  movz x14, 0xdead
  movz x15, 0xdead
  movz x16, 0xdead
  movz x17, 0xdead
  movz x18, 0xdead
  movz x19, 0xdead
  movz x20, 0xdead
  movz x21, 0xdead
  movz x22, 0xdead
  movz x23, 0xdead
  movz x24, 0xdead
  movz x25, 0xdead
  movz x26, 0xdead
  movz x27, 0xdead
  movz x28, 0xdead
  br x0
