.align 2
s0:
    .asciz "/r/trebuchetmemes"
.align 2
s1:
    .asciz "__ZN4dyld12gLinkContextE"
.align 2
s2:
    .asciz "__ZN16ImageLoaderMachO25instantiateMainExecutableEPK12macho_headermPKcRKN11ImageLoader11LinkContextE"
.align 2
s3:
    .asciz "__ZN4dyldL8addImageEP11ImageLoader"
.align 2
s4:
    .asciz "__ZN4dyld4linkEP11ImageLoaderbbRKNS0_10RPathChainEj" // iOS 10+
.align 2
s4o:
    .asciz "__ZN4dyld4linkEP11ImageLoaderbbRKNS0_10RPathChainE" // iOS 9
.align 2
s5:
    .asciz "__ZN4dyld15runInitializersEP11ImageLoader"
.align 2
fn:
    ldrb w2, [x0], 0x1
    ldrb w3, [x1], 0x1
    subs w4, w3, w2
    b.ne rt
    cbnz w2, fn
.align 2
rt:
    ret
.align 2
.globl genesis
genesis:
    // x19 = codeAddr
    // x20 = codeSlide
    // x21 = self_task
    // x22 = dyldBase
    // x23 = dyldSlide
    // x24 = dyld::gLinkContext
    // x25 = ImageLoaderMachO::instantiateMainExecutable / macho
    // x26 = dyld::addImage
    // x27 = dyld::link
    // x28 = dyld::runInitializers
    mov x0, sp
    and sp, x0, ~15
    sub sp, sp, 0x140           // XXX: don't change this value without changing "stp xzr, xzr, [sp, 0x130]!" at the bottom as well

    // Get our own header
L1: adrp x19, __mh_execute_header@page
L2: add x19, x19, __mh_execute_header@pageoff
.loh AdrpAdd L1, L2

    // Get our own slide
    add x10, x19, 0x20
    ldr w11, [x19, 0x10]        // ncmds
1:
    ldp w8, w9, [x10]           // cmd, size
    cmp w8, 0x19                // LC_SEGMENT_64
    b.ne 2f
    ldp x12, x13, [x10, 0x28]   // fileoff, filesize
    cbnz x12, 2f                // fileoff == 0
    cbnz x13, 3f                // filesize != 0
2:
    add x10, x10, w9, uxtw      // cmd = cmd + cmd->cmdsize
    subs w11, w11, 0x1
    b.ne 1b
    movn x18, 0x4541
    br x18
3:
    ldr x20, [x10, 0x18]        // vmaddr
    sub x20, x19, x20           // codeSlide = codeAddr - vmaddr

    // task_self_trap
    movn x16, 0x1b
    svc 0x80
    mov w21, w0

    // Kill all other threads
    // task_threads(mach_task_self(), ...);
    movn x16, 0x19              // mach_reply_port
    svc 0x80
    mov w4, w0

    movz w0, 0x1513             // MACH_MSG_TYPE_MAKE_SEND_ONCE | MACH_MSG_TYPE_COPY_SEND
    movz w2, 0x18               // insize
    stp w0, w2, [sp]
    stp w21, w4, [sp, 0x8]      // request port, reply port
    movz w0, 0xd4a              // task_threads
    stp wzr, w0, [sp, 0x10]     // voucher, msg id

    mov x0, sp
    movz w1, 0x3                // send & receive
    movz w3, 0x40               // outsize
    movz w5, 0                  // timeout
    movz w6, 0                  // notify port
    movn x16, 0x1e              // mach_msg
    svc 0x80
    cbnz w0, 1f
    ldr w1, [sp]                // msgh_bits
    tbnz w1, 31, 2f
1:
    movz x18, 0x2ff2
    br x18
2:
    ldur x22, [sp, 0x1c]        // act_list.address
    ldr  w23, [sp, 0x34]        // act_listCnt
    cbz w23, 10f
    ubfiz x24, x23, 2, 32

    // thread_self_trap
    movn x16, 0x1a
    svc 0x80
    mov w25, w0

    // for(...) thread_terminate();
1:
    sub w23, w23, 1
    ldr w26, [x22, w23, uxtw 2]
    cmp w26, w25
    b.eq 3f

    movn x16, 0x19              // mach_reply_port
    svc 0x80
    mov w4, w0

    movz w0, 0x1511             // MACH_MSG_TYPE_MAKE_SEND_ONCE | MACH_MSG_TYPE_MOVE_SEND
    movz w2, 0x18               // insize
    stp w0, w2, [sp]
    stp w26, w4, [sp, 0x8]      // request port, reply port
    movz w0, 0xe10              // thread_terminate
    stp wzr, w0, [sp, 0x10]     // voucher, msg id

    mov x0, sp
    movz w1, 0x3                // send & receive
    movz w3, 0x2c               // outsize
    movz w5, 0                  // timeout
    movz w6, 0                  // notify port
    movn x16, 0x1e              // mach_msg
    svc 0x80
    cbnz w0, 2f
    ldr w1, [sp, 0x20]          // RetCode
    cbz w1, 3f
2:
    movz x18, 0x0ff2
    br x18
3:
    cbnz w23, 1b

    // mach_port_deallocate
    mov w0, w21
    mov w1, w25
    movn x16, 0x11
    svc 0x80

    // mach_vm_deallocate
    mov w0, w21
    mov x1, x22
    mov x2, x24
    movn x16, 0xb
    svc 0x80
10:

/*
    // Copy-remap rw- segments
    // x22 and above is currently scratch space
    add x22, x19, 0x20
    ldr w23, [x19, 0x10]        // ncmds
1:
    ldp w0, w24, [x22]          // cmd, size
    cmp w0, 0x19                // LC_SEGMENT_64
    b.ne 3f
    ldr w4, [x22, 0x3c]         // prot
    tbz w4, 1, 3f               // VM_PROT_WRITE

    mov w0, w21
    ldp x1, x2, [x22, 0x18]     // vmaddr, vmsize
    add x1, x1, x20             // add slide
    movz w3, 0                  // set_max
    orr w4, w4, 0x10            // VM_PROT_COPY
    movn x16, 0xd               // mach_vm_protect
    svc 0x80

    cbz w0, 3f
2:
    movn x18, 0x0521
    br x18
3:
    add x22, x22, w24, uxtw     // cmd = cmd + cmd->cmdsize
    subs w23, w23, 0x1
    b.ne 1b
*/

    // Ask kernel where dyld is
    movn x16, 0x19              // mach_reply_port
    svc 0x80
    mov w4, w0

    movz w0, 0x1513             // MACH_MSG_TYPE_MAKE_SEND_ONCE | MACH_MSG_TYPE_COPY_SEND
    movz w2, 0x28               // insize
    stp w0, w2, [sp]
    stp w21, w4, [sp, 0x8]      // request port, reply port
    movz w0, 0xd4d              // task_info
    stp wzr, w0, [sp, 0x10]     // voucher, msg id
    movz x0, 0x1, lsl 32        // NDR
    str x0, [sp, 0x18]
    movz w0, 0x11               // TASK_DYLD_INFO
    movz w1, 0x5                // TASK_DYLD_INFO_COUNT
    stp w0, w1, [sp, 0x20]

    mov x0, sp
    movz w1, 0x3                // send & receive
    movz w3, 0x13c              // outsize
    movz w5, 0                  // timeout
    movz w6, 0                  // notify port
    movn x16, 0x1e              // mach_msg
    svc 0x80
    cbnz w0, 1f
    ldr w1, [sp, 0x20]          // RetCode
    cbz w1, 2f
1:
    movz x18, 0x3535
    br x18
2:
    ldr x22, [sp, 0x28]         // all_image_info_addr
    ldr x22, [x22, 0x20]        // dyldImageLoadAddress

    // Get dyld slide
    add x10, x22, 0x20
    ldr w11, [x22, 0x10]        // ncmds
1:
    ldp w8, w9, [x10]           // cmd, size
    cmp w8, 0x19                // LC_SEGMENT_64
    b.ne 2f
    ldp x12, x13, [x10, 0x28]   // fileoff, filesize
    cbnz x12, 2f                // fileoff == 0
    cbnz x13, 3f                // filesize != 0
2:
    add x10, x10, w9, uxtw      // cmd = cmd + cmd->cmdsize
    subs w11, w11, 0x1
    b.ne 1b
    movn x18, 0x3f21
    br x18
3:
    ldr x23, [x10, 0x18]        // vmaddr
    sub x23, x22, x23           // dyldSlide = dyldBase - vmaddr

    // Walk dyld symtab
    add x10, x22, 0x20
    ldr w11, [x22, 0x10]        // ncmds
5:
    ldp w8, w9, [x10]           // cmd, size
    cmp w8, 0x2                 // LC_SYMTAB
    b.ne 6f
    ldr w12, [x10, 0x10]        // stroff
    ldp w10, w11, [x10, 0x8]    // symoff, nsyms
    movz x8, 0
    movz x9, 0
    // Translate offsets to VM
    ldr w13, [x22, 0x10]        // ncmds
    add x14, x22, 0x20
14:
    ldp w15, w16, [x14]         // cmd, size
    cmp w15, 0x19               // LC_SEGMENT_64
    b.ne 15f
    ldp x15, x17, [x14, 0x28]   // fileoff, filesize
    add x17, x17, x15
    cmp w15, w10
    ccmp w17, w10, 4, ls
    b.ls 17f
    ldr x8, [x14, 0x18]         // vmaddr
    sub x8, x8, x15
    add x8, x8, w10, uxtw
    add x8, x8, x23             // symp
    cbnz x9, 16f
17:
    cmp w15, w12
    ccmp w17, w12, 4, ls
    b.ls 15f
    ldr x9, [x14, 0x18]         // vmaddr
    sub x9, x9, x15
    add x9, x9, w12, uxtw
    add x9, x9, x23             // strp
    cbnz x8, 16f
15:
    subs w13, w13, 0x1
    b.eq 7f
    add x14, x14, w16, uxtw     // cmd = cmd + cmd->cmdsize
    b 14b
16:
    movz x24, 0
    movz x25, 0
    movz x26, 0
    movz x27, 0
    movz x28, 0
9:
    ldr w13, [x8]               // n_strx
    add x13, x9, w13, uxtw
    mov x0, x13
    adr x1, s1
    bl fn
    cbnz w4, 10f
    ldr x24, [x8, 0x8]          // n_value
    add x24, x24, x23
    b 12f
10:
    mov x0, x13
    adr x1, s2
    bl fn
    cbnz w4, 20f
    ldr x25, [x8, 0x8]          // n_value
    add x25, x25, x23
    b 12f
20:
    mov x0, x13
    adr x1, s3
    bl fn
    cbnz w4, 11f
    ldr x26, [x8, 0x8]          // n_value
    add x26, x26, x23
    b 12f
11:
    mov x0, x13
    adr x1, s4
    bl fn
    cbz w4, 19f
    mov x0, x13
    adr x1, s4o
    bl fn
    cbnz w4, 18f
19:
    ldr x27, [x8, 0x8]          // n_value
    add x27, x27, x23
    b 12f
18:
    mov x0, x13
    adr x1, s5
    bl fn
    cbnz w4, 13f
    ldr x28, [x8, 0x8]          // n_value
    add x28, x28, x23
12:
    cmp x24, 0
    ccmp x25, 0, 4, ne
    ccmp x26, 0, 4, ne
    ccmp x27, 0, 4, ne
    ccmp x28, 0, 4, ne
    b.ne 8f
13:
    subs w11, w11, 0x1
    b.eq 7f
    add x8, x8, 0x10            // ++strp
    b 9b
6:
    subs w11, w11, 0x1
    b.eq 7f
    add x10, x10, w9, uxtw      // cmd = cmd + cmd->cmdsize
    b 5b
7:
    movn x18, 0x3501
    br x18
8:

    // macho = ImageLoaderMachO::instantiateMainExecutable(codeAddr, codeSlide, "/r/trebuchetmemes", dyld::gLinkContext);
    mov x3, x24
    adr x2, s0
    mov x1, x20
    mov x0, x19
    blr x25

    // Save macho
    mov x25, x0

    // dyld::addImage(macho);
    blr x26

/*
    adr x1, rt
    str x1, [x24, 0x48]

    // dyld::gLinkContext.mainExecutable = macho
    str x0, [x24, 0x108]
*/

    // dyld::link(macho, true, true, ImageLoader::RPathChain(NULL, NULL), -1);
    mov x0, x25
    movz x1, 0x1
    movz x2, 0x1
    stp xzr, xzr, [sp]
    mov x3, sp
    movn x4, 0x1
    blr x27

    // dyld::runInitializers(macho);
    mov x0, x25
    blr x28

    stp xzr, xzr, [sp, 0x120]!  // XXX: don't change this value without changing "sub sp, sp, 0x140" at the top as well
    stp xzr, xzr, [sp, 0x10]
    movz x0, 0                  // argc
    mov x1, sp                  // argv
    add x2, x1, 0x8             // envp
    add x3, x2, 0x8             // apple
    bl _main
    movz x16, 0x1
    svc 0x80
