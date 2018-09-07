# High level overview of the patch for 11.4
Commit: https://github.com/WebKit/webkit/commit/b602e9d167b2c53ed96a42ed3ee611d237f5461a
Changes:
They added a clobberWorld call here: https://github.com/WebKit/webkit/blob/b602e9d167b2c53ed96a42ed3ee611d237f5461a/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h#L2277
And modified a lot in the method here: https://github.com/WebKit/webkit/blob/d9cd5e31e4ebd912fee7e53295d847d16e1b229b/Source/JavaScriptCore/dfg/DFGClobberize.h#L45

I don't really know how those changes affected execution, because I don't know the code base really well, but feel free to let me know.

# How can we fix that in binary
Because those methods are templates, there are multiple implementations in the code.

## patch clobberize
To get all of the clobberize implementations you can run:
nm <path to JSC> | grep "clobberize"

We need to patch all of the template functions.
Because they only moved stuff around in clobberize, we focues on patching the jumptable as we needed less assumptions/offsets to do that, then to hook the function and emulate/recreate it for create this.
We looked at the patched version and found out that now CreateThis does the same as VALUEADD (are inside of the same case in the big switch case statment).

For big switch case statments, the compiler generates jumptables, which look kinda like this:
```
mov <reg1>, 0x3ff => as that is typical for the NodeType value
and <reg3>,<reg1>,<reg2> or and <reg3>,<reg2>,<reg1>
```
This can also be represented as:
`and <reg3>, <reg1>, 0x3ff`

(reg3 is now Node->op)
```
cmp <reg3>, <intermidiate> => the intermidiate could change between version so we just search for the instruction
bhi <some addr> => jumps if the number is outside of the switch case range
adrp <reg4>, <some addr>
add <reg4>, <reg4>, <some value> => we need to get the value of reg4 now as this is our jumptable address
```

(now reg4 contains the jumptable address)
```
- ldrb <reg5>,[<reg4>,<reg3>,uxtw] (can also be ldrsw)
- adr <reg6>, <some value>
- add <reg7>, <reg6>, <reg5>, (sxtb #2)
- br <reg7>
```

The 0x3ff is a "magic" value, because the Nodetype is only a few bytes long, the value loaded is anded with that to mask the others out.
We use that as a safty mechanism to make sure that we found the right jumptable code.

So the current patch code finds this jumptable code in the method (yes I wrote a fucking disassembler...) and from that we get the a pointer to an array of 32bit offsets which gets loaded (Node->op is used as an index into that array) into reg7. Then we can just switch memory permissions to rw-, get the 32 bit jump offset from VALUEADD and replace the offset of CREATETHIS with it in the jumptable array.
After that we have to switch permissions back as the jumptable array is inlined, so there can be code on the same page.

While testing we also noticied that the jumptable code sometimes gets spilt up by the compiler and some asm is moved inbetween instructions, so we also encount for that in the finder.

In the end there was one big question, how can we find the value for CREATETHIS and VALUEADD? We looked around, but there are no methods which are using it in a way we can easily extract.
Luckily, as Webkit is open source, Apple also posts a version on every IOS release on the svn server: https://svn.webkit.org/repository/webkit/releases/Apple/
There is a problem for betas tho and we didn't found a solution for that yet.


## patching executionEffects
The clobberWorld patch is the easier one, there we can just use substitute to hook the function, call the origial one, check if Node->op is create this and then call clobberWorld.
You might ask yourself now, wtf, in the original patch the clobberWorld call happens before the forNode call and yeah that's the case, but we asked Samuel Groß if it would make a difference and he said it won't.

# What needs to be done/is broke
- hardcoded offsets: The enum values from the website aren't added to the code yet and we still have just two defines hardcoded in, that needs to change for the release with multiple firmware versions
- switching memory to rw- and back to r-x: on IOS 11 things change and now the second call to vm_protect fails, this should be solvable by porting the substitute implementation here:  https://github.com/comex/substitute/blob/95f2beda374625dd503bfb51a758b6f6ced57887/lib/darwin/execmem.c#L373-L447
- the patch crashes on ios 10 with a null deref: this needs to be debugged and fixed, I have no idea why it happens yet...

~ litlelailo
