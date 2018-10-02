/********************** PATCHER FOR CVE-2018-4233 **********************/
/* Details:      - dylib to patch a vuln in JavaScriptCore             */
/*               - applies patches to the executeWorld and clobberize  */
/*               templates                                             */
/* Patch commit: b602e9d167b2c53ed96a42ed3ee611d237f5461a              */
/* Usage:        inject the dylib into the WebContent Process          */
/* Dependencies: substitute by @comex (tested with coolstars fork)     */
/* TODO:         At the moment it crashes because of the not working   */
/*               jumptable patch                                       */
/* Notes:        - Uses code from siguza (Thank you) for finding       */
/*               private symbols                                       */
/*               - only works on arm64                                 */
/*                                                                     */
/**********************   created by @littelailo   *********************/

/**********************           Building         *********************/
/* To build run:                                                       */
/* $ git clone https://github.com/coolstar/substitute                  */
/* $ cd substitute                                                     */
/*                                                                     */
/* cs's fork won't build for me                                        */
/* I had to add an underscore (_) to _dyld_get_all_image_infos         */
/* in ./lib/darwin/inject.c                                            */
/* (_dyld_get_all_image_infos  => __dyld_get_all_image_infos )         */
/*                                                                     */
/* $ ./configure --xcode-sdk=iphoneos --xcode-archs=arm64 &&           */
/*    make -j8 && ./script/gen-deb.sh                                  */
/* $ cp substrate/substrate.h ../                                      */
/* $ cd ..                                                             */
/*                                                                     */
/* you need <mach/vm_mach.h>,  which was removed from the iphone sdk,  */
/* just copy it from the macos one                                     */
/* or dowload an older one from the internet                           */
/*                                                                     */
/* $ xcrun -sdk iphoneos cc -arch arm64 -dynamiclib -flat_namespace    */
/*   3.c ./substitute/out/libsubstitute.dylib -o test.dylib            */
/* $ ldid -S test.dylib                                                */
/*                                                                     */
/***********************************************************************/

#if 0
xcrun -sdk iphoneos cc -arch arm64 -o SpywarePatch.dylib -shared SpywarePatch.m -Wall -O3 -framework Foundation -F. -framework CydiaSubstrate && codesign -s - SpywarePatch.dylib
#endif

/**********************           Includes         *********************/

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>              // open
#include <stdbool.h>
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // stat
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <Foundation/Foundation.h>

extern void MSHookFunction(void *symbol, void *hook, void **old);
extern kern_return_t mach_vm_protect(task_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t max, vm_prot_t prot);
extern kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);

/**********************        Function Defs       *********************/
/* => just search for the function to get an understanding of what     */
/*    they are doing                                                   */
/***********************************************************************/

void* get_addr(void *handler, char *dylib_path, void *pub_sym_addr, char *pub_sym_name,  char *real_name);
uint64_t get_jumptable(void *func_start, uint16_t *max_val);
uint64_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits);

/**********************       Symbols to patch     *********************/
/* for clobberize it's basically nm <path to JSC> | grep "clobberize"  */
/* for executeWorld you can also just grep, but you have to sort out   */
/* the ones where the executeWorld function is passed as an arg        */
/*                                                                     */
/* Warning: for executeEffects the handling is different as the patch  */
/*          calls a diffrent function:                                 */
/*          - for AtTail..., clobberStructures_attail is called        */
/*          - while for InPlace... clobberStructures_inplace is called */
/*          That means that you shouldn't swap the two symbols         */
/*          Same is true for clobberStructures                         */
/***********************************************************************/

char *clobberize_syms[] = {
    "__ZN3JSC3DFG10clobberizeINS0_14NoOpClobberizeENS0_13ClobberSetAddES2_EEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_13ClobberSetAddES2_NS0_14NoOpClobberizeEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_14NoOpClobberizeENS0_13ClobberSetAddES2_EEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_14NoOpClobberizeENS0_15CheckClobberizeES2_EEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_14NoOpClobberizeENS0_20AbstractHeapOverlapsES2_EEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_18ClobberSetOverlapsENS0_14NoOpClobberizeES3_EEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20AbstractHeapOverlapsES2_NS0_14NoOpClobberizeEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_12_GLOBAL__N_113LocalCSEPhase8BlockCSEINS4_9LargeMapsEEEEENS0_21WriteMethodClobberizeIS7_EENS0_19DefMethodClobberizeIS7_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_12_GLOBAL__N_113LocalCSEPhase8BlockCSEINS4_9SmallMapsEEEEENS0_21WriteMethodClobberizeIS7_EENS0_19DefMethodClobberizeIS7_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_12_GLOBAL__N_114GlobalCSEPhaseEEENS0_21WriteMethodClobberizeIS4_EENS0_19DefMethodClobberizeIS4_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_29PreciseLocalClobberizeAdaptorIZNS0_12_GLOBAL__N_120PutStackSinkingPhase3runEvEUlNS_15VirtualRegisterEE1_ZNS5_3runEvEUlS6_E2_ZNS5_3runEvEUlS6_NS0_8LazyNodeEE0_EEEENS0_21WriteMethodClobberizeISB_EENS0_19DefMethodClobberizeISB_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_29PreciseLocalClobberizeAdaptorIZNS0_12_GLOBAL__N_120PutStackSinkingPhase3runEvEUlNS_15VirtualRegisterEE3_ZNS5_3runEvEUlS6_E4_ZNS5_3runEvEUlS6_NS0_8LazyNodeEE1_EEEENS0_21WriteMethodClobberizeISB_EENS0_19DefMethodClobberizeISB_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeINS0_20ReadMethodClobberizeINS0_29PreciseLocalClobberizeAdaptorIZNS0_12_GLOBAL__N_120PutStackSinkingPhase3runEvEUlNS_15VirtualRegisterEE_ZNS5_3runEvEUlS6_E0_ZNS5_3runEvEUlS6_NS0_8LazyNodeEE_EEEENS0_21WriteMethodClobberizeISB_EENS0_19DefMethodClobberizeISB_EEEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    "__ZN3JSC3DFG10clobberizeIZNS0_12_GLOBAL__N_18Validate8validateEvEUlNS0_12AbstractHeapEE_ZNS3_8validateEvEUlS4_E0_ZNS3_8validateEvE16DefLambdaAdaptorEEvRNS0_5GraphEPNS0_4NodeERKT_RKT0_RKT1_",
    NULL
};

char *executeEffects_syms[] = {
    "__ZN3JSC3DFG19AbstractInterpreterINS0_19AtTailAbstractStateEE14executeEffectsEjPNS0_4NodeE",
    "__ZN3JSC3DFG19AbstractInterpreterINS0_20InPlaceAbstractStateEE14executeEffectsEjPNS0_4NodeE",
};
char *clobberStructures_syms[] = {
    "__ZN3JSC3DFG19AbstractInterpreterINS0_19AtTailAbstractStateEE17clobberStructuresEj",
    "__ZN3JSC3DFG19AbstractInterpreterINS0_20InPlaceAbstractStateEE17clobberStructuresEj"
};

/**********************        Important defs      *********************/
/* Those might change with the JSC version...                          */
/* - You can get CREATE_THIS and the other one from the NodeType enum  */
/*   under JSC/dfg/DFGNodeType.h from here:                            */
/*   https://svn.webkit.org/repository/webkit/releases/Apple/          */
/* - the node op offset is inside of a struct just open a disassembler */
/*   and go to of the clobberize symbols, find the jumptable code,     */
/*   now the var which is used as an index and which is modified with  */
/*   & 0x3ff is the node->op, search for the load of this var          */
/* - the jsc path shouldn't change                                     */
/*                                                                     */
/***********************************************************************/

#if 1
#   define CREATE_THIS 6                                                                              /* the value of createThis in the enum            */
#   define VALUEADD 65                                                                                /* the value of ValueAdd in the enum              */
#else
#   define CREATE_THIS 6                                                                              /* the value of createThis in the enum            */
#   define VALUEADD 68                                                                                /* the value of ValueAdd in the enum              */
#endif
#define OFFSET_NODE_OP 0x38                                                                           /* offset of op in the Node struct                */
#define JSC_PATH "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore"                 /* path to JSC, used in the get_addr function     */

/**********************        Variable  defs      *********************/

// used by the executeEffects functions to get node->op and check if it's createThis
typedef struct
{
    char padding[OFFSET_NODE_OP];
    uint64_t op;
}Node;

// the two method which will be called by the executeEffects hooks
void* (*clobberStructures_inplace)(void* ourthis, unsigned clobberLimit);
void* (*clobberStructures_attail)(void* ourthis,unsigned clobberLimit);

// the two original executeEffects functions
bool (*executeEffects_original_inplace)(void* ourthis,unsigned clobberLimit, Node *node);
bool (*executeEffects_original_attail)(void* ourthis,unsigned clobberLimit, Node *node);

/**********************        Function  defs      *********************/

// the two executeEffects function hooks
// they check if the op is create this
// if so they call clobberStructure on it, which can be called after forNode without sideeffects
// by that we apply the whole commit to the executeEffects functions
bool executeEffects_hook_inplace(void* ourthis, unsigned clobberLimit, Node *node)
{
    bool ret_val = executeEffects_original_inplace(ourthis,clobberLimit, node);

    if((node->op & 0x3ff) == CREATE_THIS)
    {
        clobberStructures_inplace(ourthis,clobberLimit);
    }
    return ret_val;
}
bool executeEffects_hook_attail(void* ourthis,unsigned clobberLimit, Node *node)
{
    bool ret_val = executeEffects_original_attail(ourthis,clobberLimit, node);

    if((node->op & 0x3ff) == CREATE_THIS)
    {
        clobberStructures_attail(ourthis,clobberLimit);
    }
    return ret_val;
}

// constructor gets executed on load
// installs all the hooks
__attribute__((constructor))
static void doit(void)
{
    /* prepare stuff for the private symbol finder */
    void *handle = dlopen(JSC_PATH, RTLD_NOW);
    void *pub_sym = dlsym(handle, "_ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE");

    /* get the symbols for the  clobberizeWorld patches aka both clobberStructures symbols */
    clobberStructures_inplace = get_addr(handle, JSC_PATH, pub_sym, "__ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE", clobberStructures_syms[0]);
    if(clobberStructures_inplace == NULL)
    {
        NSLog(@"Unable to find symbol clobberStructures! Abort\n");
        return;
    }
    clobberStructures_attail = get_addr(handle, JSC_PATH, pub_sym, "__ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE", clobberStructures_syms[1]);
    if(clobberStructures_attail == NULL)
    {
        NSLog(@"Unable to find symbol clobberStructures! Abort\n");
        return;
    }
    /* we patch clobberize first */
    int i = 0;
    while(clobberize_syms[i] != NULL)
    {
        /* get privat symbol address */
        void *real_sym = get_addr(handle, JSC_PATH, pub_sym, "__ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE", clobberize_syms[i]);
        if(real_sym == NULL)
        {
            NSLog(@"Unable to find symbol %s! Abort\n", clobberize_syms[i]);
            return;
        }
        NSLog(@"Clobberize address: %p \n", real_sym);

        /* find jumptable */
        uint16_t max_val = 0;
        uint64_t jumptable_addr = get_jumptable(real_sym, &max_val);
        if(!jumptable_addr)
        {
            NSLog(@"Unable to find jumptable for the method %s! Abort\n", clobberize_syms[i]);
            return;
        }
        NSLog(@"Found jumptable (max: 0x%x) @ 0x%llx\n", max_val, jumptable_addr);

#if 0
        /* set permissions */
        // TODO: make this work on IOS 11
        // this works on 10 tho so we should have two diffrent versions, for 11, we should port https://github.com/comex/substitute/blob/95f2beda374625dd503bfb51a758b6f6ced57887/lib/darwin/execmem.c#L373-L447 
        // ofc without all the manual stuff we can use the real methods there
        kern_return_t ret = mach_vm_protect(mach_task_self(), jumptable_addr, 0x1000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if(ret != 0)
        {
            NSLog(@"mach_vm_protect failed with %d! Abort\n", ret);
            return;
        }
        /* patch jumptable */
        uint32_t *jumptable = (uint32_t*)jumptable_addr;
        jumptable[CREATE_THIS] = jumptable[VALUEADD];

        /* set permission back (at least I try...) */
        ret = mach_vm_protect(mach_task_self(), jumptable_addr, 0x1000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        if(ret != 0)
        {
            NSLog(@"Second mach_vm_protect failed with %d! Abort\n", ret);
            return;
        }
#else
        vm_size_t page_size = 0;
        host_page_size(mach_task_self(),&page_size);
        NSLog(@"Working with a page size of %lx\n",page_size);
        void *new_page = mmap(NULL,page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
        if (new_page == MAP_FAILED) {
            NSLog(@"mmap failed, errno=%d (%s)\n",errno,strerror(errno));
        }
        kern_return_t ret = vm_copy(mach_task_self(), jumptable_addr & ~(page_size-1), page_size, (vm_address_t) new_page);
        if (ret != 0) {
            NSLog(@"vm_copy failed:%d\n",ret);
        }
        errno = 0;
        void *new_map = mmap((void*)(jumptable_addr & ~(page_size-1)), page_size, PROT_NONE, MAP_ANON | MAP_SHARED | MAP_FIXED, -1, 0);
        if (new_map == MAP_FAILED) {
            NSLog(@"Second mmap failed:%d (%s)\n",errno,strerror(errno));
        }
				
        /* patch jumptable */
        uint32_t *jumptable = (uint32_t*)new_page;
        jumptable[CREATE_THIS] = jumptable[VALUEADD];

        if (mprotect(new_page, page_size, PROT_READ | PROT_EXEC)) {
            NSLog(@"mprotect failed\n");
        }
        vm_prot_t a, b;
        mach_vm_address_t target = jumptable_addr;
        ret = mach_vm_remap(mach_task_self(), &target, page_size, 0, VM_FLAGS_OVERWRITE, mach_task_self(), (mach_vm_address_t) new_page, 1, &a, &b,0);
        if (ret) {
            NSLog(@"vm_remap failed:%d\n",ret);
        }
        munmap(new_page, page_size);
#endif
        i++;
    }
    /* second executeEffects */
    i = 0;

    /* get function address */
    void *real_sym = get_addr(handle, JSC_PATH, pub_sym, "__ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE", executeEffects_syms[i]);
    if(real_sym == NULL)
    {
        NSLog(@"Unable to find symbol %s! Abort\n", executeEffects_syms[i]);
        return;
    }
    NSLog(@"addr: %p \n", real_sym);

    /* install function hook */
    MSHookFunction(real_sym, &executeEffects_hook_inplace, &executeEffects_original_inplace);

    i++;

    /* get function address */
    real_sym = get_addr(handle, JSC_PATH, pub_sym, "__ZNK3JSC2B37Effects4dumpERN3WTF11PrintStreamE", executeEffects_syms[i]);
    if(real_sym == NULL)
    {
        NSLog(@"Unable to find symbol %s! Abort\n", executeEffects_syms[i]);
        return;
    }
    NSLog(@"addr: %p \n", real_sym);

    /* install function hook */
    MSHookFunction(real_sym, &executeEffects_hook_attail, &executeEffects_original_attail);
}

// From iometa, thx sig

// internal stuff I don't even understand :p
// only used by DecodeBitMasks
static inline uint64_t Ones(uint8_t len)
{
    return (((1ULL << ((len & 0x40) >> 1)) - 1) << 32) | ((1ULL << (len & 0x3f)) - 1);
}

// implementation of DecodeBitMasks from the ARM PDF
uint64_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits)
{
    uint8_t len = (N << 6) | (~imms & 0x3f);

    len = (len & (1 << 6)) ? 6 : (len & (1 << 5)) ? 5 : (len & (1 << 4)) ? 4 : (len & (1 << 3)) ? 3 : (len & (1 << 2)) ? 2 : (len & (1 << 1)) ? 1 : (len & (1 << 0)) ? 0 : -1;
    uint64_t levels = Ones(len);
    uint64_t S = imms & levels;
    uint64_t R = immr & levels;
    uint8_t esize = 1 << len;
    uint64_t welem = Ones(S + 1);
    uint64_t wmask = (welem >> R) | ((welem & Ones(R % esize)) << (esize - (R % esize)));
    while(esize < bits)
    {
        wmask |= wmask << esize;
        esize <<= 1;
    }
    return wmask;
}

// searches for an arm64 generated jumptable
// which looks like the instructions seen below
// allows some unknown instruction between them (change max_inbetween_instruction to allow more/less)
// search 0x1000 instructions before it stops
uint64_t get_jumptable(void *func_start, uint16_t *max_val)
{
    /* we search for something like this:
     * - mov <reg1>, 0x3ff => as that is typical for the NodeType value
     * - and <reg3>,<reg1>,<reg2> or and <reg3>,<reg2>,<reg1>
     * This can also be represented as:
     * - and <reg3>, <reg1>, 0x3ff
     *
     * - cmp <reg3>, <intermidiate> => the intermidiate could change between version so we just search for the instruction
     * - bhi <some addr> => jumps if the number is outside of the switch case range
     * - adrp <reg4>, <some addr>
     * - add <reg4>, <reg4>, <some value> => we need to get the value of reg4 now as this is our jumptable address
     * - ldrb <reg5>,[<reg4>,<reg3>,uxtw] (can also be ldrsw)
     * - adr <reg6>, <some value>
     * - add <reg7>, <reg6>, <reg5>, (sxtb #2)
     * - br <reg7>
     */

// check if bit is set
#define CHECK_BIT(value, nthbit) ((value >> nthbit) & 1)
// gets the value at a certain address
#define get_value_at_address(addr, type) (*((type*)addr))
// alias for get_value_at_address
#define get_val(addr, type) get_value_at_address(addr, type)
// alias for CB using the search_ptr
#define CB(n) (CHECK_BIT(get_val(search_ptr, uint32_t), n))
// alias for get_val but with a mask and using search_ptr
#define get_inner_val(shift, mask) ((get_val(search_ptr, uint32_t) >> shift) & mask)
// get the destination register
#define get_rd() (get_inner_val(0, 0x1f)) // 1f == b11111
// move the memory pointer
#define pointer_minus() search_ptr -= sizeof(uint32_t);
#define pointer_plus() search_ptr += sizeof(uint32_t);

    uint64_t search_ptr = (uint64_t)func_start;

    pointer_minus();     // this is need because the first instruction in the while loop will move the memory pointer again, easier for, because then I can just call continue to get to the next instruction
    long long max_search = 0x1000;     // how long we should search for a jumptable
    uint64_t max_inbetween_instructions;     // how many instruction can be between the real jumptable code instruction we are trying to find
    uint64_t jumptable_addr = 0x0;     // return value
    while(max_search)
    {
        //NSLog(@"value: %x\n",get_val(search_ptr,uint32_t));
        pointer_plus();
        max_search--;
        max_inbetween_instructions = 20;         // maximum number of instruction the finder will skip between the two real instruction which need to be found, zero is the best value for this, but the compiler sometimes does some weird shit so...

        uint8_t and_rd = 0xff;         // needs to be defind here if we jump in the else case of the move

        /* check for the mov */
        /* turns out the mov is accually a movz */
        uint8_t movz_rd = 0xff;         // set 0xff, cause RD can be max 0x1f
        if(         // sf can be 0 or 1
            CB(30) && !CB(29) && CB(28) && !CB(27) & !CB(26) && CB(25) && !CB(24) && CB(23)             // opc
            // hw doesn't matter (should be zero?)
            // 20-5 is imm16
            // 4-0 is Rd
            )
        {
            movz_rd = get_rd();
            uint16_t imm = get_inner_val(5, 0xffff);
            NSLog(@"Found movz [x/w]%d, %x\n", movz_rd, imm);
            if(imm != 0x3ff)
            {
                NSLog(@"Wrong imm! Abort\n");
                continue;
            }
            pointer_plus();
            /* check for the and */
            while(!(             // sf doesn't matter
                      !CB(30) && !CB(29) && !CB(28) && CB(27) && !CB(26) && CB(25) && !CB(24) &&           // opc
                      // shift 2 bits
                      !CB(21)           // N
                      // 20-16 Rm
                      // 15-10 imm6
                      // 9-5 Rn
                      // 4-0 Rd
                      ))
            {
                max_inbetween_instructions--;
                if(max_inbetween_instructions == 0)
                {
                    continue;
                }
                pointer_plus();
            }
            uint8_t and_rm = get_inner_val(16, 0x1f);
            uint8_t and_rn = get_inner_val(5, 0x1f);
            and_rd = get_rd();
            NSLog(@"Found and [x/w]%d, [x/w]%d, [x/w]%d\n", and_rd, and_rn, and_rm);
            if(and_rm != movz_rd && and_rn != movz_rd)
            {
                NSLog(@"The and doesn't match the right regs! Abort\n");
                continue;
            }
            /* and with imm (doesn't have the move)*/
        }
        else if(          // sf doesn't matter
            !CB(30) && !CB(29) && CB(28) && !CB(27) && !CB(26) && CB(25) && !CB(24) && !CB(23)             // opc
            // N
            // 21 - 16 immr
            // 15 - 10 imms
            // 9 - 5 Rn
            // 4 - 0 Rd
            )
        {
            and_rd = get_rd();
            uint64_t imm = DecodeBitMasks(CB(22), get_inner_val(10, 0x1f), get_inner_val(16, 0x1f), 32 << CB(31));
            NSLog(@"Found an and which doesn't use a reg (rd = [x/w]%d, imm=0x%llx)\n", and_rd, imm);
            if(imm != 0x3ff)
            {
                NSLog(@"Wrong imm! Abort\n");
                continue;
            }
        }
        else
        {
            continue;
        }                        // no movz;and and no and with an imm

        pointer_plus();
        /* check for the cmp */
        while(!(         // sf doesn't matter
                  CB(30) && CB(29) && CB(28) && !CB(27) && !CB(26) && !CB(25) && CB(24) &&
                  // shift doesn't matter (2 bits)
                  // 21 - 10 imm12
                  // 9-5 Rn
                  get_rd() == 0x1f
                  ))
        {
            max_inbetween_instructions--;
            if(max_inbetween_instructions == 0)
            {
                continue;
            }
            pointer_plus();
        }
        uint8_t cmp_rn = get_inner_val(5, 0x1f);
        uint64_t imm = get_inner_val(10, 0xfff);
        if(max_val != NULL)
        {
            *max_val = imm;
        }
        NSLog(@"Found cmp[x/w]%d, 0x%llx\n", cmp_rn, imm);
        if(cmp_rn != and_rd)
        {
            NSLog(@"The cmp uses the wrong reg! Abort\n");
            continue;
        }
        pointer_plus();
        /* check for the bhi */
        while(!(!CB(31) && CB(30) && !CB(29) && CB(28) && !CB(27) && CB(26) && !CB(25) && !CB(24) &&          // branch opcode
                // 23 - 5 imm19
                !CB(4) &&         // has to be not set, don't know why
                CB(3) && !CB(2) && !CB(1) && !CB(0)         // the condition, in this case high (see the armv8 manuel and search for condition codes)
                ))
        {
            max_inbetween_instructions--;
            if(max_inbetween_instructions == 0)
            {
                continue;
            }
            pointer_plus();
        }
        NSLog(@"Found bhi\n");

        pointer_plus();

        /* check for the adrp */
        uint8_t adrp_rd = 0xff;
        uint64_t adrp_imm = 0;
        while(!(CB(31) &&         // first bit of the opcode
                // 2 bits for immlo (wtf arm)
                CB(28) && !CB(27) && !CB(26) && !CB(25) && !CB(24)
                // 23-5 is the rest of the imm
                // 4-0 is rd
                ))
        {
            max_inbetween_instructions--;
            if(max_inbetween_instructions == 0)
            {
                continue;
            }
            pointer_plus();
        }
        adrp_rd = get_rd();

        int scale = CB(31) ? 12 : 0;
        uint64_t immlo = get_inner_val(29, 0x3);
        uint64_t immhi = get_inner_val(5, 0x3fff);
        adrp_imm = ((uint64_t)(immlo | (immhi << 2))) << (64 - 21) >> (64 - 21 - scale);
        jumptable_addr = (search_ptr & 0xffffffffffff0000) + adrp_imm;
        NSLog(@"Found adrp, result is saved into [x/w]%d, address is pc mod 0x1000 + 0x%llx (%llx)\n", adrp_rd, adrp_imm, jumptable_addr);

        pointer_plus();

        /* check for the add to adjust the adrp */
        uint8_t adrp_add_rd = 0xff;
        while(!(         // sf doesn't matter
                  !CB(30) && !CB(29) && CB(28) && !CB(27) && !CB(26) && !CB(25) && CB(24)
                  // shift 2 bits
                  // imm 21-10
                  // Rn 9-5
                  // Rd 4-0
                  ))
        {
            max_inbetween_instructions--;
            if(max_inbetween_instructions == 0)
            {
                continue;
            }
            pointer_plus();
        }
        adrp_add_rd = get_rd();
        uint8_t add_rn = get_inner_val(5, 0x1f);
        imm = get_inner_val(10, 0xfff);         // ignore shift here... prob bad (TODO: add shift support here)
        jumptable_addr += imm;
        NSLog(@"Found add [x/w]%d, [x/w]%d, 0x%llx\n", adrp_add_rd, add_rn, imm);
        if(add_rn != adrp_rd)
        {
            NSLog(@"add uses the wrong reg! Abort\n");
            continue;
        }
        pointer_plus();

        // from here on I didn't wanted fuzzyness anymore, if that turns out to be a problem I will add the loops here too, but I think it's saver like that

        /* check for the ldrb */
        uint8_t ldrb_rt = 0xff;
        if(!CB(31) && !CB(30) && CB(29) && CB(28) && CB(27) && !CB(26) && !CB(25) && !CB(24) && !CB(23) && CB(22) && CB(21) &&          // opcode
           // 20-16 Rm
           // 15-13 options (we could check here, but I'm not to sure if the compilter will always generate code with the same options...)
           // 1bit S
           CB(11) && !CB(10)
           // 9-5 Rn
           // 4-0 Rt
           )
        {
            uint8_t ldrb_rn = get_inner_val(5, 0x1f);
            uint8_t ldrb_rm = get_inner_val(16, 0x1f);
            ldrb_rt = get_rd();
            NSLog(@"Found ldrb [x/w]%d, [[x/w]%d,[x/w]%d]\n", ldrb_rt, ldrb_rm, ldrb_rn);
            if(ldrb_rn != adrp_add_rd || ldrb_rm != and_rd)
            {
                NSLog(@"ldrb registers aren't matching! Abort\n");
                continue;
            }
        }
        else
        {
            /* check for ldrsw as it's used sometimes */
            if(CB(31) && !CB(30) && CB(29) && CB(28) && CB(27) && !CB(26) && !CB(25) && !CB(24) && CB(23) && !CB(22) && CB(21) &&
               //20 - 16 Rm
               //15 - 13 option
               //12 S
               CB(11) && !CB(10)
               // 9 - 5 Rn
               // 4 - 0 Rt
               )
            {
                uint8_t ldrsw_rn = get_inner_val(5, 0x1f);
                uint8_t ldrsw_rm = get_inner_val(16, 0x1f);
                ldrb_rt = get_rd();
                NSLog(@"Found ldrsw [x/w]%d, [[x/w]%d,[x/w]%d]\n", ldrb_rt, ldrsw_rm, ldrsw_rn);
                if(ldrsw_rn != adrp_add_rd || ldrsw_rm != and_rd)
                {
                    NSLog(@"ldrsw registers aren't matching! Abort\n");
                    continue;
                }
            }
            else
            {
                continue;
            }
        }
        pointer_plus();

        /* check for the adr */
        /* sometimes this is not there, so we might skip it */
        uint8_t adr_rd = 0xff;
        if(!CB(31) &&
           // 2 bits for the immlo
           CB(28) && !CB(27) && !CB(26) && !CB(25) && !CB(24)
           // 23-5 immhi
           // 4-0 rd
           )
        {
            adr_rd = get_rd();
            NSLog(@"Found adr [x/w]%d, <some value>\n", adr_rd);
            pointer_plus();
        }
        /* check for the add */
        uint8_t adr_add_rd = 0xff;
        if(         // sf doesn't matter
            !CB(30) && !CB(29) && !CB(28) && CB(27) && !CB(26) && CB(25) && CB(24) && !CB(23) && !CB(22)             // && CB(21) if 21 is set the instruction is an and (extended register) while if it's not it's (shifted regiter)
            // 20 - 16 Rm
            // 15 - 13 option
            // 12 - 10 imm3
            //  9 -  5 Rn
            //  4 -  9 Rd
            )
        {
            adr_add_rd = get_rd();
            uint8_t add_rn = get_inner_val(5, 0x1f);
            uint8_t add_rm = get_inner_val(16, 0x1f);
            NSLog(@"Found add [x/w]%d, [x/w]%d, [x/w]%d\n", adr_add_rd, add_rn, add_rm);
            if(adr_rd != 0xff && add_rn != adr_rd && add_rm != adr_rd)
            {
                NSLog(@"add uses the wrong reg! Abort\n");
                continue;
            }
            else if(adr_rd == 0xff)
            {
                // no relativ addressing; now the two operands should be the result from the ldrsw/b and the base of the jumptable (result from the adrp_add)
                if(!((ldrb_rt == add_rn && adrp_add_rd == add_rm) || (ldrb_rt == add_rm && adrp_add_rd == add_rn)))
                {
                    NSLog(@"add uses the wrongs regs! Abort\n");
                    continue;
                }
            }
        }
        else
        {
            continue;
        }
        pointer_plus();
        /* check for the br */
        if(CB(31) && CB(30) && !CB(29) && CB(28) && !CB(27) && CB(26) && CB(25) && !CB(24) && !CB(23) && !CB(22) && !CB(21) &&
           CB(20) && CB(19) && CB(18) && CB(17) && CB(16) && !CB(15) & !CB(14) && !CB(13) && !CB(12) && !CB(11) && !CB(10) &&              // opcode
           // 9-5 Rn
           !CB(4) && !CB(3) && !CB(2) && !CB(1) && !CB(0)              // Rm
           )
        {
            uint8_t br_rn = get_inner_val(5, 0x1f);
            NSLog(@"Found br x%d\n", br_rn);
            if(br_rn != adr_add_rd)
            {
                NSLog(@"Wrong reg for br! Abort\n");
                continue;
            }
#ifdef DEBUG
            NSLog(@"%d instructions left to skip\n", max_inbetween_instructions);
#endif
            return jumptable_addr;
        }
    }
    return 0;
}

// Private symbol finder from https://github.com/Siguza/ios-kern-utils/blob/master/src/lib/libkern.c#L381-L518 Thank you very much Siguza!
// I renamed some vars and added some printfs
typedef struct
{
    char magic[16];
    uint32_t segoff;
    uint32_t nsegs;
    uint32_t _unused32[2];
    uint64_t _unused64[5];
    uint64_t localoff;
    uint64_t nlocals;
} dysc_hdr_t;

typedef struct
{
    uint64_t addr;
    uint64_t size;
    uint64_t fileoff;
    vm_prot_t maxprot;
    vm_prot_t initprot;
} dysc_seg_t;

typedef struct
{
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
} dysc_local_info_t;

typedef struct
{
    uint32_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} dysc_local_entry_t;

#define CMD_ITERATE(hdr, cmd) \
    for(struct load_command *cmd = (struct load_command*)((hdr) + 1), \
        *end = (struct load_command*)((char*)cmd + (hdr)->sizeofcmds); \
        cmd < end; \
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize))

void *cache = NULL;

void* get_addr(void *handler, char *dylib_path, void *pub_sym_addr, char *pub_sym_name,  char *real_name)
{
    typedef struct mach_header_64 mach_hdr_t;
    struct nlist_64 *symtab = NULL;
    const char *strtab = NULL;
    uintptr_t cache_base = 0;
    int fd = 0;
    struct stat s = {0};
    if(cache == NULL)
    {
        // TODO: This will have to be reworked once there are more 64-bit sub-archs than just arm64.
        //       It's probably gonna be easiest to use PROC_PIDREGIONPATHINFO, at least that gives the full path on iOS.
        fd = open("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64", O_RDONLY);
        if(fd == -1)
        {
            NSLog(@"Failed to open dyld_shared_cache_arm64 for reading: %s\n", strerror(errno));
            goto out;
        }
        if(fstat(fd, &s) != 0)
        {
            NSLog(@"Failed to stat(dyld_shared_cache_arm64): %s\n", strerror(errno));
            goto out;
        }
        cache = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if(cache == MAP_FAILED)
        {
            NSLog(@"Failed to map dyld_shared_cache_arm64 to memory: %s\n", strerror(errno));
            cache = NULL;
            goto out;
        }
    }
    cache_base = (uintptr_t)cache;
    NSLog(@"dyld_shared_cache is at 0x%lx", cache_base);

    dysc_hdr_t *cache_hdr = cache;
    if(cache_hdr->nlocals == 0)
    {
        NSLog(@"Cache contains no local symbols.\n");
        goto out;
    }
    dysc_local_info_t *local_info = (dysc_local_info_t*)(cache_base + cache_hdr->localoff);
    dysc_local_entry_t *local_entries = (dysc_local_entry_t*)((uintptr_t)local_info + local_info->entriesOffset);
    NSLog(@"cache_hdr: 0x%lx local_info: 0x%lx local_entries: 0x%lx\n", (uintptr_t)cache_hdr, (uintptr_t)local_info, (uintptr_t)local_entries);
    dysc_local_entry_t *local_entry = NULL;
    struct nlist_64 *local_symtab = (struct nlist_64*)((uintptr_t)local_info + local_info->nlistOffset);
    const char *local_strtab = (const char*)((uintptr_t)local_info + local_info->stringsOffset);
    mach_hdr_t *searched_dylib_hdr = NULL;
    for(size_t i = 0; i < local_info->entriesCount; ++i)
    {
        mach_hdr_t *dylib_hdr = (mach_hdr_t*)(cache_base + local_entries[i].dylibOffset);
        CMD_ITERATE(dylib_hdr, cmd)
        {
            if(cmd->cmd == LC_ID_DYLIB && strcmp((char*)cmd + ((struct dylib_command*)cmd)->dylib.name.offset, dylib_path) == 0)
            {
                searched_dylib_hdr = dylib_hdr;
                local_entry = &local_entries[i];
                local_symtab = &local_symtab[local_entries[i].nlistStartIndex];
                goto found;
            }
        }
    }
    NSLog(@"Failed to find local symbols for the Libary.\n");
    goto out;

found:;
    NSLog(@"header: 0x%lx  local_symtab: 0x%lx local_strtab: 0x%lx\n", (uintptr_t)searched_dylib_hdr, (uintptr_t)local_symtab, (uintptr_t)local_strtab);
    uint64_t real_addr = 0;
    for(size_t i = 0; i < local_entry->nlistCount; ++i)
    {
        const char *name = &local_strtab[local_symtab[i].n_un.n_strx];
        if(strcmp(name, real_name) == 0)
        {
            real_addr = local_symtab[i].n_value;
            break;
        }
    }
    struct symtab_command *symcmd = NULL;
    CMD_ITERATE(searched_dylib_hdr, cmd)
    {
        if(cmd->cmd == LC_SYMTAB)
        {
            symcmd = (struct symtab_command*)cmd;
            symtab = (struct nlist_64*)(cache_base + symcmd->symoff);
            strtab = (const char*)(cache_base + symcmd->stroff);
            break;
        }
    }
    NSLog(@"symcmd: %lx, symtab: %lx, strtab: %lx\n", (uintptr_t)symcmd, (uintptr_t)symtab, (uintptr_t)strtab);
    if(symcmd == NULL || symtab == NULL || strtab == NULL)
    {
        NSLog(@"Failed to find Lib symtab.\n");
        goto out;
    }
    uint64_t pub_sym_file_addr = 0;
    for(size_t i = 0; i < symcmd->nsyms; ++i)
    {
        const char *name = &strtab[symtab[i].n_un.n_strx];
        if(strcmp(name, pub_sym_name) == 0)
        {
            pub_sym_file_addr = symtab[i].n_value;
        }
    }
    return (void*)(pub_sym_addr - pub_sym_file_addr + real_addr);

out:
    return NULL;
}
