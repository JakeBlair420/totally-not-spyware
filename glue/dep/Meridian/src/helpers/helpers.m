//
//  helpers.m
//  Meridian
//
//  Created by Ben Sparkes on 30/12/2017.
//  Copyright © 2017 Ben Sparkes. All rights reserved.
//

#include "helpers.h"
#include "kernel.h"
#include "amfi.h"
#include "jailbreak_daemonUser.h"
#include "iokit.h"
#include <dirent.h>
#include <unistd.h>
#include <dlfcn.h>
#include <spawn.h>
#include <sys/fcntl.h>
#include <sys/spawn.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#import <Foundation/Foundation.h>

int call_jailbreakd(int command, uint32_t pid) {
    mach_port_t jbd_port;
    if (bootstrap_look_up(bootstrap_port, "zone.sparkes.jailbreakd", &jbd_port) != 0) {
        return -1;
    }

    return jbd_call(jbd_port, command, pid);
}

uint64_t find_proc_by_name(char *name) {
    uint64_t proc = rk64(kernprocaddr + 0x08);

    while (proc) {
        char proc_name[40] = { 0 };

        kread(proc + 0x26c, proc_name, 40);

        if (!strcmp(name, proc_name)) {
            return proc;
        }

        proc = rk64(proc + 0x08);
    }

    return 0;
}

uint64_t find_proc_by_pid(uint32_t pid) {
    uint64_t proc = rk64(kernprocaddr + 0x08);

    while (proc) {
        uint32_t proc_pid = rk32(proc + 0x10);

        if (pid == proc_pid) {
            return proc;
        }

        proc = rk64(proc + 0x08);
    }

    return 0;
}

uint32_t get_pid_for_name(char *name) {
    uint64_t proc = find_proc_by_name(name);
    if (proc == 0) {
        return -1;
    }

    return rk32(proc + 0x10);
}

int uicache() {
    return execprog("/bin/uicache", NULL);
}

int start_launchdaemon(const char *path) {
    int ret = inject_trust("/bin/launchctl");
    if (ret != 0) {
        NSLog(@"Failed to inject trust to /bin/launchctl: %d", ret);
        return -30;
    }

    chmod(path, 0755);
    chown(path, 0, 0);
    return execprog("/bin/launchctl", (const char **)&(const char*[]) {
        "/bin/launchctl",
        "load",
        "-w",
        path,
        NULL
    });
}

int respring() {
    pid_t springBoard = get_pid_for_name("SpringBoard");
    if (springBoard == 0) {
        return 1;
    }

    kill(springBoard, 9);
    return 0;
}

int inject_library(uint32_t pid, const char *path) {
    mach_port_t task_port;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &task_port);
    if (ret != KERN_SUCCESS || task_port == MACH_PORT_NULL) {
        task_port = task_for_pid_workaround(pid);
        if (task_port == MACH_PORT_NULL) {
            NSLog(@"[injector] failed to get task for pid %d", pid);
            return ret;
        }
    }

    NSLog(@"[injector] got task port: %x", task_port);

    call_remote(task_port, dlopen, 2, REMOTE_CSTRING(path), REMOTE_LITERAL(RTLD_NOW));
    uint64_t error = call_remote(task_port, dlerror, 0);
    if (error != 0) {
        uint64_t len = call_remote(task_port, strlen, 1, REMOTE_LITERAL(error));
        char* local_cstring = malloc(len +  1);
        remote_read_overwrite(task_port, error, (uint64_t)local_cstring, len + 1);

        NSLog(@"[injector] error: %s", local_cstring);
        return -1;
    }

    return 0;
}

int killall(const char *procname, const char *kill) {
    return execprog(
        "/usr/bin/killall",
        (const char **)&(const char *[]) {
            "/usr/bin/killall",
            kill,
            procname,
            NULL
        });
}

int check_for_jailbreak() {
    int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

    uint32_t flags;
    csops(getpid(), 0, &flags, 0);

    return flags & CS_PLATFORM_BINARY;
}

// remember: returns 0 if file exists
int file_exists(const char *path) {
    return access(path, F_OK);
}

int extract_bundle_tar(const char *file_path) {
    if (file_exists(file_path) != 0) {
        LOG("Error, file was not found at path %s!", file_path);
        return -1;
    }

    return execprog(
        "/meridian/bootstrap/tar",
        (const char **)&(const char*[]) {
            "/meridian/bootstrap/tar",
            "--preserve-permissions",
            "--no-overwrite-dir",
            "-C",
            "/",
            "-xvf",
            file_path,
            NULL
        });
}

void touch_file(char *path) {
    fclose(fopen(path, "w+"));
}

void grant_csflags(uint32_t pid) {
    int tries = 3;
    while (tries-- > 0) {
        uint64_t proc = find_proc_by_pid(pid);
        if (proc == 0) {
            sleep(1);
            continue;
        }

        uint32_t csflags = rk32(proc + 0x2a8);
        csflags = (csflags |
                   CS_PLATFORM_BINARY |
                   CS_INSTALLER |
                   CS_GET_TASK_ALLOW)
                   & ~(CS_RESTRICT | CS_HARD);
        wk32(proc + 0x2a8, csflags);
        break;
    }
}

// creds to stek29 on this one
int execprog(const char *prog, const char* args[]) {
    if (args == NULL) {
        args = (const char **)&(const char*[]){ prog, NULL };
    }

    if (file_exists("/meridian") != 0) {
        mkdir("/meridian", 0755);
    }
    if (file_exists("/meridian/logs") != 0) {
        mkdir("/meridian/logs", 0755);
    }

    const char *logfile = [NSString stringWithFormat:@"/meridian/logs/%@-%lu",
                           [[NSMutableString stringWithUTF8String:prog] stringByReplacingOccurrencesOfString:@"/" withString:@"_"],
                           time(NULL)].UTF8String;

    NSString *prog_args = @"";
    for (const char **arg = args; *arg != NULL; ++arg) {
        prog_args = [prog_args stringByAppendingString:[NSString stringWithFormat:@"%s ", *arg]];
    }
    NSLog(@"[execprog] Spawning [ %@ ] to logfile [ %s ]", prog_args, logfile);

    int rv;
    posix_spawn_file_actions_t child_fd_actions;
    if ((rv = posix_spawn_file_actions_init (&child_fd_actions))) {
        perror ("posix_spawn_file_actions_init");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_addopen (&child_fd_actions, STDOUT_FILENO, logfile,
                                                O_WRONLY | O_CREAT | O_TRUNC, 0666))) {
        perror ("posix_spawn_file_actions_addopen");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_adddup2 (&child_fd_actions, STDOUT_FILENO, STDERR_FILENO))) {
        perror ("posix_spawn_file_actions_adddup2");
        return rv;
    }

    pid_t pd;
    if ((rv = posix_spawn(&pd, prog, &child_fd_actions, NULL, (char**)args, NULL))) {
        printf("posix_spawn error: %d (%s)\n", rv, strerror(rv));
        return rv;
    }

    NSLog(@"[execprog] Process spawned with pid %d", pd);

    grant_csflags(pd);

    int ret, status;
    do {
        ret = waitpid(pd, &status, 0);
        if (ret > 0) {
            NSLog(@"'%s' exited with %d (sig %d)\n", prog, WEXITSTATUS(status), WTERMSIG(status));
        } else if (errno != EINTR) {
            NSLog(@"waitpid error %d: %s\n", ret, strerror(errno));
        }
    } while (ret < 0 && errno == EINTR);

    char buf[65] = {0};
    int fd = open(logfile, O_RDONLY);
    if (fd == -1) {
        perror("open logfile");
        return 1;
    }

    close(fd);
    remove(logfile);
    return (int8_t)WEXITSTATUS(status);
}

#ifndef HEADLESS
// credits to tihmstar
void restart_device() {
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
    while (1) {
        IOConnectCallAsyncStructMethod(connect, 17, port, &references, 1, input, sizeof(input), NULL, NULL);
    }
}

// credits to tihmstar
double uptime() {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boottime, &len, NULL, 0) < 0) {
        return -1.0;
    }

    time_t bsec = boottime.tv_sec, csec = time(NULL);

    return difftime(csec, bsec);
}

// credits to tihmstar
void suspend_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                    exit(1);
                }
            }
        }
    }
}

// credits to tihmstar
void resume_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}
#endif
