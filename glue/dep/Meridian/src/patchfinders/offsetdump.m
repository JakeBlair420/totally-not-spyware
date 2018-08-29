//
//  offsetdump.m
//  Meridian
//
//  Created by Ben Sparkes on 30/03/2018.
//  Copyright © 2018 Ben Sparkes. All rights reserved.
//

#import <Foundation/Foundation.h>

#include "patchfinder64.h"
#include "offsetdump.h"

void dumpOffsetsToFile(offsets_t *offsets, uint64_t kernel_base, uint64_t kernel_slide) {
    NSData *blob = [NSData dataWithContentsOfFile:@"/meridian/offsets.plist"];
    NSMutableDictionary *offFile = [NSPropertyListSerialization propertyListWithData:blob
                                                                             options:NSPropertyListMutableContainers
                                                                              format:nil
                                                                               error:nil];

    // There is probably a better way than doing this all manually, but ¯\_(ツ)_/¯
    // We don't really need to log *all* of these, but better safe than PR'ing, right?
    // See the amfid patch for an example of using this (amfid/main.m)

    offFile[@"Base"]                           = [NSString stringWithFormat:@"0x%016llx", offsets->base];
    offFile[@"KernelBase"]                     = [NSString stringWithFormat:@"0x%016llx", kernel_base];
    offFile[@"KernelSlide"]                    = [NSString stringWithFormat:@"0x%016llx", kernel_slide];

    offFile[@"SizeOfTask"]                     = [NSString stringWithFormat:@"0x%016llx", offsets->sizeof_task];
    offFile[@"TaskItkSelf"]                    = [NSString stringWithFormat:@"0x%016llx", offsets->task_itk_self];
    offFile[@"TaskItkRegistered"]              = [NSString stringWithFormat:@"0x%016llx", offsets->task_itk_registered];
    offFile[@"TaskBsdInfo"]                    = [NSString stringWithFormat:@"0x%016llx", offsets->task_bsd_info];
    offFile[@"ProcUcred"]                      = [NSString stringWithFormat:@"0x%016llx", offsets->proc_ucred];
    offFile[@"VmMapHdr"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->vm_map_hdr];
    offFile[@"IpcSpaceIsTask"]                 = [NSString stringWithFormat:@"0x%016llx", offsets->ipc_space_is_task];
    offFile[@"RealhostSpecial"]                = [NSString stringWithFormat:@"0x%016llx", offsets->realhost_special];
    offFile[@"IOUserClientIPC"]                = [NSString stringWithFormat:@"0x%016llx", offsets->iouserclient_ipc];
    offFile[@"VtabGetRetainCount"]             = [NSString stringWithFormat:@"0x%016llx", offsets->vtab_get_retain_count];
    offFile[@"VtabGetExternalTrapForIndex"]    = [NSString stringWithFormat:@"0x%016llx", offsets->vtab_get_external_trap_for_index];

    offFile[@"ZoneMap"]                        = [NSString stringWithFormat:@"0x%016llx", offsets->zone_map];
    offFile[@"KernelMap"]                      = [NSString stringWithFormat:@"0x%016llx", offsets->kernel_map];
    offFile[@"KernelTask"]                     = [NSString stringWithFormat:@"0x%016llx", offsets->kernel_task];
    offFile[@"RealHost"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->realhost];

    offFile[@"CopyIn"]                         = [NSString stringWithFormat:@"0x%016llx", offsets->copyin];
    offFile[@"CopyOut"]                        = [NSString stringWithFormat:@"0x%016llx", offsets->copyout];
    offFile[@"Chgproccnt"]                     = [NSString stringWithFormat:@"0x%016llx", offsets->chgproccnt];
    offFile[@"KauthCredRef"]                   = [NSString stringWithFormat:@"0x%016llx", offsets->kauth_cred_ref];
    offFile[@"IpcPortAllocSpecial"]            = [NSString stringWithFormat:@"0x%016llx", offsets->ipc_port_alloc_special];
    offFile[@"IpcKobjectSet"]                  = [NSString stringWithFormat:@"0x%016llx", offsets->ipc_kobject_set];
    offFile[@"IpcPortMakeSend"]                = [NSString stringWithFormat:@"0x%016llx", offsets->ipc_port_make_send];
    offFile[@"OSSerializerSerialize"]          = [NSString stringWithFormat:@"0x%016llx", offsets->osserializer_serialize];
    offFile[@"RopLDR"]                         = [NSString stringWithFormat:@"0x%016llx", offsets->rop_ldr_x0_x0_0x10];

    offFile[@"RootVnode"]                      = [NSString stringWithFormat:@"0x%016llx", offsets->root_vnode];

    offFile[@"VfsContextCurrent"]              = [NSString stringWithFormat:@"0x%016llx", offsets->vfs_context_current];
    offFile[@"VnodeGetFromFD"]                 = [NSString stringWithFormat:@"0x%016llx", offsets->vnode_getfromfd];
    offFile[@"VnodeGetAttr"]                   = [NSString stringWithFormat:@"0x%016llx", offsets->vnode_getattr];
    offFile[@"VnodePut"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->vnode_put];
    offFile[@"CSBlobEntDictSet"]               = [NSString stringWithFormat:@"0x%016llx", offsets->csblob_ent_dict_set];
    offFile[@"SHA1Init"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->sha1_init];
    offFile[@"SHA1Update"]                     = [NSString stringWithFormat:@"0x%016llx", offsets->sha1_update];
    offFile[@"SHA1Final"]                      = [NSString stringWithFormat:@"0x%016llx", offsets->sha1_final];

    offFile[@"ProcFind"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->proc_find];
    offFile[@"ProcName"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->proc_name];
    offFile[@"ProcRele"]                       = [NSString stringWithFormat:@"0x%016llx", offsets->proc_rele];

    offFile[@"AddGadgetRet"]                   = [NSString stringWithFormat:@"0x%016llx", find_add_x0_x0_0x40_ret()];
    offFile[@"OSBooleanTrue"]                  = [NSString stringWithFormat:@"0x%016llx", find_OSBoolean_True()];
    offFile[@"OSBooleanFalse"]                 = [NSString stringWithFormat:@"0x%016llx", find_OSBoolean_False()];
    offFile[@"OSUnserializeXML"]               = [NSString stringWithFormat:@"0x%016llx", find_OSUnserializeXML()];
    offFile[@"Smalloc"]                        = [NSString stringWithFormat:@"0x%016llx", find_smalloc()];
    offFile[@"CSFindMD"]                       = [NSString stringWithFormat:@"0x%016llx", find_cs_find_md(offsets->sha1_init + kernel_slide,
                                                                                                           offsets->sha1_update + kernel_slide,
                                                                                                           offsets->sha1_final + kernel_slide)];

    [offFile writeToFile:@"/meridian/offsets.plist" atomically:YES];
}
