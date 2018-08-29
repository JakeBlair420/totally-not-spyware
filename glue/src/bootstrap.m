#include <errno.h>
#include <fcntl.h>              // open
#include <stdio.h>              // asprintf
#include <stdlib.h>             // free
#include <string.h>             // strerror
#include <unistd.h>             // chdir, fchdir, close
#include <sys/stat.h>           // mkdir
#include <mach/mach.h>
#include <archive.h>            // archive_*

#include "common.h"             // LOG
#include "dl.h"                 // downloadFile

#include "bootstrap.h"

#define BASE_URL "http://192.168.2.1:8080/bootstrap/"

int downloadAndExtract(const char *file, const char *path, const char *dir)
{
    int retval = -1,
        fd = -1;
    char *url = NULL;
    struct archive *ar  = NULL,
                   *dsk = NULL;

    asprintf(&url, BASE_URL "%s", file);
    if(!url)
    {
        LOG("asprintf: %s", strerror(errno));
        goto out;
    }

    int r = downloadFile(url, path);
    if(r != 0)
    {
        goto out;
    }

    fd = open(".", O_RDONLY);
    if(fd == -1)
    {

        goto out;
    }
    r = mkdir(dir, 0755);
    if(r != 0)
    {
        LOG("mkdir: %s", strerror(errno));
        goto out;
    }
    r = chdir(dir);
    if(r != 0)
    {
        LOG("chdir: %s", strerror(errno));
        goto out;
    }

    ar = archive_read_new();
    if(!ar)
    {
        LOG("archive_read_new failed");
        goto out0;
    }
    dsk = archive_write_disk_new();
    if(!dsk)
    {
        LOG("archive_write_disk_new failed");
        goto out0;
    }
#define ASSERT(lbl, hndl, name, code) \
do \
{ \
    if((code) != ARCHIVE_OK) \
    { \
        LOG(name ": %s", archive_error_string(hndl)); \
        goto lbl; \
    } \
} while(0)
    ASSERT(out0, dsk, "archive_write_disk_set_options", archive_write_disk_set_options(dsk, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS));
    ASSERT(out0,  ar, "archive_read_support_format_tar", archive_read_support_format_tar(ar));
    ASSERT(out0,  ar, "archive_read_support_compression_xz", archive_read_support_compression_xz(ar));
    ASSERT(out0,  ar, "archive_read_open_filename", archive_read_open_filename(ar, path, 0x10000));
    while(1)
    {
        struct archive_entry *ent;
        r = archive_read_next_header(ar, &ent);
        if(r == ARCHIVE_EOF)
        {
            break;
        }
        ASSERT(out1, ar, "archive_read_next_header2", r);
        ASSERT(out1, ar, "archive_read_extract2", archive_read_extract2(ar, ent, dsk));
    }

    retval = 0;
out1:;
    archive_read_close(ar);
out0:;
    fchdir(fd);
out:;
    if(dsk)
    {
        archive_write_finish(dsk);
    }
    if(ar)
    {
        archive_read_finish(ar);
    }
    if(fd != -1)
    {
        close(fd);
    }
    if(url)
    {
        free(url);
    }
    return retval;
}
