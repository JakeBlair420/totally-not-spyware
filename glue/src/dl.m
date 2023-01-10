#include <errno.h>
#include <stdio.h>              // fopen, fwrite, fclose
#include <string.h>             // strerror
#include <curl/curl.h>
#include <Foundation/Foundation.h>

#include "dl.h"

#ifndef LOG
#   define LOG(str, args...) do { NSLog(@str "\n", ##args); } while(0)
#endif

static size_t write_callback(char *ptr, size_t size, size_t times, void *f)
{
    return fwrite(ptr, size, times, f);
}

static int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    LOG("%ld%%", (dlnow * 100) / dltotal);
    return 0;
}

int downloadFile(const char *url, const char *file)
{
    LOG("Downloading %s...", url);
    int retval = -1;
    FILE *f = NULL;
    CURL *curl = NULL;

    f = fopen(file, "wb");
    if(!f)
    {
        LOG("fopen: %s", strerror(errno));
        goto out;
    }

    curl = curl_easy_init();
    if(!curl)
    {
        LOG("curl_easy_init failed");
        goto out;
    }

#define ASSERT(name, code) \
do \
{ \
    CURLcode r = (code); \
    if(r != 0) \
    { \
        LOG(name ": %d", r); \
        goto out; \
    } \
} while(0)
    ASSERT("curl_easy_setopt(CURLOPT_URL)",              curl_easy_setopt(curl, CURLOPT_URL, url));
    ASSERT("curl_easy_setopt(CURLOPT_WRITEFUNCTION)",    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback));
    ASSERT("curl_easy_setopt(CURLOPT_WRITEDATA)",        curl_easy_setopt(curl, CURLOPT_WRITEDATA, f));
    ASSERT("curl_easy_setopt(CURLOPT_XFERINFOFUNCTION)", curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback));
    ASSERT("curl_easy_setopt(CURLOPT_NOPROGRESS)",       curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0));
    ASSERT("curl_easy_setopt(CURLOPT_FOLLOWLOCATION)",   curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1));

    ASSERT("curl_easy_perform", curl_easy_perform(curl));
#undef ASSERT

    retval = 0;
out:;
    if(curl)
    {
        curl_easy_cleanup(curl);
    }
    if(f)
    {
        fclose(f);
    }
    LOG("Download %s.", retval == 0 ? "complete" : "failed");
    return retval;
}
