
#import <Foundation/Foundation.h>

#include "common.h"
#include "preferences.h"

#define ELECTRA_GENERATOR "0x62b2fe45ea2c3324"

const char *BootNonce;

enum DropbearPortEnum DropbearPortSetting;

bool StartDropbear;
bool StartLaunchDaemons;
bool TweaksEnabled;

NSDictionary *getDefaultPreferences()
{
    NSMutableDictionary *prefsDict = [[NSMutableDictionary alloc] init];

    [prefsDict setObject:@ELECTRA_GENERATOR forKey:@"BootNonce"];
    [prefsDict setObject:@"Both" forKey:@"DropbearPort"];
    [prefsDict setObject:@YES forKey:@"StartDropbear"];
    [prefsDict setObject:@YES forKey:@"StartLaunchDaemons"];
    [prefsDict setObject:@YES forKey:@"TweaksEnabled"];

    return (NSDictionary *)prefsDict;
}

void initAllPreferences()
{
    NSString *prefsFilePath = @"/meridian/preferences.plist";

    NSDictionary *prefsDict = [NSDictionary dictionaryWithContentsOfFile:prefsFilePath];

    if (prefsDict == nil)
    {
        prefsDict = getDefaultPreferences();

        [prefsDict writeToFile:prefsFilePath atomically:NO];

        LOG("created a new preferences file: %s", [prefsFilePath UTF8String]);
    }

    if (prefsDict[@"BootNonce"] == nil)
    {
        LOG("BootNonce field found, using default...");
        BootNonce = strdup(ELECTRA_GENERATOR);
    }
    else if ([prefsDict[@"BootNonce"] rangeOfString:@"^0x[0-9a-fA-F]+$" options:NSRegularExpressionSearch].location != NSNotFound)
    {
        LOG("failed to set boot nonce: invalid string '%s'. using default...", [prefsDict[@"BootNonce"] UTF8String]);
        BootNonce = strdup(ELECTRA_GENERATOR);
    }
    else
    {
        BootNonce = [prefsDict[@"BootNonce"] UTF8String];
    }
    LOG("using boot nonce %s", BootNonce);

    if (prefsDict[@"DropbearPort"] == nil)
    {
        LOG("DropbearPort field not found, using default (both)");
        DropbearPortSetting = DropbearPortBoth;
    }
    else
    {
        NSString *dropbearPort = [prefsDict[@"DropbearPort"] lowercaseString];
        if ([dropbearPort isEqual:@"22"])
        {
            LOG("using dropbear port 22");
            DropbearPortSetting = DropbearPort22;
        }
        else if ([dropbearPort isEqual:@"2222"])
        {
            LOG("using dropbear port 2222");
            DropbearPortSetting = DropbearPort2222;
        }
        else 
        {
            LOG("using dropbear port both");
            DropbearPortSetting = DropbearPortBoth;
        }
    }

    if (prefsDict[@"StartDropbear"] == nil)
    {
        LOG("StartDropbear field not found, using deafult...");
        StartDropbear = true;
    }
    else
    {
        StartDropbear = [prefsDict[@"StartDropbear"] boolValue];
    }
    LOG("start dropbear: %d", StartDropbear);

    if (prefsDict[@"StartLaunchDaemons"] == nil)
    {
        LOG("StartLaunchDaemons field not found, using default...");
        StartLaunchDaemons = true;
    }
    else
    {
        StartLaunchDaemons = [prefsDict[@"StartLaunchDaemons"] boolValue];
    }
    LOG("start launch daemons: %d", StartLaunchDaemons);

    if (prefsDict[@"TweaksEnabled"] == nil)
    {
        LOG("TweaksEnabled field not found, using default...");
        TweaksEnabled = true;
    }
    else
    {
        TweaksEnabled = [prefsDict[@"TweaksEnabled"] boolValue];
    }
    LOG("tweaks enabled: %d", TweaksEnabled);
}
