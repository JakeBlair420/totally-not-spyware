
enum DropbearPortEnum
{
    DropbearPort22,
    DropbearPort2222,
    DropbearPortBoth
};

extern const char *BootNonce;

extern enum DropbearPortEnum DropbearPortSetting;

extern bool StartDropbear;
extern bool StartLaunchDaemons;
extern bool TweaksEnabled;

void initAllPreferences(void);
