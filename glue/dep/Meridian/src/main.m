#ifndef HEADLESS

#include "jailbreak.h"

#import <Foundation/Foundation.h>

int main() {
    @autoreleasepool {
        NSLog(@"main has been called... time for some pwnage >:D");

        makeShitHappen();

        return 0;
    }
}

#endif
