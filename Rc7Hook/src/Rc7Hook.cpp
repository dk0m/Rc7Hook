#include <iostream>
#include "./Examples/examples.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("[-] Provide an Example to Run!\n");
        return -1;
    }

    const char* chosenExample = argv[1];

    if (!_stricmp(chosenExample, "MessageBoxHook")) {
        examples::runMessageBoxAHook();
    }
    else if (!_stricmp(chosenExample, "AmsiHook")) {
        examples::runAmsiHookExample();
    }
    else {
        printf("[-] Invalid Example.\n");
        return -1;
    }

}
