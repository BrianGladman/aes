
#include "aes.h"

int __stdcall DllMain()
{
    aes_init();
    return 1;
}
