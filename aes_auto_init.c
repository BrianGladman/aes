/*
-----------------------------------------------------------------------------
Copyright 2015 Henrik S. Gaßmann

Distributed under the Boost Software License, Version 1.0.
(See accompanying file BOOST.LICENSE or http://www.boost.org/LICENSE_1_0.txt)
-----------------------------------------------------------------------------
*/

#include "aes.h"
#include "aesopt.h"

#if defined(FIXED_TABLES)

#if defined(_MSC_VER)
#pragma section(".CRT$XCU",read)
#define DEFINE_INITIALIZER(name) \
    void __cdecl name (); \
    __declspec(allocate(".CRT$XCU")) void (__cdecl* name##_ptr)() = name; \
    void __cdecl name ()
#elif (defined(__GNUC__) || defined(__clang__))
#define DEFINE_INITIALIZER(name) __attribute__((constructor)) void name ()
#else
#error "Auto initialization has not been implemented for your compiler."
#endif

DEFINE_INITIALIZER(aes_auto_init)
{
    aes_init();
}

#endif
