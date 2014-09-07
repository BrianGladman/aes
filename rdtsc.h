/*
---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#ifndef RDTSC_H
#define RDTSC_H

#if defined( __GNUC__ )

#   if defined( __i386__ ) && defined( __ILP32__ ) /* x86 32-bit */
    __inline__ unsigned long long read_tsc(void)
    {
        unsigned long long tick;
        __asm__ __volatile__("rdtsc":"=A"(tick));
        return tick;
    }
#   elif defined( __x86_64__ ) && defined( __LP64__ ) /* x86 64-bit */
    __inline__ unsigned long long read_tsc(void)
    {
        unsigned int tickl, tickh;
        __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
        return ((unsigned long long)tickh << 32)|tickl;
    }
#   else
#   error Please define read_tsc() for your platform in rdtsc.h
#   endif

#elif defined( _WIN32 ) || defined( _WIN64 )

#   include <intrin.h>
#   pragma intrinsic( __rdtsc )

    __inline volatile unsigned long long read_tsc(void)
    {
        return __rdtsc();
    }

#else
#   error A high resolution timer is not available
#endif

#endif
