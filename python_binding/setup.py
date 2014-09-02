#!/usr/bin/env python

from distutils.core import setup, Extension
setup(name='brg',
      version='1.0',
      ext_modules=[Extension('brg', ['brgmodule.c', 'aeskey.c', 'aes_modes.c', 'aestab.c', 'aescrypt.c'], extra_compile_args=['-Wno-sequence-point'])],
     )
