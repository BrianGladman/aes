#!/usr/bin/env python

from distutils.core import setup, Extension
setup(name='aes',
      version='1.0',
      ext_modules=[Extension('aes', ['brgmodule.c', '../aeskey.c', '../aes_modes.c', '../aestab.c', '../aescrypt.c'],
                             include_dirs=['..'], extra_compile_args=['-Wno-sequence-point'])],
     )
