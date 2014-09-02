/*
---------------------------------------------------------------------------
Copyright (c) 2014, Michael Mohr, San Jose, CA, USA. All rights reserved.

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
Issue Date: 30/08/2014
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/mman.h>
#include <Python.h>
#include <structmember.h>
#include "aes.h"

typedef enum {
    AES_MODE_ECB,
    AES_MODE_CBC,
    AES_MODE_CFB,
    AES_MODE_OFB,
    AES_MODE_CTR
} aes_mode;

typedef struct {
    PyObject_HEAD
    aes_mode mode;
    aes_encrypt_ctx ectx[1] __attribute__ ((aligned(16)));
    aes_decrypt_ctx dctx[1] __attribute__ ((aligned(16)));
    unsigned char iv[AES_BLOCK_SIZE] __attribute__ ((aligned(16)));
    unsigned char iv_o[AES_BLOCK_SIZE] __attribute__ ((aligned(16)));
} brg_aesObject;

/*
This subroutine implements the CTR mode standard incrementing function.
See NIST Special Publication 800-38A, Appendix B for details:
http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
*/
void ctr_inc(unsigned char *cbuf) {
    uint64_t c;

    #if BYTE_ORDER == LITTLE_ENDIAN
    c = be64toh(*(uint64_t *)(cbuf + 8));
    c++;
    *(uint64_t *)(cbuf + 8) = be64toh(c);
    #elif BYTE_ORDER == BIG_ENDIAN
    /* big endian support? completely untested... */
    c = be64toh(*(uint64_t *)(cbuf + 0));
    c++;
    *(uint64_t *)(cbuf + 0) = be64toh(c);
    #else
    /* something more exotic? */
    #error "Unsupported byte order"
    #endif
    return;
}

/*
A discussion of buffers in Python can be found here:
https://mail.python.org/pipermail/python-dev/2000-October/009974.html
Suggested data type for {en|de}cryption: Python array class
*/

static PyObject *py_aes_encrypt(brg_aesObject *self, PyObject *args) {
    aes_mode mode;
    Py_ssize_t data_len = 0;
    unsigned char *data = NULL;
    AES_RETURN ret = EXIT_FAILURE;

    if(!PyArg_ParseTuple(args, "w#", &data, &data_len))
        return NULL;

    /* Verify constraints based on mode */
    mode = self->mode;
    if(((mode == AES_MODE_ECB) || (mode == AES_MODE_CBC)) && ((data_len & 15) != 0)) {
        PyErr_SetString(PyExc_ValueError, "Data size must be a multiple of 16 bytes");
        return NULL;
    }

    /* Perform the real encryption operation */
    switch(mode) {
    case AES_MODE_ECB:
        ret = aes_ecb_encrypt(data, data, data_len, self->ectx);
        break;
    case AES_MODE_CBC:
        ret = aes_cbc_encrypt(data, data, data_len, self->iv, self->ectx);
        break;
    case AES_MODE_CFB:
        ret = aes_cfb_encrypt(data, data, data_len, self->iv, self->ectx);
        break;
    case AES_MODE_OFB:
        ret = aes_ofb_encrypt(data, data, data_len, self->iv, self->ectx);
        break;
    case AES_MODE_CTR:
        /* cbuf data is passed as iv */
        ret = aes_ctr_encrypt(data, data, data_len, self->iv, ctr_inc, self->ectx);
        break;
    }

    /* Verify result and return */
    if(ret != EXIT_SUCCESS) {
        PyErr_SetString(PyExc_ValueError, "Failed to encrypt data");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *py_aes_decrypt(brg_aesObject *self, PyObject *args) {
    aes_mode mode;
    int data_len = 0;
    unsigned char *data = NULL;
    AES_RETURN ret = EXIT_FAILURE;

    if(!PyArg_ParseTuple(args, "w#", &data, &data_len))
        return NULL;

    /* Verify constraints based on mode */
    mode = self->mode;
    if(((mode == AES_MODE_ECB) || (mode == AES_MODE_CBC)) && ((data_len & 15) != 0)) {
        PyErr_SetString(PyExc_ValueError, "Data size must be a multiple of 16 bytes");
        return NULL;
    }

    /* Perform the real encryption operation */
    switch(mode) {
    case AES_MODE_ECB:
        ret = aes_ecb_decrypt(data, data, data_len, self->dctx);
        break;
    case AES_MODE_CBC:
        ret = aes_cbc_decrypt(data, data, data_len, self->iv, self->dctx);
        break;
    case AES_MODE_CFB:
        ret = aes_cfb_decrypt(data, data, data_len, self->iv, self->ectx);
        break;
    case AES_MODE_OFB:
        ret = aes_ofb_decrypt(data, data, data_len, self->iv, self->ectx);
        break;
    case AES_MODE_CTR:
        /* cbuf data is passed as iv */
        ret = aes_ctr_decrypt(data, data, data_len, self->iv, ctr_inc, self->ectx);
        break;
    }

    /* Verify result and return */
    if(ret != EXIT_SUCCESS) {
        PyErr_SetString(PyExc_ValueError, "Failed to decrypt data");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *py_aes_reset(brg_aesObject *self) {
    switch(self->mode) {
    case AES_MODE_ECB:
        break;
    case AES_MODE_CBC:
        memcpy(self->iv, self->iv_o, AES_BLOCK_SIZE);
        break;
    case AES_MODE_CFB:
    case AES_MODE_OFB:
    case AES_MODE_CTR:
        memcpy(self->iv, self->iv_o, AES_BLOCK_SIZE);
        aes_mode_reset(self->ectx);
        break;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef aes_methods[] = {
    {"encrypt", (PyCFunction)py_aes_encrypt, METH_VARARGS, "encrypts a series of blocks"},
    {"decrypt", (PyCFunction)py_aes_decrypt, METH_VARARGS, "decrypts a series of blocks"},
    {"reset",   (PyCFunction)py_aes_reset,   METH_NOARGS, "resets the object state"},
    {NULL}  /* Sentinel */
};

static PyMemberDef aes_members[] = {
    {NULL}  /* Sentinel */
};

static int py_aes_init(brg_aesObject *self, PyObject *args, PyObject *kwds) {
    size_t mode_len = 0;
    const char *mode = NULL;
    int key_len = 0, iv_len = 0;
    unsigned char *key = NULL, *iv = NULL;
    char *kwlist[] = {"key", "mode", "iv", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "t#s|t#", kwlist, &key, &key_len, &mode, &iv, &iv_len))
        return -1;
    /* determine the operation mode */
    mode_len = strlen(mode);
    if(strncasecmp(mode, "ecb", mode_len) == 0) {
        self->mode = AES_MODE_ECB;
    } else if(strncasecmp(mode, "cbc", mode_len) == 0) {
        self->mode = AES_MODE_CBC;
    } else if(strncasecmp(mode, "cfb", mode_len) == 0) {
        self->mode = AES_MODE_CFB;
    } else if(strncasecmp(mode, "ofb", mode_len) == 0) {
        self->mode = AES_MODE_OFB;
    } else if(strncasecmp(mode, "ctr", mode_len) == 0) {
        self->mode = AES_MODE_CTR;
    } else {
        PyErr_SetString(PyExc_ValueError, "Unsupported AES mode");
        return -1;
    }
    /* ensure required parameters have been passed */
    switch(self->mode) {
    case AES_MODE_ECB:
        // no additional parameters are required for ECB mode
        break;
    case AES_MODE_CBC:
    case AES_MODE_CFB:
    case AES_MODE_OFB:
    case AES_MODE_CTR:
        if(iv_len != AES_BLOCK_SIZE) {
            PyErr_SetString(PyExc_ValueError, "A 16-byte IV must be supplied for this mode");
            return -1;
        }
        memcpy(self->iv, iv, AES_BLOCK_SIZE);
        /* Save a copy of the original IV, for possible reset later */
        memcpy(self->iv_o, iv, AES_BLOCK_SIZE);
        break;
    }
    /* validate key length and initialize encryption / decryption states */
    switch(key_len) {
    case 16:
        aes_encrypt_key128(key, self->ectx);
        aes_decrypt_key128(key, self->dctx);
        break;
    case 24:
        aes_encrypt_key192(key, self->ectx);
        aes_decrypt_key192(key, self->dctx);
        break;
    case 32:
        aes_encrypt_key256(key, self->ectx);
        aes_decrypt_key256(key, self->dctx);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "Invalid AES key length");
        return -1;
    }
    return 0;
}

/* https://docs.python.org/2/c-api/typeobj.html#PyTypeObject.tp_alloc */
static PyObject *secure_alloc(PyTypeObject *type, Py_ssize_t nitems) {
    int success;
    brg_aesObject *self;
    size_t required_mem, extra, tmp;

    required_mem = (size_t)type->tp_basicsize;
    if(type->tp_itemsize != 0) {
        extra = type->ob_size * type->tp_itemsize;
        /* round up to a multiple of sizeof(void *) */
        tmp = extra % sizeof(void *);
        if(tmp > 0)
            extra += (sizeof(void *) - tmp);
        required_mem += extra;
    }
    success = posix_memalign((void **)&self, 16, required_mem);
    if (success != 0)
        return (PyObject *)PyErr_NoMemory();
    success = mlock(self, required_mem);
    if (success != 0) {
        free(self);
        return (PyObject *)PyErr_NoMemory();
    }
    memset(self, 0, required_mem);
    PyObject_INIT(self, type);
    return (PyObject *)self;
}

void secure_free(void *self) {
    memset(self, 0, sizeof(brg_aesObject));
    munlock(self, sizeof(brg_aesObject));
    free(self);
    self = NULL;
    return;
}

static PyTypeObject brg_aesType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "brg.aes",                 /*tp_name*/
    sizeof(brg_aesObject),     /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    "brg crypto objects",      /*tp_doc*/
    0,		               /*tp_traverse*/
    0,		               /*tp_clear*/
    0,		               /*tp_richcompare*/
    0,		               /*tp_weaklistoffset*/
    0,		               /*tp_iter*/
    0,		               /*tp_iternext*/
    aes_methods,               /*tp_methods*/
    aes_members,               /*tp_members*/
    0,                         /*tp_getset*/
    0,                         /*tp_base*/
    0,                         /*tp_dict*/
    0,                         /*tp_descr_get*/
    0,                         /*tp_descr_set*/
    0,                         /*tp_dictoffset*/
    (initproc)py_aes_init,     /*tp_init*/
    (allocfunc)secure_alloc,   /*tp_alloc*/
    (newfunc)PyType_GenericNew,/*tp_new*/
    (freefunc)secure_free,     /*tp_free*/
};

/* module methods (none for now) */
static PyMethodDef brg_methods[] = {
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC initbrg(void) {
    PyObject *m;

    /*brg_aesType.tp_new = PyType_GenericNew;*/
    if (PyType_Ready(&brg_aesType) < 0)
        return;

    m = Py_InitModule3("brg", brg_methods,
                       "Python bindings for Brian Gladman's crypto code");

    Py_INCREF(&brg_aesType);
    PyModule_AddObject(m, "aes", (PyObject *)&brg_aesType);
}
