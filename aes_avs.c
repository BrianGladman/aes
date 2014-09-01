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
Issue Date: 20/11/2013
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "aes.h"

#define BLOCK_SIZE       16
#define MAX_TEXT_SIZE   256
#define INPUT_BUF_SIZE 1024
#define MCT_REPEAT     1000

typedef enum { ECB = 0, CBC, CFB, OFB } mode;
char *mode_str[] = { "ECB", "CBC", "CFB128", "OFB" };

typedef enum { GFSbox = 0, KeySbox, MCT, MMT, VarKey, VarTxt } type;
char *type_str[] = { "GFSbox", "KeySbox", "MCT", "MMT", "VarKey", "VarTxt" };

typedef enum { Key128 = 0, Key192, Key256 } key;
char *klen_str[] = { "128",  "192",  "256" };

typedef enum { L_bad = -1, L_count = 0, L_key, L_iv, L_plaintext, L_ciphertext } line_type;
char *hdr_str[] = { "COUNT = ", "KEY = ", "IV = ", "PLAINTEXT = ", "CIPHERTEXT = " };

char *test_path = "..\\testvals\\fax\\";
char *hxx = "0123456789abcdef";

int to_hex(int ch)
{
    return (ch & 15) + (ch >= '0' && ch <= '9' ? 0 : 9);
}

int get_dec(const char *s)
{   const char  *p = s;
    int nbr = 0;

    while(*p && *p >= '0' && *p <= '9')
    {
        nbr = 10 * nbr + (*p - '0'); ++p;
    }

    return nbr;
}

int get_line(FILE *inf, char s[])
{
    if(feof(inf))
        return EXIT_FAILURE;
    return fgets(s, INPUT_BUF_SIZE, inf) == s ? EXIT_SUCCESS : EXIT_FAILURE;
}

int block_in(unsigned char l[], const char *p)
{   int i = 0;

    while(*p && *(p + 1) && isxdigit(*p) && isxdigit(*(p + 1)))
    {
        l[i++] = (to_hex(*p) << 4) + to_hex(*(p + 1)); p += 2;
    }
    return i;
}

int find_string(const char *s1, const char s2[])
{   const char  *p1 = s1, *q1, *q2;

    while(*p1)
    {
        q1 = p1; q2 = s2;

        while(*q1 && *q2 && *q1 == *q2)
        {
            q1++; q2++;
        }

        if(!*q2)
            return (int)(p1 - s1);
        p1++;
    }
    return -1;
}

enum line_type find_line(FILE *inf, char str[], char **p)
{   int i;

    for(i = 0 ; i < sizeof(hdr_str) / sizeof(hdr_str[0]) ; ++i) 
        if(find_string(str, hdr_str[i]) >= 0)
        {
            *p = str + strlen(hdr_str[i]);
            return (line_type)i;
        }
    return L_bad;
}

void do_encrypt(mode mm, const unsigned char key[], unsigned char iv[], 
                const unsigned char pt[], unsigned char ct[], int key_len, int block_len)
{   aes_encrypt_ctx ctx[1];

    aes_encrypt_key(key, key_len, ctx);
    switch(mm)
    {
    case ECB:
        aes_ecb_encrypt(pt, ct, block_len, ctx); 
        break;
    case CBC:
        aes_cbc_encrypt(pt, ct, block_len, iv, ctx); 
        break;
    case CFB:
        aes_cfb_encrypt(pt, ct, block_len, iv, ctx); 
        break;
    case OFB:
        aes_ofb_encrypt(pt, ct, block_len, iv, ctx); 
        break;
    }
}

void do_decrypt(mode mm, const unsigned char key[], unsigned char iv[], 
                const unsigned char ct[], unsigned char pt[], int key_len, int block_len)
{   aes_decrypt_ctx ctx[1];

    switch(mm)
    {
    case ECB:
        aes_decrypt_key(key, key_len, ctx);
        aes_ecb_decrypt(ct, pt, block_len, ctx); 
        break;
    case CBC:
        aes_decrypt_key(key, key_len, ctx);
        aes_cbc_decrypt(ct, pt, block_len, iv, ctx); 
        break;
    case CFB:
        aes_encrypt_key(key, key_len, (aes_encrypt_ctx*)ctx);
        aes_cfb_decrypt(ct, pt, block_len, iv, (aes_encrypt_ctx*)ctx); 
        break;
    case OFB:
        aes_encrypt_key(key, key_len, (aes_encrypt_ctx*)ctx);
        aes_ofb_decrypt(ct, pt, block_len, iv, (aes_encrypt_ctx*)ctx); 
        break;
    }
}

void do_mct_encrypt(mode mm, const unsigned char key[], unsigned char iv[], 
                unsigned char pt[], unsigned char ct[], int key_len, int block_len)
{   aes_encrypt_ctx ctx[1];
    unsigned char tmp[BLOCK_SIZE];
    int i;
    typedef AES_RETURN (*f_enc)(const unsigned char*, unsigned char*, int, 
                         unsigned char*, aes_encrypt_ctx*);

    aes_encrypt_key(key, key_len, ctx);
    if(mm == ECB)
    {
        for( i = 0 ; i < MCT_REPEAT / 2 ; ++i )
        {
            aes_ecb_encrypt(pt, ct, BLOCK_SIZE, ctx);
            aes_ecb_encrypt(ct, pt, BLOCK_SIZE, ctx);
        }
        memcpy(ct, pt, BLOCK_SIZE);
    }
    else
    {   
        f_enc f[3] = { aes_cbc_encrypt, aes_cfb_encrypt, aes_ofb_encrypt };
        memcpy(tmp, iv, BLOCK_SIZE);
        for( i = 0 ; i < MCT_REPEAT ; ++i )
        {
            f[mm - 1](pt, ct, BLOCK_SIZE, iv, ctx);
            memcpy(pt, tmp, BLOCK_SIZE);
            memcpy(tmp, ct, BLOCK_SIZE);
        }
    }
}


void do_mct_decrypt(mode mm, const unsigned char key[], unsigned char iv[], 
                const unsigned char ct[], unsigned char pt[], int key_len, int block_len)
{   aes_decrypt_ctx ctx[1];
    unsigned char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE];
    int i;
    typedef AES_RETURN (*f_dec)(const unsigned char*, unsigned char*, int, 
                         unsigned char*, aes_decrypt_ctx*);
    if(mm == ECB)
    {
        aes_decrypt_key(key, key_len, ctx);
        memcpy(tmp, ct, BLOCK_SIZE);
        for( i = 0 ; i < MCT_REPEAT / 2 ; ++i )
        {
            aes_ecb_decrypt(ct, pt, BLOCK_SIZE, ctx);
            aes_ecb_decrypt(pt, ct, BLOCK_SIZE, ctx);
        }
        memcpy(pt, ct, BLOCK_SIZE);
    }
    else
    {
        f_dec f[3] = { aes_cbc_decrypt, (f_dec)aes_cfb_decrypt, (f_dec)aes_ofb_decrypt };
        if( mm == CBC )
            aes_decrypt_key(key, key_len, ctx);
        else
            aes_encrypt_key(key, key_len, (aes_encrypt_ctx*)ctx);
        memcpy(tmp, iv, BLOCK_SIZE);
        for( i = 0 ; i < MCT_REPEAT ; ++i )
        {
            f[mm - 1](ct, pt, BLOCK_SIZE, iv, ctx);
            memcpy(ct, tmp, BLOCK_SIZE);
            memcpy(tmp, pt, BLOCK_SIZE);
        }
    }
}

void run_aes_avs_test(mode mm, type tt)
{   char  path[128], inbuf[1024], *p;
    unsigned char key[2 * BLOCK_SIZE], iv[BLOCK_SIZE], pt[MAX_TEXT_SIZE], ct[MAX_TEXT_SIZE], rt[MAX_TEXT_SIZE];
    int i, err, cnt, key_len, iv_len, pt_len, ct_len;
    FILE *f;
    line_type ty;

    for( i = 0 ; i < 3 ; ++i )
    {
        err = 0;
        strcpy(path, test_path);
        strcat(path, mode_str[mm]);
        strcat(path, type_str[tt]);
        strcat(path, klen_str[i]);
        strcat(path, ".fax");
        if(!(f = fopen(path, "r")))
            return EXIT_FAILURE;
        while(get_line(f, inbuf) == EXIT_SUCCESS)
        {
            if((ty = find_line(f, inbuf, &p)) != L_bad)
                switch(ty)
                {
                case L_count:
                    key_len = iv_len = pt_len = ct_len = 0;
                    cnt = get_dec(p);
                    break;
                case L_key:
                    key_len = block_in(key, p);
                    break;
                case L_iv:
                    iv_len = block_in(iv, p);
                    break;
                case L_plaintext:
                    pt_len = block_in(pt, p);
                    if(pt_len == ct_len)
                    {
                        if(tt != MCT)
                            do_decrypt(mm, key, iv, ct, rt, key_len, pt_len);
                        else
                            do_mct_decrypt(mm, key, iv, ct, rt, key_len, pt_len);
                        if(memcmp(pt, rt, pt_len))
                        {
                            printf("\nError on file %s, on test %i", path, cnt);
                            ++err;
                        }
                    }
                    break;
                case L_ciphertext:
                    ct_len = block_in(ct, p);
                    if(ct_len == pt_len)
                    {
                        if(tt == MCT)
                            do_mct_encrypt(mm, key, iv, pt, rt, key_len, pt_len);
                        else
                            do_encrypt(mm, key, iv, pt, rt, key_len, pt_len);
                        if(memcmp(ct, rt, pt_len))
                        {
                            printf("\nError on file %s, on test %i", path, cnt);
                            ++err;
                        }
                    }
                    break;
                }
        }
        fclose(f);
        if(!err)
            printf("\nCorrect results for %s", path);
    }
}

int main(void)
{   int i, j;

    for( i = 0 ; i < 4 ; ++i )
        for( j = 0 ; j < 6 ; ++j)
            run_aes_avs_test((mode)i, (type)j);
    printf("\n\n");
}
