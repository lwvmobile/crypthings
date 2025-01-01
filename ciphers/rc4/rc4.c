/*-------------------------------------------------------------------------------
 * rc4.c         Crypthings
 * RC4 Alg
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>

void rc4_keystream_output(int16_t drop, uint8_t keylength, int16_t nbytes, uint8_t * key, uint8_t * ks_bytes)
{
  int16_t i, j, x, count;
  uint8_t t, b;

  //init Sbox
  uint8_t S[256];
  for(i = 0; i < 256; i++)
    S[i] = i;

  //Key Scheduling
  j = 0;
  for(i = 0; i < 256; i++)
  {
    j = (j + S[i] + key[i % keylength]) % 256;
    t = S[i];
    S[i] = S[j];
    S[j] = t;
  }

  //Drop Bytes and KS Byte collection
  i = j = x = 0;
  for(count = 0; count < (nbytes + drop); count++)
  {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    t = S[i];
    S[i] = S[j];
    S[j] = t;
    b = S[(S[i] + S[j]) % 256];

    if (count >= drop)
      ks_bytes[x++] = b;
  }

}