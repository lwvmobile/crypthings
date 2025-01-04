/*-------------------------------------------------------------------------------
 * aes-key-unwrap.c         Crypthings
 * Key Unwrap Alg using AES
 *
 * SEE: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 * SEE: Figure 3 for illustative graphic
 *
 * NOTE: This Program only wraps/unwraps standard AES key lens
 * Vectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/key-wrapping-KW-KWP.pdf
 *
 * buid with gcc aes-key-unwrap.c ../ciphers/aes/aes.c ../utils/utils.c -o aes-key-unwrap.o -Wall -Wextra -Wpedantic
 * run with ./aes-key-unwrap.o

 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc aes-key-unwrap.c ../ciphers/aes/aes.c ../utils/utils.c -o aes-key-unwrap.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../ciphers/aes/aes.h"
#include "../utils/utils.h"

int main ()
{

  //counters
  int16_t i = 0, j = 0, k = 0;

  //start / stop values for iterators (based on AES type / key len)
  int16_t istart = 4, jstart = 5, ostop = 40;

  uint8_t key[32];
  memset (key, 0, 32*sizeof(uint8_t));

  uint8_t iv[8]; //Default to 0xA6A6A6A6A6A6A6A6
  memset (iv, 0xA6, 8*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  char input_string[3000];

  uint16_t type = 2;
  int16_t  confirm = 0;
  int16_t  de = 0;

  fprintf (stderr, "\n------------AES Key Unwrap Algorithm------------------------------");
  fprintf (stderr, "\n");

  fprintf (stderr, " Enter AES Key to Unwrap Len / Type (128/192/256): ");
  scanf("%hu", &type);

  //echo input and internally change AES type to work in the internal function
  if (type == 128)
  {
    istart = 2;
    jstart = 5;
    ostop = 24;
  }
  else if (type == 192)
  {
    istart = 3;
    jstart = 5;
    ostop = 32;
  }
  else if (type == 256)
  {
    istart = 4;
    jstart = 5;
    ostop = 40;
  }
  else
  {
    fprintf (stderr, " %d Not Recognized, defaulting to AES 256 \n", type);
    istart = 4;
    jstart = 5;
    ostop = 40;
  }

  //prompt for the len of the Key to be Wrapped or Unwrapped
  fprintf (stderr, " Enter AES Un/Wrap Key Len / Type   (128/192/256): ");
  scanf("%hu", &type);

  //internally change AES type
  if (type == 128)
    type = 0;
  else if (type == 192)
    type = 1;
  else if (type == 256)
    type = 2;
  else
  {
    fprintf (stderr, " %d Not Recognized, defaulting Un/Wrap Key Len to AES 256 \n", type);
    type = 2;
  }

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Un/Wrap Key: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, key);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Cipher Text: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, input_bytes);

  //Semi Block Cipher Code Words
  uint8_t C[10][8];
  memset(C, 0, sizeof(C));

  //copy input_bytes to cipher code words
  for (i = 0; i < 6; i++) 
    memcpy(C[i], input_bytes+(i*8), sizeof(C[0]));

  //debug loaded code words
  // for (j = 0; j < jstart; j++)
  // {
  //   fprintf (stderr, "\n   C[%d]: ", j);
  //   for (i = 0; i < 8; i++)
  //     fprintf (stderr, "%02X", C[j][i]);
  // }

  // fprintf (stderr, "\n");

  //A = C0 (IV) first 8 octets only
  uint8_t A[8];
  memset (A, 0, sizeof(A));
  memcpy (A, C[0], sizeof(A));

  //B = ECB-1K ((A XOR ((x*j) + i)) | Ri)
  uint8_t B[16];
  memset(B, 0, sizeof(B));

  uint8_t X[8]; // ((x*j) + i)
  memset(X, 0, sizeof(X));
  uint16_t t_idx = (istart * jstart) + istart; //iterator increment 't' index
  uint16_t XX = 0;

  uint8_t T[16];
  memset(T, 0, sizeof(T));

  //key unwrap, reverse order of the key wrap
  for (j = jstart; j >= 0; j--) //5,4,3,2,1,0
  {

    for (i = istart; i >= 1; i--) //x, x-1, ... 1
    {
      //calculate the inner XOR variable
      // XX = (xlen * j) + i;
      XX = t_idx--;
      X[6] = (XX >> 8) & 0xFF;
      X[7] = (XX >> 0) & 0xFF;

      //setup input T array based on semi-blocks
      memset(T, 0, sizeof(T));
      for (k = 0; k < 8; k++)
      {
        T[k+0] = A[k] ^ X[k]; // (A XOR ((x*j) + i))
        T[k+8] = C[i][k];     // | Ri (assign to LSB)
      }

      //Execute AES Cipher in ECB Mode
      aes_ecb_bytewise_payload_crypt(T, key, B, type, de);

      //copy ciphered output B so that,

      //A = MSBn/2(B)
      memcpy(A, B+0, sizeof(A));

      //Copy A to Code Word 0
      memcpy(C[0], A, sizeof(A));

      //C[j] = Ri, and Ri = LSBn/2(B)
      memcpy(C[i], B+8, sizeof(A));

      //debug intermediate values
      // fprintf (stderr, "   --J: %d; I: %d; XX: %02d--", j, i, XX);
      // fprintf (stderr, "\n   ICV1: ");
      // for (int16_t y = 0; y < 8; y++)
      //   fprintf (stderr, "%02X", A[y]);
      // for (int16_t z = 1; z < 6; z++)
      // {
      //   fprintf (stderr, "\n   C[%d]: ", z);
      //   for (int16_t y = 0; y < 8; y++)
      //     fprintf (stderr, "%02X", C[z][y]);
      // }
      // fprintf (stderr, "\n");

    }
  }

  //copy final to output_bytes
  for (i = 0; i < 6; i++)
    memcpy (output_bytes+(i*8), C[i], sizeof(C[0]));

  //debug output
  fprintf (stderr, " Plain Text: ");
  for (i = 0; i < ostop; i++)
    fprintf (stderr, "%02X", output_bytes[i]);

  //success check
  if (memcmp(A, iv, sizeof(A)) != 0)
  {
    fprintf (stderr, "\n Unwrap Failure! IV != 0xA6A6A6A6A6A6A6A6! \n");
    fprintf (stderr, "Enter any value to Exit: ");
    scanf("%hi", &confirm);
    return 0;
  }
  else fprintf (stderr, "\n Unwrap Success!");

  memcpy (key, output_bytes+8, 32);

  //print key
  fprintf (stderr, "\n Unwrapped Key: ");
  for (i = 0; i < (ostop-8); i++)
  {
    if ((i != 0) && ((i%8) == 0))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", key[i]);
  }

  //ending line break
  fprintf (stderr, "\n ");

  //set a pause for user interaction before closing
  fprintf (stderr, "Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}