/*-------------------------------------------------------------------------------
 * tdea-key-unwrap.c         Crypthings
 * Key Unwrap Alg using TDEA
 *
 * SEE: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 * SEE: Figure 1 and Figure 2 for illustative graphic (substitute 32 for 64)
 *
 * NOTE: This Program only wraps/unwraps 64, 128, or 192 bit keys
 * Vectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/key-wrapping-KW-KWP.pdf
 *
 * buid with gcc tdea-key-unwrap.c ../ciphers/des/des.c ../utils/utils.c -o tdea-key-unwrap.o -Wall -Wextra -Wpedantic
 * run with ./tdea-key-unwrap.o

 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc tdea-key-unwrap.c ../ciphers/des/des.c ../utils/utils.c -o tdea-key-unwrap.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../ciphers/des/des.h"
#include "../utils/utils.h"

int main (void)
{

  //counters
  int16_t i = 0, j = 0, k = 0;

  //stop values for iterators (based on len)
  int16_t istart = 6, jstart = 5, ostop = 28;

  uint8_t K1[8];
  memset (K1, 0, 8*sizeof(uint8_t));

  uint8_t K2[8];
  memset (K2, 0, 8*sizeof(uint8_t));

  uint8_t K3[8];
  memset (K3, 0, 8*sizeof(uint8_t));

  uint8_t iv[4]; //Default to 0xA6A6A6A6
  memset (iv, 0xA6, 4*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  char input_string[3000];

  uint16_t type = 2;
  int16_t  confirm = 0;
  uint8_t  de = 0;

  fprintf (stderr, "\n------------TDEA Key Unwrap Algorithm------------------------------");
  fprintf (stderr, "\n");

  fprintf (stderr, " Enter Key to Unwrap Len / Type (64/128/192): ");
  scanf("%hu", &type);

  //internally change key wrap i, j, and o bounds
  if (type == 64)
  {
    istart = 2;
    jstart = 5;
    ostop = 12;
  }
  else if (type == 128)
  {
    istart = 4;
    jstart = 5;
    ostop = 20;
  }
  else if (type == 192)
  {
    istart = 6;
    jstart = 5;
    ostop = 28;
  }
  else
  {
    fprintf (stderr, " %d Not Recognized, defaulting Key to Wrap Len to 192 \n", type);
    istart = 6;
    jstart = 5;
    ostop = 28;
  }

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K1: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, K1);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K2: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, K2);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K3: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, K3);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Cipher Text: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  parse_raw_user_string(input_string, input_bytes);

  //Semi Block Cipher Code Words
  uint8_t C[10][4];
  memset(C, 0, sizeof(C));

  //copy input_bytes to cipher code words
  for (i = 0; i < (istart+1); i++) 
    memcpy(C[i], input_bytes+(i*4), sizeof(C[0]));

  //debug loaded code words
  // for (j = 0; j < (istart+1); j++)
  // {
  //   fprintf (stderr, "\n   C[%d]: ", j);
  //   for (i = 0; i < 4; i++)
  //     fprintf (stderr, "%02X", C[j][i]);
  // }
  // fprintf (stderr, "\n");

  //A = C0 (IV) first 4 octets only
  uint8_t A[4];
  memset (A, 0, sizeof(A));
  memcpy (A, C[0], sizeof(A));

  //B = ECB-1K ((A XOR ((x*j) + i)) | Ri)
  uint8_t B[8];
  memset(B, 0, sizeof(B));

  uint8_t X[4]; // ((x*j) + i)
  memset(X, 0, sizeof(X));
  uint16_t t_idx = (istart * jstart) + istart; //iterator increment 't' index
  uint16_t XX = 0;

  uint8_t T[8];
  memset(T, 0, sizeof(T));

  //key unwrap, reverse order of the key wrap
  for (j = jstart; j >= 0; j--) //5,4,3,2,1,0
  {

    for (i = istart; i >= 1; i--) //x, x-1, ... 1
    {

      //calculate the XOR variable
      XX = t_idx--;
      X[2] = (XX >> 8) & 0xFF;
      X[3] = (XX >> 0) & 0xFF;

      //setup input T array based on semi-blocks
      memset(T, 0, sizeof(T));
      for (k = 0; k < 4; k++)
      {
        T[k+0] = A[k] ^ X[k]; // (A XOR ((x*j) + i));
        T[k+4] = C[i][k];     // | Ri (assign to LSB)
      }

      //Execute TDEA Cipher in ECB Mode
      memset(B, 0, sizeof(B)); //reset B (output register)
      tdea_ecb_payload_crypt(K3, K2, K1, T, B, de); //Keys in reverse order for decryption!!

      //copy ciphered output B so that,

      //A = MSBn/2(B)
      memcpy(A, B+0, sizeof(A));

      //Copy A to Code Word 0
      memcpy(C[0], A, sizeof(A));

      //C[j] = Ri, and Ri = LSBn/2(B)
      memcpy(C[i], B+4, sizeof(A));

      //debug intermediate values
      // fprintf (stderr, "   --J: %d; I: %d; XX: %02d--", j, i, XX);
      // fprintf (stderr, "\n   ICV1: ");
      // for (int16_t y = 0; y < 4; y++)
      //   fprintf (stderr, "%02X", A[y]);
      // for (int16_t z = 1; z < 7; z++)
      // {
      //   fprintf (stderr, "\n   C[%d]: ", z);
      //   for (int16_t y = 0; y < 4; y++)
      //     fprintf (stderr, "%02X", C[z][y]);
      // }
      // fprintf (stderr, "\n");

    }
  }

  //copy final to output_bytes
  for (i = 0; i < 10; i++) //(jstart+1)
    memcpy (output_bytes+(i*4), C[i], sizeof(C[0]));

  //debug output
  fprintf (stderr, " Plain Text: ");
  for (i = 0; i < ostop; i++)
    fprintf (stderr, "%02X", output_bytes[i]);

  //success check
  if (memcmp(A, iv, sizeof(A)) != 0)
  {
    fprintf (stderr, "\n Unwrap Failure! IV != 0xA6A6A6A6! \n");
    fprintf (stderr, "Enter any value to Exit: ");
    scanf("%hi", &confirm);
    return 0;
  }
  else fprintf (stderr, "\n Unwrap Success!");

  uint8_t key[32]; memset (key, 0, sizeof(key));
  memcpy (key, output_bytes+4, 32);

  //print key
  fprintf (stderr, "\n Unwrapped Key: ");
  for (i = 0; i < (ostop-4); i++)
  {
    if ((i != 0) && ((i%4) == 0))
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
