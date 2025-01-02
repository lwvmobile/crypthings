/*-------------------------------------------------------------------------------
 * aes-ofb-crypt.c         Tinier AES / Crypthings
 * Message Encryptor/Decryptor using AES OFB Mode
 *
 * buid with gcc aes-ofb-crypt.c ../ciphers/aes/aes.c ../utils/utils.c -o aes-ofb-crypt.o -Wall -Wextra -Wpedantic
 * run with ./aes-ofb-crypt.o

 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc aes-ofb-crypt.c ../ciphers/aes/aes.c ../utils/utils.c -o aes-ofb-crypt.exe
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

  int16_t i = 0;

  uint8_t key[32];
  memset (key, 0, 32*sizeof(uint8_t));

  uint8_t iv[16];
  memset (iv, 0, 16*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t keystream_bytes[129*18];
  memset (keystream_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  char input_string[3000];

  uint16_t len = 0;
  uint16_t type = 256;  //AES256
  uint16_t nblocks = 1; //number of rounds needed
  int16_t  offset = 16;  //an offset value to keystream application, if required (account for OFB discard round)
  int16_t  confirm = 0;

  fprintf (stderr, "\n----------------Tinier-AES OFB Message Cipher----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, " Enter AES Key Len / Type (128/192/256): ");
  scanf("%hu", &type);

  //echo input and internally change AES type to work in the internal function
  if (type == 128)
  {
    fprintf (stderr, " AES 128 ");
    type = 0;
  }
  else if (type == 192)
  {
    fprintf (stderr, " AES 192 ");
    type = 1;
  }
  else if (type == 256)
  {
    fprintf (stderr, " AES 256 ");
    type = 2;
  }
  else
  {
    fprintf (stderr, " %d Not Recognized, defaulting to AES 256 ", type);
    type = 2;
  }
  fprintf (stderr, "\n");

  fprintf (stderr, "\n Include any leading zeroes in key values, IV, and Input Message!");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, key);

  //print key
  fprintf (stderr, "\n Key: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", key[i]);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter IV (4, 8, or 16 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print input IV len in octets
  fprintf (stderr, "\n  IV Len: %02d Octets;", len);

  //if supplied IV len is 4 octets (32-bit)
  if (len == 4)
  {
    //print iv
    fprintf (stderr, "\n  IV(32): ");
    for (i = 0; i < len; i++)
        fprintf (stderr, "%02X", iv[i]);

    //LFSR to expand a 32-bit IV into a 128-bit IV
    lfsr_32_to_128(iv);
  }

  //if supplied IV len is 8 octets (64-bit)
  else if (len == 8)
  {
    //print iv
    fprintf (stderr, "\n  IV(64): ");
    for (i = 0; i < len; i++)
        fprintf (stderr, "%02X", iv[i]);

    //LFSR to expand a 64-bit IV into a 128-bit IV
    lfsr_64_to_128(iv);
  }

  //if supplied IV len is 16 octets (128-bit)
  else if (len == 16)
  {
    fprintf (stderr, "\n IV(128): ");
    for (i = 0; i < len; i++)
      fprintf (stderr, "%02X", iv[i]);
    fprintf (stderr, "\n");
  }

  else
  {
    fprintf (stderr, "\n Abnormal IV len %d octets; Please enter 32-bit(8 hex char/4 octets),\n 64-bit (16 hex char/8 octets), or 128-bit (32 hex char/16 octet) IV; ", len);
    return 0;
  }

  fprintf (stderr, "\n Enter Keystream Application Offset (#Bytes, 0 and 16 are typical): ");
  scanf("%hi", &offset);
  fprintf (stderr, " Keystream Offset: %d", offset);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //calculate nblocks needed based on returned len value here
  nblocks = len / 16;
  if (len % 16) nblocks += 1;
  
  //additional to account for keystream offset
  int16_t t = offset;
  while (t)
  {
    t /= 16;
    nblocks++;
  }
  if (offset % 16) nblocks++;

  //print input
  fprintf (stderr, "\n  Input: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", input_bytes[i]);

  //byte-wise output of AES OFB Keystream
  aes_ofb_keystream_output(iv, key, keystream_bytes, type, nblocks);

  //xor keystream vs input to get output
  for (i = 0; i < len; i++)
    output_bytes[i] = input_bytes[i] ^ keystream_bytes[i+offset];

  //print output
  fprintf (stderr, "\n\n Output: ");
  for (i = 0; i < len; i++)
  {
    if ((i != 0) && ((i%8) == 0))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", output_bytes[i]);
  }

  //print output (as string)
  // fprintf (stderr, "\n Output: %s", output_bytes);

  //ending line break
  fprintf (stderr, "\n ");

  //set a pause for user interaction before closing
  fprintf (stderr, "Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}