/*-------------------------------------------------------------------------------
 * rc4-crypt.c         Crypthings
 * Message Encryptor/Decryptor using RC4
 *
 * buid with gcc rc4-crypt.c ../ciphers/rc4/rc4.c ../utils/utils.c -o rc4-crypt.o -Wall -Wextra -Wpedantic
 * run with ./rc4-crypt.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc rc4-crypt.c ../ciphers/rc4/rc4.c ../utils/utils.c -o rc4-crypt.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../ciphers/rc4/rc4.h"
#include "../utils/utils.h"

int main (void)
{

  int16_t i = 0;

  uint8_t key[5];
  memset (key, 0, 5*sizeof(uint8_t));

  uint8_t iv[95];
  memset (iv, 0, 95*sizeof(uint8_t));

  uint8_t kiv[100];
  memset (kiv, 0, 100*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t keystream_bytes[129*18];
  memset (keystream_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  char input_string[3000];

  uint16_t len = 0;
  int16_t  nbytes = 1;  //number of bytes needed
  int16_t  drop = 256;  //depending on application
  int16_t  offset = 0;  //an offset value to keystream application, if required (just add to the drop value)
  uint16_t kivlen = 13; //the len of the combined key and iv (mod value inside RC4 cipher)
  int16_t  confirm = 0; //confirm exit (or input values)

  fprintf (stderr, "\n----------------RC4 Message Cipher----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, " Enter RC4 IV Len (32 or 64 bits are typical):  ");
  scanf("%hu", &kivlen);

  //echo input and calculate the kivlen
  if ((kivlen % 8) != 0)
  {
    fprintf (stderr, " Abnormal IV len %d bits!", kivlen);
    kivlen = 64;
    fprintf (stderr, "\n Defaulting to %d bit value.\n", kivlen);
  }
  
  //convert to byte count with key's 5 bytes
  kivlen = (kivlen / 8) + 5;

  //sanity check on kivlen, most applications will most likely be 9, or 13 (32 or 64 bit IV)
  //but this has been expanded to allow a longer KIV value of up to 94 (probably overkill)
  if (kivlen > 94) kivlen = 94;

  fprintf (stderr, " Enter RC4 Dropbyte Value (#Bytes, 256 and 267 are typical):  ");
  scanf("%hi", &drop);

  fprintf (stderr, " Enter Keystream Application Offset (#Bytes, 0 is default):  ");
  scanf("%hi", &offset);

  //in the RC4 cipher, you can just add the offset to the drop value to get a starting position for keystream output
  drop += offset;

  fprintf (stderr, "\n Include any leading zeroes in key values, IV, and Input Message!");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key (5 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, key);

  //print key
  fprintf (stderr, " Key: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", key[i]);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter IV (4 or 8 octets are typical): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print key
  fprintf (stderr, "  IV: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", iv[i]);

  //pack key and IV into kiv
  for (i = 0; i < 5; i++)
    kiv[i] = key[i];

  for (i = 0; i < (kivlen-5); i++)
    kiv[i+5] = iv[i];

  //print kiv
  fprintf (stderr, "\n");
  fprintf (stderr, " KIV: ");
  for (i = 0; i < kivlen; i++)
    fprintf (stderr, "%02X", kiv[i]);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //returned len will also be the number of bytes to get from the RC4 cipher
  nbytes = len;

  //print input
  fprintf (stderr, "\n  In: ");
  for (i = 0; i < len; i++)
  {
    if ((i != 0) && ((i%8) == 0))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", input_bytes[i]);
  }

  //byte-wise output of RC4 Keystream
  rc4_keystream_output(drop, kivlen, nbytes, kiv, keystream_bytes);

  //xor keystream vs input to get output
  for (i = 0; i < nbytes; i++)
    output_bytes[i] = input_bytes[i] ^ keystream_bytes[i];

  //print keystream
  fprintf (stderr, "\n  KS: ");
  for (i = 0; i < len; i++)
  {
    if ((i != 0) && ((i%8) == 0))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", keystream_bytes[i]);
  }

  //print output
  fprintf (stderr, "\n Out: ");
  for (i = 0; i < len; i++)
  {
    if ((i != 0) && ((i%8) == 0))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", output_bytes[i]);
  }

  //print output (as string)
  // fprintf (stderr, "\n Output: %s", output_bytes+offset);

  //set a pause for user interaction before closing
  fprintf (stderr, "\n\n Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}
