/*-------------------------------------------------------------------------------
 * tdea-tofb-crypt.c         Crypthings
 * Message Encryptor/Decryptor using TDEA (Triple DES) in OFB Mode
 *
 * buid with gcc tdea-tofb-crypt.c ../ciphers/des/des.c ../utils/utils.c -o tdea-tofb-crypt.o -Wall -Wextra -Wpedantic
 * run with ./tdea-tofb-crypt.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc tdea-tofb-crypt.c ../ciphers/des/des.c ../utils/utils.c -o tdea-tofb-crypt.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../ciphers/des/des.h"
#include "../utils/utils.h"

int main ()
{

  int16_t i = 0;

  uint8_t K1[8];
  memset (K1, 0, 8*sizeof(uint8_t));

  uint8_t K2[8];
  memset (K2, 0, 8*sizeof(uint8_t));

  uint8_t K3[8];
  memset (K3, 0, 8*sizeof(uint8_t));

  uint8_t iv[8];
  memset (iv, 0, 8*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t keystream_bytes[129*18];
  memset (keystream_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  char input_string[3000];

  uint16_t len = 0;
  int16_t  nblocks = 1; //number of blocks/rounds needed
  int16_t  offset = 8;  //an offset value to keystream application, if required (account for OFB discard round)
  int16_t  confirm = 0; //confirm exit (or input values)
  uint8_t  de = 1;      //run DES Cipher in encryption mode, or decryption mode (OFB always use enc)

  fprintf (stderr, "\n----------------TDEA (Triple DES) OFB Message Cipher----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, "\n Include any leading zeroes in key values, IV, and Input Message!");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K1 (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, K1);

  //print key
  fprintf (stderr, " K1: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", K1[i]);
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K2 (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, K2);

  //print key
  fprintf (stderr, " K2: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", K2[i]);
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key K3 (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, K3);

  //print key
  fprintf (stderr, " K3: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", K3[i]);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter IV (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print key
  fprintf (stderr, " IV: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", iv[i]);

  fprintf (stderr, "\n Enter Keystream Application Offset (#Bytes, 0, 8, or 19 are typical): ");
  scanf("%hi", &offset);
  fprintf (stderr, " Keystream Offset: %d", offset);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //calculate the number of blocks/rounds required
  nblocks = len / 8;
  if (len % 8) nblocks += 1; //additional if not an even multiple of 8
  
  //additional to account for keystream offset
  int16_t t = offset;
  while (t)
  {
    t /= 8;
    nblocks++;
  }
  if (offset % 8) nblocks++;

  //print input
  fprintf (stderr, "\n  Input: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", input_bytes[i]);

  //byte-wise output of TDEA-TOFB Keystream
  tdea_tofb_keystream_output (K1, K2, K3, iv, keystream_bytes, de, nblocks);

  //NOTE: When testing ECB, CBC or CFB modes, print the entirety of output_bytes
  //(completed multiples of 8), user will need that cipher text to properly decrypt
  //the last 8 bytes of output or the plain text's last 8 will mismatch the original

  //test TDEA ECB Mode
  // Note: Key bundle needs to be reversed manually for ECB Mode
  // tdea_ecb_payload_crypt(K1, K2, K3, input_bytes, output_bytes, de);

  //Test TDEA CBC Mode (working, disable xor below)
  // Note: Key bundle is reversed in the tdea_cbc_payload_crypt function if decrypting
  // de = 0;
  // tdea_cbc_payload_crypt(K1, K2, K3, iv, input_bytes, output_bytes, nblocks, de);

  //Test TDEA CBC MAC Generator (working, disable xor below)
  // tdea_cbc_mac_generator(K1, K2, K3, input_bytes, output_bytes, nblocks);

  //Test TDEA CTR Mode (untested against test vectors, disable xor below)
  // tdea_ctr_payload_crypt(K1, K2, K3, iv, input_bytes, output_bytes, nblocks);

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
  // fprintf (stderr, "\n Output: %s", output_bytes+offset);

  //set a pause for user interaction before closing
  fprintf (stderr, "\n\n Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}