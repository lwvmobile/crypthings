/*-------------------------------------------------------------------------------
 * des56-ca-crypt.c         Crypthings
 * Message Encryptor/Decryptor using DES56 in LFSR based Counter Addressing Mode (1-bit)
 *
 * buid with gcc des56-ca-crypt.c ../ciphers/des/des.c ../utils/utils.c -o des56-ca-crypt.o -Wall -Wextra -Wpedantic
 * run with ./des56-ca-crypt.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc des56-ca-crypt.c ../ciphers/des/des.c ../utils/utils.c -o des56-ca-crypt.exe
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

  uint8_t key[8];
  memset (key, 0, 8*sizeof(uint8_t));

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
  int16_t  nbits = 0;
  int16_t  ffwrd = 0;   //how many increments to 'fast-forward' the IR from the LFSR Vector
  int16_t  offset = 11; //an offset value to keystream application, if required
  int16_t  confirm = 0; //confirm exit (or input values)
  uint8_t  de = 1;      //run DES Cipher in encryption mode, or decryption mode (CA always use enc)

  fprintf (stderr, "\n----------------DES56 CA Message Cipher----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, "\n Include any leading zeroes in key values, IV, and Input Message!");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, key);

  //print key
  fprintf (stderr, " Key: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", key[i]);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter MI - LFSR Value (8 octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print lfsr
  fprintf (stderr, " LFSR: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", iv[i]);
  
  //need to know whether the MI was from HDU or LDU2 ESS
  fprintf (stderr, "\n Note: The Forward Increment is derived from the location of the MI. ");
  fprintf (stderr, "\n Note: HDU is 110. LDU2 is 806. Others are Unknown. ");
  fprintf (stderr, "\n LFSR Initial Forward Increment: ");
  scanf("%hi", &ffwrd);

  //user warning and custom offset value question
  if (ffwrd != 110 && ffwrd != 806)
  {
    fprintf (stderr, " Warning! Forward Increment %d Does Not Match Known Value for HDU (110) or for LDU2 (806) ESS.", ffwrd);

    fprintf (stderr, "\n Enter Custom KS Offset Value: ");
    scanf("%hi", &offset);
    fprintf (stderr, " Custom KS Offset: %d", offset);
  }
  else
  {
    offset = 11; //known good offset for this value
    fprintf (stderr, " Forward Increment %03d; Configured for FDMA Voice Application with KS Offset: %d; ", ffwrd, offset);
  }

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //calculate the number of blocks/rounds required
  nblocks = len / 8;
  if (len % 8) nblocks += 1; //additional if not an even multiple of 8
  nblocks+=2; //no discard round executed with this CA setup, but this is required for the +11 offset

  //DES56-CA is a bit-wise operation on the des_cipher, and runs by bit number required
  nbits = nblocks * 64;

  //print input
  fprintf (stderr, "\n  In: ");
  for (i = 0; i < len; i++)
  {
    if (i == 8*11+2)
      fprintf (stderr, " ");
    else if ((i != 0) && ((i%11) == 0) && (i != 9*11))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", input_bytes[i]);
  }

  //byte-wise output of DES56-CA Keystream
  des56_ca_keystream_output(key, iv, keystream_bytes, de, ffwrd, nbits);

  fprintf (stderr, "\n  KS: ");
  for (i = 0; i < len; i++)
  {
    if (i == 8*11+2)
      fprintf (stderr, " ");
    else if ((i != 0) && ((i%11) == 0) && (i != 9*11))
      fprintf (stderr, " ");
    fprintf (stderr, "%02X", keystream_bytes[i+offset]);
  }

  //xor keystream vs input to get output
  for (i = 0; i < len; i++)
    output_bytes[i] = input_bytes[i] ^ keystream_bytes[i+offset];

  //print output
  fprintf (stderr, "\n Out: ");
  for (i = 0; i < len; i++)
  {
    if (i == 8*11+2)
      fprintf (stderr, " ");
    else if ((i != 0) && ((i%11) == 0) && (i != 9*11))
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