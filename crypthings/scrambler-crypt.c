/*-------------------------------------------------------------------------------
 * scrambler-crypt.c         Crypthings
 * Message Encryptor/Decryptor using Scrambler w/ LFSR Taps (known 8, 9, 15, 16, 24, and 44 bit modes)
 *
 * buid with gcc scrambler-crypt.c ../ciphers/scrambler/scrambler.c ../utils/utils.c -o scrambler-crypt.o -Wall -Wextra -Wpedantic
 * run with ./scrambler-crypt.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc scrambler-crypt.c ../ciphers/scrambler/scrambler.c ../utils/utils.c -o scrambler-crypt.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../ciphers/scrambler/scrambler.h"
#include "../utils/utils.h"

int main (void)
{

  uint32_t i = 0;
  
  unsigned long long int lfsr = 0; 

  uint8_t pn[129*18*8];
  memset (pn, 0, sizeof(pn));

  uint8_t pn_bytes[129*18];
  memset (pn_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t input_bits[129*18*8];
  memset (input_bits, 0, sizeof(input_bits));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bits[129*18*8];
  memset (output_bits, 0, sizeof(output_bits));

  char input_string[3000];

  uint32_t len     = 0;
  uint32_t bytelen = 0;
  uint32_t bitlen  = 0;
  uint16_t kbitlen = 0;
  uint8_t  bits49  = 0; //is this a select 49-bit operation
  uint32_t offset  = 0; //offset value to apply keystream
  int16_t  confirm = 0; //confirm exit (or input values)

  fprintf (stderr, "\n----------------Scrambler Message Cipher----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, "\n Include any leading zeroes in Input Message!");
  fprintf (stderr, "\n");

  fprintf (stderr, " Enter Key or Seed Value (hex): ");
  scanf("%llX", &lfsr);

  //print key
  fprintf (stderr, " Key: %llX (%lld)", lfsr, lfsr);

  fprintf (stderr, "\n");
  fprintf (stderr, " Enter Number of bits in Key/Seed (dec): ");
  scanf("%hu", &kbitlen);

  fprintf (stderr, " Apply Keystream Offset by number of bits (0-no/#bits): ");
  scanf("%u", &offset);

  fprintf (stderr, " Is this a 49-bit mode operation on 56-bit input? (0-no/1-yes): ");
  scanf("%hhu", &bits49);

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //calculate byte and bitlen
  bytelen = len;
  bitlen = len*8;

  //print input
  fprintf (stderr, "\n  Input: ");
  for (i = 0; i < bytelen; i++)
  {
    if (bits49)
    {
      if ((i != 0) && ((i%7) == 0))
        fprintf (stderr, " ");
    }
    fprintf (stderr, "%02X", input_bytes[i]);
  }

  //convert input_bytes to input_bits
  unpack_byte_array_into_bit_array(input_bytes, input_bits, bytelen);

  //scrambler pseudo-random number sequence
  if (kbitlen == 15)
    rs_scrambler_sequence_generator(lfsr, pn, kbitlen, bitlen+offset);
  else if (kbitlen == 9 || kbitlen == 44)
    ls_scrambler_sequence_generator_r(lfsr, pn, kbitlen, bitlen+offset);
  else
    ls_scrambler_sequence_generator(lfsr, pn, kbitlen, bitlen+offset);

  //debug print the pn sequence for comparison
  pack_bit_array_into_byte_array(pn+offset, pn_bytes, bytelen);

  fprintf (stderr, "\n     KS: ");
  for (i = 0; i < bytelen; i++)
  {
    if (bits49)
    {
      if ((i != 0) && ((i%7) == 0))
        fprintf (stderr, " ");
    }
    fprintf (stderr, "%02X", pn_bytes[i]);
  }

  //XOR bitwise keystream vs bitwise input_bits
  uint16_t k_idx = 0;
  for (i = 0; i < bitlen; i++)
  {
    if (bits49)
    {
      if (i%56 < 49)
        output_bits[i] = input_bits[i] ^ pn[(k_idx++)+offset];
    }
    else output_bits[i] = input_bits[i] ^ pn[(k_idx++)+offset];
    
  }

  //convert output_bits to output_bytes
  pack_bit_array_into_byte_array(output_bits, output_bytes, bytelen);

  //print output
  fprintf (stderr, "\n Output: ");
  for (i = 0; i < bytelen; i++)
  {
    if(bits49)
    {
      if ((i != 0) && ((i%7) == 0))
        fprintf (stderr, " ");
    }
    fprintf (stderr, "%02X", output_bytes[i]);
  }
  
  //print output (as string)
  // fprintf (stderr, "\n Output: %s", output_bytes+offset);

  //set a pause for user interaction before closing
  fprintf (stderr, "\n\n Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}
