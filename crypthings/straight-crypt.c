/*-------------------------------------------------------------------------------
 * straight-crypt.c         Crypthings
 * Message Encryptor/Decryptor using a straight xor
 *
 * buid with gcc straight-crypt.c ../utils/utils.c -o straight-crypt.o -Wall -Wextra -Wpedantic
 * run with ./straight-crypt.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc straight-crypt.c ../utils/utils.c -o straight-crypt.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../utils/utils.h"

int main (void)
{

  int16_t i = 0;
  int16_t kbitlen  = 0; //number of significant bits of key supplied
  int16_t kbytelen = 0; //kbitlen converted to len in bytes
  int16_t mask     = 0; //if a particular type of mask needs applying to a range of the result key stream

  uint8_t key[256];
  memset (key, 0, sizeof(key));

  uint8_t ks_bits[129*18*8];
  memset (ks_bits, 0, sizeof(ks_bits));

  uint8_t ks_bytes[129*18];
  memset (ks_bytes, 0, sizeof(ks_bytes));

  uint8_t input_bytes[129*18];
  memset (input_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t input_bits[129*18*8];
  memset (input_bits, 0, sizeof(input_bits));

  uint8_t output_bytes[129*18];
  memset (output_bytes, 0, 129*18*sizeof(uint8_t));

  uint8_t output_bits[129*18*8];
  memset (output_bits, 0, sizeof(output_bits));

  char input_string[3000];

  uint16_t len = 0;
  uint16_t bytelen = 0;
  uint16_t bitlen  = 0;
  int16_t  offset  = 0; //offset value to apply keystream
  int16_t  confirm = 0; //confirm exit (or input values)
  uint8_t    shift = 0; //if set, then shift last octet of key array to the left by 4 bits

  fprintf (stderr, "\n----------------Straight XOR Message Cipher----------------");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter Key (Hex): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = strlen((const char*)input_string);
  if (len&1) shift = 1; //set shift flag if odd number on len to indicate the last octet needs shifting by 4
  len = parse_raw_user_string(input_string, key);
  // if (shift) key[len-1] <<= 4; //handled by parse_raw_user_string now

  //debug print key as it is loaded in the byte array
  // fprintf (stderr, " Key: ");
  // for (i = 0; i < len; i++)
  //   fprintf (stderr, "%02X", key[i]);
  // fprintf (stderr, "\n");

  //print key value in hex
  unsigned long long int key_value = 0; 
  key_value = (unsigned long long int)convert_bytes_into_value(key, len);
  if (shift) key_value >>= 4;
  fprintf (stderr, " Key: %llX \n", key_value);

  fprintf (stderr, " Enter Number of Significant Bits in Key: ");
  scanf("%hi", &kbitlen);

  fprintf (stderr, " Is this a 48/49-bit mode operation on 56-bit input? (0-no/1-yes): ");
  scanf("%hi", &mask);

  fprintf (stderr, " Apply Keystream Offset by number of bits (0-no/#bits): ");
  scanf("%hi", &offset);

  fprintf (stderr, "\n Include any leading zeroes in Input Message!");
  fprintf (stderr, "\n");

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, "\n Enter Input Message (Hex Octets): ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, input_bytes);

  //calculate byte and bitlen
  bytelen = len;
  bitlen = len*8;

  //calculate key byte len for unpacking
  kbytelen = kbitlen/8;
  if (kbitlen%8) kbytelen++;

  //print input
  fprintf (stderr, "\n  In: ");
  for (i = 0; i < bytelen; i++)
  {
    if (mask)
    {
      if ((i != 0) && ((i%7) == 0))
        fprintf (stderr, " ");
    }
    fprintf (stderr, "%02X", input_bytes[i]);
  }

  //convert input_bytes to input_bits
  unpack_byte_array_into_bit_array(input_bytes, input_bits, bytelen);

  //convert key from bytes to bits, then expand via repititon
  unpack_byte_array_into_bit_array(key, ks_bits, kbytelen);
  int16_t k_idx = 0;
  for (i = kbitlen; i < bitlen+offset; i++)
  {
    ks_bits[i] = ks_bits[k_idx%kbitlen];
    k_idx++;
  }

  //debug print the ks_bits for comparison
  pack_bit_array_into_byte_array(ks_bits+offset, ks_bytes, bytelen);

  fprintf (stderr, "\n  KS: ");
  for (i = 0; i < bytelen; i++)
  {
    if (mask)
    {
      if ((i != 0) && ((i%7) == 0))
        fprintf (stderr, " ");
    }
    fprintf (stderr, "%02X", ks_bytes[i]);
  }

  //XOR bitwise keystream vs bitwise input_bits
  k_idx = 0;
  for (i = 0; i < bitlen; i++)
  {
    if (mask == 0)
    {
      output_bits[i] = input_bits[i] ^ ks_bits[i+offset];
    }
    else 
    {
      if ( ((i%56) < 48) )
      {
        if ( ((k_idx%48) != 8) && ((k_idx%48) != 9) && ((k_idx%48) != 10) && ((k_idx%48) != 11) )
        {
          output_bits[i] = input_bits[i] ^ ks_bits[k_idx+offset];
          k_idx++;
        }
        else k_idx++;
      }
      else
      {
        output_bits[i] = input_bits[i];
        // k_idx++;
      }
    }
  }

  //convert output_bits to output_bytes
  pack_bit_array_into_byte_array(output_bits, output_bytes, bytelen);

  //print output
  fprintf (stderr, "\n Out: ");
  for (i = 0; i < bytelen; i++)
  {
    if(mask)
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
