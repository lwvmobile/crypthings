/*-------------------------------------------------------------------------------
 * utils.c         Crypthings
 * Collection of Utility Functions
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

//convert a user string into a uint8_t array
uint16_t parse_raw_user_string (char * input, uint8_t * output)
{
  //since we want this as octets, get strlen value, then divide by two
  uint16_t len = strlen((const char*)input);
  
  //if zero is returned, just do two
  if (len == 0) len = 2;

  //if odd number, then user didn't pass complete octets, but just add one to len value to make it even
  if (len&1) len++;

  //divide by two to get octet len
  len /= 2;

  char octet_char[3];
  octet_char[2] = 0;
  uint16_t k = 0;
  uint16_t i = 0;

  for (i = 0; i < len; i++)
  {
    strncpy (octet_char, input+k, 2);
    octet_char[2] = 0;
    sscanf (octet_char, "%hhX", &output[i]);

    k += 2;
  }

  return len;
}

//input bit array, return output as up to a 64-bit value
uint64_t convert_bits_into_value(uint8_t * input, int len)
{
  int i;
  uint64_t output = 0;
  for(i = 0; i < len; i++)
  {
    output <<= 1;
    output |= (uint64_t)(input[i] & 1);
  }
  return output;
}

//input byte array, return output as up to a 64-bit value
uint64_t convert_bytes_into_value(uint8_t * input, int len)
{
  int i;
  uint64_t output = 0;
  for(i = 0; i < len; i++)
  {
    output <<= 8;
    output |= (uint64_t)(input[i] & 0xFF);
  }
  return output;
}

//take len amount of bytes and unpack back into a bit array
void unpack_byte_array_into_bit_array (uint8_t * input, uint8_t * output, int len)
{
  int i = 0, k = 0;
  for (i = 0; i < len; i++)
  {
    output[k++] = (input[i] >> 7) & 1;
    output[k++] = (input[i] >> 6) & 1;
    output[k++] = (input[i] >> 5) & 1;
    output[k++] = (input[i] >> 4) & 1;
    output[k++] = (input[i] >> 3) & 1;
    output[k++] = (input[i] >> 2) & 1;
    output[k++] = (input[i] >> 1) & 1;
    output[k++] = (input[i] >> 0) & 1;
  }
}

//take x amount of bits and pack into len amount of bytes (symmetrical)
void pack_bit_array_into_byte_array (uint8_t * input, uint8_t * output, int len)
{
  int i;
  for (i = 0; i < len; i++)
    output[i] = (uint8_t)convert_bits_into_value(&input[i*8], 8);
}

//take len amount of bits and pack into x amount of bytes (asymmetrical)
void pack_bit_array_into_byte_array_asym (uint8_t * input, uint8_t * output, int len)
{
  int i = 0; int k = len % 8;
  for (i = 0; i < len; i++)
  {
    output[i/8] <<= 1;
    output[i/8] |= input[i];
  }
  //if any leftover bits that don't flush the last byte fully packed, shift them over left
  if (k)
    output[i/8] <<= 8-k;
}

void xor_bytes(uint8_t * input, uint8_t * output, int16_t start, int16_t end)
{
  for (int16_t i = start; i < end; i++)
    output[i] ^= input[i];
}

void inv_bytes(uint8_t * input, int16_t start, int16_t end)
{
  for (int16_t i = start; i < end; i++)
    input[i] = ~input[i] & 0xFF;
}

//reverse the bits of an inputted array of bits
void bit_reverse (uint8_t * input, int16_t bitlen)
{

  uint8_t reverse[65535]; //largest 16 bit value
  memset(reverse, 0, sizeof(reverse));

  for (int16_t i = 0; i < bitlen; i++)
    reverse[i] = input[((bitlen-1)-i)];

  memset(input, 0, bitlen*sizeof(uint8_t));
  memcpy(input, reverse, bitlen*sizeof(uint8_t));

  //NOTE: This debug output will only work up to 64-bit
  // uint64_t sr = convert_bits_into_value_xl(input, bitlen);
  // fprintf (stderr, "\n REV: %016lX", sr);

}

//simple shift registers (up to 64 bits)
void lsr_64(uint8_t * input, int16_t bitlen, uint64_t bit)
{

  uint64_t sr = 0;

  sr = convert_bits_into_value(input, 64);

  memset (input, 0, bitlen*sizeof(uint8_t));

  sr = (sr << 1) | bit;

  for (int16_t i = 0; i < bitlen; i++)
    input[i] = ( sr >> ((bitlen-1)-i) ) & 1;

  // fprintf (stderr, "\n LSR: %016lX", sr);

}

void rsr_64(uint8_t * input, int16_t bitlen, uint64_t bit)
{

  uint64_t sr = 0;

  sr = convert_bits_into_value(input, bitlen);

  memset (input, 0, bitlen*sizeof(uint8_t));

  sr = (sr >> 1) | (bit << (bitlen-1));

  for (int16_t i = 0; i < bitlen; i++)
    input[i] = ( sr >> ((bitlen-1)-i) ) & 1;

  // fprintf (stderr, "\n RSR: %016lX", sr);

}

void lsr_add(uint8_t * input, int16_t bitlen, uint8_t bit)
{

  for (int16_t i = 0; i < (bitlen-1); i++)
    input[i] = input[i+1];
  input[(bitlen-1)] = bit;

}

void rsr_add(uint8_t * input, int16_t bitlen, uint8_t bit)
{

  for (int16_t i = 0; i < (bitlen-1); i++)
    input[i+1] = input[i];
  input[0] = bit;

}

void lsr_rot(uint8_t * input, int16_t bitlen)
{

  uint8_t bit = input[0];
  for (int16_t i = 0; i < (bitlen-1); i++)
    input[i] = input[i+1];
  input[(bitlen-1)] = bit;

}

void rsr_rot(uint8_t * input, int16_t bitlen)
{

  uint8_t bit = input[bitlen-1];
  for (int16_t i = 0; i < (bitlen-1); i++)
    input[i+1] = input[i];
  input[0] = bit;

}

//various LFSR functions

//if supplied IV is only 32-bit in value, then expand it to a 64-bit IV using these LFSR taps
void lfsr_32_to_64(uint8_t * iv)
{
  uint64_t lfsr = 0, bit = 0;

  lfsr = ((uint64_t)iv[0] << 24ULL) + ((uint64_t)iv[1] << 16ULL) + ((uint64_t)iv[2] << 8ULL)  + ((uint64_t)iv[3] << 0ULL);

  uint8_t cnt = 0, x = 32;

  for(cnt = 0; cnt < 64; cnt++) 
  {
    //32,22,2,1 (per Xilinx XAPP 052) Table 3: Taps for Maximum-Length LFSR Counters
    bit = ( (lfsr >> 31) ^ (lfsr >> 21) ^ (lfsr >> 1) ^ (lfsr >> 0) ) & 0x1;
    lfsr = (lfsr << 1) | bit;

    //continue packing iv
    iv[x/8] = (iv[x/8] << 1) + bit;

    x++;
  }

  fprintf (stderr, "\n IV(64): ");
  for (x = 0; x < 16; x++)
    fprintf (stderr, "%02X", iv[x]);
  fprintf (stderr, "\n");

}

//if supplied IV is only 32-bit in value, then expand it to a 128-bit IV using these LFSR taps
void lfsr_32_to_128(uint8_t * iv)
{
  uint64_t lfsr = 0, bit = 0;

  lfsr = ((uint64_t)iv[0] << 24ULL) + ((uint64_t)iv[1] << 16ULL) + ((uint64_t)iv[2] << 8ULL)  + ((uint64_t)iv[3] << 0ULL);

  uint8_t cnt = 0, x = 32;

  for(cnt = 0; cnt < 96; cnt++) 
  {
    //32,22,2,1 (per Xilinx XAPP 052) Table 3: Taps for Maximum-Length LFSR Counters
    bit = ( (lfsr >> 31) ^ (lfsr >> 21) ^ (lfsr >> 1) ^ (lfsr >> 0) ) & 0x1;
    lfsr = (lfsr << 1) | bit;

    //continue packing iv
    iv[x/8] = (iv[x/8] << 1) + bit;

    x++;
  }

  fprintf (stderr, "\n IV(128): ");
  for (x = 0; x < 16; x++)
    fprintf (stderr, "%02X", iv[x]);
  fprintf (stderr, "\n");

}

//if supplied IV is only 64-bit in value, then expand it to a 128-bit IV using these LFSR taps
void lfsr_64_to_128(uint8_t * iv)
{
  uint64_t lfsr = 0, bit = 0;

  lfsr = ((uint64_t)iv[0] << 56ULL) + ((uint64_t)iv[1] << 48ULL) + ((uint64_t)iv[2] << 40ULL) + ((uint64_t)iv[3] << 32ULL) + 
         ((uint64_t)iv[4] << 24ULL) + ((uint64_t)iv[5] << 16ULL) + ((uint64_t)iv[6] << 8ULL)  + ((uint64_t)iv[7] << 0ULL);

  uint8_t cnt = 0, x = 64;

  for(cnt = 0; cnt < 64; cnt++) 
  {
    //63,61,45,37,27,14
    // Polynomial is C(x) = x^64 + x^62 + x^46 + x^38 + x^27 + x^15 + 1
    bit = ((lfsr >> 63) ^ (lfsr >> 61) ^ (lfsr >> 45) ^ (lfsr >> 37) ^ (lfsr >> 26) ^ (lfsr >> 14)) & 0x1;
    lfsr = (lfsr << 1) | bit;

    //continue packing iv
    iv[x/8] = (iv[x/8] << 1) + bit;

    x++;
  }

  fprintf (stderr, "\n IV(128): ");
  for (x = 0; x < 16; x++)
    fprintf (stderr, "%02X", iv[x]);
  fprintf (stderr, "\n");

}

uint64_t lfsr_64_to_len(uint8_t * iv, int16_t len)
{

  uint64_t lfsr = 0, bit = 0;

  lfsr = ((uint64_t)iv[0] << 56ULL) + ((uint64_t)iv[1] << 48ULL) + ((uint64_t)iv[2] << 40ULL) + ((uint64_t)iv[3] << 32ULL) + 
         ((uint64_t)iv[4] << 24ULL) + ((uint64_t)iv[5] << 16ULL) + ((uint64_t)iv[6] << 8ULL)  + ((uint64_t)iv[7] << 0ULL);

  memset (iv, 0, 8*sizeof(uint8_t));

  for(int16_t cnt = 0; cnt < len; cnt++)
  {
    //63,61,45,37,27,14
    // Polynomial is C(x) = x^64 + x^62 + x^46 + x^38 + x^27 + x^15 + 1
    bit = ((lfsr >> 63) ^ (lfsr >> 61) ^ (lfsr >> 45) ^ (lfsr >> 37) ^ (lfsr >> 26) ^ (lfsr >> 14)) & 0x1;
    lfsr = (lfsr << 1) | bit;
  }

  for (int16_t i = 0; i < 8; i++)
    iv[i] = (lfsr >> (56-(i*8))) & 0xFF;

  // fprintf (stderr, "\n IV(%02d): ", len);
  // for (int16_t i = 0; i < 8; i++)
  //   fprintf (stderr, "%02X", iv[i]);

  return bit;

}

uint64_t reverse_lfsr_64_to_len(uint8_t * iv, int16_t len)
{

  uint64_t lfsr = 0, bit1 = 0, bit2 = 0;

  lfsr = ((uint64_t)iv[0] << 56ULL) + ((uint64_t)iv[1] << 48ULL) + ((uint64_t)iv[2] << 40ULL) + ((uint64_t)iv[3] << 32ULL) + 
         ((uint64_t)iv[4] << 24ULL) + ((uint64_t)iv[5] << 16ULL) + ((uint64_t)iv[6] << 8ULL)  + ((uint64_t)iv[7] << 0ULL);

  memset (iv, 0, 8*sizeof(uint8_t));

  for(int16_t cnt = 0; cnt < len; cnt++)
  {
    //63,61,45,37,27,14
    // Polynomial is C(x) = x^64 + x^62 + x^46 + x^38 + x^27 + x^15 + 1

    //basically, just get the taps at the +1 position on all but MSB, then check the LSB and configure bit as required
    bit1 = ((lfsr >> 62) ^ (lfsr >> 46) ^ (lfsr >> 38) ^ (lfsr >> 27) ^ (lfsr >> 15)) & 0x1;
    bit2 = lfsr & 1;
    if (bit1 == bit2)
      bit2 = 0;
    else bit2 = 1;

    //just run this in reverse of normal LFSR
    lfsr = (lfsr >> 1) | (bit2 << 63);
  }

  for (int16_t i = 0; i < 8; i++)
    iv[i] = (lfsr >> (56-(i*8))) & 0xFF;

  // fprintf (stderr, "\n RV(%02d): ", len);
  // for (int16_t i = 0; i < 8; i++)
  //   fprintf (stderr, "%02X", iv[i]);

  return bit2;

}