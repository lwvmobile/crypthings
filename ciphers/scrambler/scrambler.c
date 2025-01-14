/*-------------------------------------------------------------------------------
 * scrambler.c         Crypthings
 * Scrambler Sequences
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>

//scrambler pn sequence generation with left shift
uint32_t ls_scrambler_sequence_generator (uint32_t lfsr, uint8_t * pn, uint32_t len, uint32_t end)
{

  uint32_t bit;

  //run pN sequence with taps specified
  for (uint32_t i = 0; i < end; i++)
  {
    //get feedback bit with specified taps, depending on the len
    if (len == 8)
      bit = (lfsr >> 7) ^ (lfsr >> 5) ^ (lfsr >> 4) ^ (lfsr >> 3);
    else if (len == 16)
      bit = (lfsr >> 15) ^ (lfsr >> 14) ^ (lfsr >> 12) ^ (lfsr >> 3);
    else if (len == 24)
      bit = (lfsr >> 23) ^ (lfsr >> 22) ^ (lfsr >> 21) ^ (lfsr >> 16);
    else bit = 0; //should never get here, but just in case
    
    bit &= 1; //truncate bit to 1 bit
    lfsr = (lfsr << 1) | bit; //shift LFSR left once and OR bit onto LFSR's LSB
    pn[i] = bit;

  }

  return lfsr;
}

//scrambler seed calculator based on run end value
uint32_t ls_scrambler_seed_calculator (uint32_t lfsr, uint32_t len, uint32_t end)
{

  uint64_t bit;

  //run sequence with taps specified
  for (uint32_t i = 0; i < end; i++)
  {
    //get feedback bit with specified taps, depending on the len
    if (len == 8)
      bit = (lfsr >> 7) ^ (lfsr >> 5) ^ (lfsr >> 4) ^ (lfsr >> 3);
    else if (len == 16)
      bit = (lfsr >> 15) ^ (lfsr >> 14) ^ (lfsr >> 12) ^ (lfsr >> 3);
    else if (len == 24)
      bit = (lfsr >> 23) ^ (lfsr >> 22) ^ (lfsr >> 21) ^ (lfsr >> 16);
    else bit = 0; //should never get here, but just in case
    
    bit &= 1; //truncate bit to 1 bit
    lfsr = (lfsr << 1) | bit; //shift LFSR left once and OR bit onto LFSR's LSB

  }

  return lfsr;
}

//scrambler pn sequence generation with left shift, pn bits loaded before feedback bit processed
uint64_t ls_scrambler_sequence_generator_r (uint64_t lfsr, uint8_t * pn, uint32_t len, uint32_t end)
{

  uint64_t bit;

  //run pN sequence with taps specified
  for (uint32_t i = 0; i < end; i++)
  {

    //pn sequence is initiaed with the lfsr value, so first len bits of pn are the same as the LFSR
    
    //get feedback bit with specified taps, depending on the len
    if (len == 9)
    {
      pn[i] = lfsr >> 8;
      bit = ((lfsr >> 8) ^ (lfsr >> 4));
    }
    else if (len == 44)
    {
      pn[i] = lfsr >> 43;
      bit = ((lfsr >> 33) ^ (lfsr >> 19) ^ (lfsr >> 14) ^ (lfsr >> 8) ^ (lfsr >> 3) ^ (lfsr >> 43)) & 0x1;
    }
    else bit = 0; //should never get here, but just in case
    
    bit &= 1; //truncate bit to 1 bit
    lfsr = (lfsr << 1) | bit; //shift LFSR left once and OR bit onto LFSR's LSB

  }

  return lfsr;
}

//scrambler pn sequence generation with right shift and rotation
uint16_t rs_scrambler_sequence_generator (uint64_t lfsr, uint8_t * pn, uint16_t len, uint16_t end)
{

  uint64_t bit;

  //run pN sequence with taps specified
  for (uint16_t i = 0; i < end; i++)
  {
    pn[i] = lfsr & 1;

    //get feedback bit with specified taps, depending on the len
    if (len == 15)
      bit = ( (lfsr >> 1) ^ (lfsr >> 0) );
    else bit = 0; //should never get here, but just in case
    
    bit &= 1; //truncate bit to 1 bit
    lfsr = ( (lfsr >> 1 ) | (bit << 14) ); //shift LFSR right once and OR bit onto LFSR's MSB

  }

  return lfsr;
}
