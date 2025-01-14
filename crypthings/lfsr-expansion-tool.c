/*-------------------------------------------------------------------------------
 * lfsr-expansion-tool.c         Crypthings
 * Tool For running LFSR's of various tap values a specified number of
 * times in the forward direction to expand and/or iterate
 *
 * buid with gcc lfsr-expansion-tool.c ../utils/utils.c -o lfsr-expansion-tool.o -Wall -Wextra -Wpedantic
 * run with ./lfsr-expansion-tool.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc lfsr-expansion-tool.c ../utils/utils.c -o lfsr-expansion-tool.exe
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <stdio.h>
#include "../utils/utils.h"

int main (void)
{

  uint16_t i = 0;

  uint8_t iv[16];
  memset (iv, 0, 16*sizeof(uint8_t));

  char input_string[3000];

  uint16_t len = 0;
  int16_t  bittaps = 64; //what kind of LFSR are we running taps for, i.e., 32, 64, or 128
  int16_t  maxlen  = 64; //how large should the LFSR be?
  uint16_t iter = 0;     //number of times to run the LFSR
  int16_t  confirm = 0;  //confirm exit (or input values)

  fprintf (stderr, "\n----------------LFSR Expansion Tool----------------");
  fprintf (stderr, "\n");

  fprintf (stderr, "\n Include any leading zeroes!");
  fprintf (stderr, "\n");

  fprintf (stderr, " LFSR Tap Configuration (32/64): ");
  scanf("%hi", &bittaps);

  if (bittaps != 32 && bittaps != 64)
  {
    fprintf (stderr, " Invalid Response, Defaulting to 64-bit Taps ");
    bittaps = 64;
  }

  fprintf (stderr, " LFSR Max Size (32/64/128): ");
  scanf("%hi", &maxlen);

  if (maxlen != 32 && maxlen != 64 && maxlen != 128)
  {
    fprintf (stderr, " Invalid Response, Defaulting to 64-bit Size ");
    maxlen = 64;
  }

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter LFSR Value: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print lfsr
  fprintf (stderr, " LFSR: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", iv[i]);

  fprintf (stderr, "\n How Many Times? (up to 65535): ");
  scanf("%hu", &iter);

  for (i = 0; i < iter; i++)
  {
    fprintf (stderr, " ITER: %04d;", i+1);

    //expand, then rotate if needed
    if (bittaps == 32 && maxlen == 32)
    {
      lfsr_32d_to_len(iv, 32);
      fprintf (stderr, "\n");
    }
    else if (bittaps == 32 && maxlen == 64)
    {
      lfsr_32_to_64(iv);
      lsr_rot(iv, 8);
      lsr_rot(iv, 8);
      lsr_rot(iv, 8);
      lsr_rot(iv, 8);
      memset(iv+4, 0, 4*sizeof(uint8_t));
    }
    else if (bittaps == 32 && maxlen == 128)
    {
      lfsr_32_to_128(iv);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      memset(iv+12, 0, 4*sizeof(uint8_t));
    }
    else if (bittaps == 64 && maxlen == 64)
    {
      lfsr_64_to_len(iv, 64);
      fprintf (stderr, "\n");
    }
    else if (bittaps == 64 && maxlen == 128)
    {
      lfsr_64_to_128(iv);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      lsr_rot(iv, 16); lsr_rot(iv, 16);
      memset(iv+8, 0, 8*sizeof(uint8_t));
    }
    else if (bittaps == 128 && maxlen == 128)
    {
      //TODO: Make a util for this
    }
    else fprintf (stderr, " Invalid Taps and Len Configuration: %d/%d \n", bittaps, maxlen);
    
  }

  //set a pause for user interaction before closing
  fprintf (stderr, "\n\n Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}
