/*-------------------------------------------------------------------------------
 * lfsr-recovery-tool.c         Crypthings
 * Tool For running LFSR's of various tap values a specified number of
 * times in the forward or reverse direction
 *
 * buid with gcc lfsr-recovery-tool.c ../utils/utils.c -o lfsr-recovery-tool.o -Wall -Wextra -Wpedantic
 * run with ./lfsr-recovery-tool.o
 * 
 * cross compile for windows: 
 * /usr/bin/x86_64-w64-mingw32-gcc lfsr-recovery-tool.c ../utils/utils.c -o lfsr-recovery-tool.exe
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

  uint8_t iv[8];
  memset (iv, 0, 8*sizeof(uint8_t));

  char input_string[3000];

  uint16_t len = 0;
  int16_t  bittaps = 64; //what kind of LFSR are we running taps for, i.e., 32, 64, or 128
  int16_t  ffwrd = 0;    //how many increments cycle the LFSR
  uint16_t iter = 0;     //number of times to run the LFSR
  int16_t  dir = 1;      //run in forward, or reverse direction?
  int16_t  confirm = 0;  //confirm exit (or input values)

  fprintf (stderr, "\n----------------LFSR Recovery Tool----------------");
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

  memset (input_string, 0, 2048*sizeof(char));
  fprintf (stderr, " Enter LFSR Value: ");
  scanf("%s", input_string); //no white space allowed
  input_string[2999] = '\0'; //terminate string
  len = parse_raw_user_string(input_string, iv);

  //print lfsr
  fprintf (stderr, " LFSR: ");
  for (i = 0; i < len; i++)
    fprintf (stderr, "%02X", iv[i]);
  
  fprintf (stderr, "\n LFSR Increment: ");
  scanf("%hi", &ffwrd);

  fprintf (stderr, " How Many Times? (up to 65535): ");
  scanf("%hu", &iter);

  fprintf (stderr, " Direction? (0-reverse/1-forward): ");
  scanf("%hi", &dir);

  if (dir != 0 && dir != 1)
  {
    fprintf (stderr, " Invalid Response, Defaulting to Forward Direction ");
    dir = 1;
  }

  for (i = 0; i < iter; i++)
  {
    fprintf (stderr, "\n ITER: %04d;", i+1);
    if (dir)
    {
      if (bittaps == 64)
        lfsr_64_to_len(iv, ffwrd);
      else lfsr_32d_to_len(iv, ffwrd);
    }
    else
    {
      if (bittaps == 64)
        reverse_lfsr_64_to_len(iv, ffwrd);
      else reverse_lfsr_32d_to_len(iv, ffwrd);
    }
  }

  //set a pause for user interaction before closing
  fprintf (stderr, "\n\n Enter any value to Exit: ");
  scanf("%hi", &confirm);

  return 0;
}
