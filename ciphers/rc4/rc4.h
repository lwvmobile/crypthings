/*-------------------------------------------------------------------------------
 * rc4.h         Crypthings
 * RC4 Alg
 *-----------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C"{
#endif

//function prototypes
void rc4_keystream_output(int16_t drop, uint8_t keylength, int16_t nbytes, uint8_t * key, uint8_t * ks_bytes);

#ifdef __cplusplus
}
#endif