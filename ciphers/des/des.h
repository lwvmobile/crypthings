/*-------------------------------------------------------------------------------
 * des.h         Crypthings
 * DES Alg
 *-----------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C"{
#endif

//function prototypes
void des_cipher (uint8_t * main_key, uint8_t * input_register, uint8_t * output_register, uint8_t de);
void des56_ofb_keystream_output (uint8_t * main_key, uint8_t * iv, uint8_t * ks_bytes, uint8_t de, int16_t nblocks);
void des56_ecb_payload_crypt (uint8_t * main_key, uint8_t * input_register, uint8_t * output_register, uint8_t de);
void tdea_ecb_payload_crypt (uint8_t * K1, uint8_t * K2, uint8_t * K3, uint8_t * input, uint8_t * output, uint8_t de);
void tdea_cbc_payload_crypt (uint8_t * K1, uint8_t * K2, uint8_t * K3, uint8_t * iv, uint8_t * in, uint8_t * out, int16_t nblocks, uint8_t de);
void tdea_cfb_payload_crypt (uint8_t * K1, uint8_t * K2, uint8_t * K3, uint8_t * iv, uint8_t * in, uint8_t * out, int16_t nblocks, uint8_t de);
void tdea_tofb_keystream_output (uint8_t * K1, uint8_t * K2, uint8_t * K3, uint8_t * iv, uint8_t * ks_bytes, uint8_t de, int16_t nblocks);
void des56_ca_keystream_output (uint8_t * main_key, uint8_t * iv, uint8_t * ks_bytes, uint8_t de, int16_t ff, int16_t nbits);

#ifdef __cplusplus
}
#endif