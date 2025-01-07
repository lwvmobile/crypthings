/*-------------------------------------------------------------------------------
 * utils.h         Crypthings
 * Collection of Utility Functions
 *-----------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C"{
#endif

//function prototypes
uint16_t parse_raw_user_string (char * input, uint8_t * output);
uint64_t convert_bits_into_value(uint8_t * input, int len);
uint64_t convert_bytes_into_value(uint8_t * input, int len);

void unpack_byte_array_into_bit_array (uint8_t * input, uint8_t * output, int len);
void pack_bit_array_into_byte_array (uint8_t * input, uint8_t * output, int len);
void pack_bit_array_into_byte_array_asym (uint8_t * input, uint8_t * output, int len);
void pack_value_into_bit_array (uint64_t input, uint8_t * output, uint64_t len, uint64_t shift);

void xor_bytes(uint8_t * input, uint8_t * output, int16_t start, int16_t end);
void inv_bytes(uint8_t * input, int16_t start, int16_t end);
void bit_reverse (uint8_t * input, int16_t bitlen);

//simple shift registers
void lsr_64(uint8_t * input, int16_t bitlen, uint64_t bit);
void rsr_64(uint8_t * input, int16_t bitlen, uint64_t bit);
void lsr_add(uint8_t * input, int16_t bitlen, uint8_t bit);
void rsr_add(uint8_t * input, int16_t bitlen, uint8_t bit);
void lsr_rot(uint8_t * input, int16_t bitlen);
void rsr_rot(uint8_t * input, int16_t bitlen);

//various LFSR functions
void lfsr_32_to_64(uint8_t * iv);
void lfsr_32_to_128(uint8_t * iv);
void lfsr_64_to_128(uint8_t * iv);

uint64_t lfsr_64_to_len(uint8_t * iv, int16_t len);
uint64_t reverse_lfsr_64_to_len(uint8_t * iv, int16_t len);

uint64_t lfsr_32d_to_len(uint8_t * iv, int16_t len);
uint64_t reverse_lfsr_32d_to_len(uint8_t * iv, int16_t len);

#ifdef __cplusplus
}
#endif