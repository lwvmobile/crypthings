/*-------------------------------------------------------------------------------
 * scrambler.h         Crypthings
 * Scrambler Sequences
 *-----------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C"{
#endif

//function prototypes
uint32_t ls_scrambler_sequence_generator (uint32_t lfsr, uint8_t * pn, uint32_t len, uint32_t end);
uint32_t ls_scrambler_seed_calculator (uint32_t lfsr, uint32_t len, uint32_t end);
uint64_t ls_scrambler_sequence_generator_r (uint64_t lfsr, uint8_t * pn, uint32_t len, uint32_t end);
uint16_t rs_scrambler_sequence_generator (uint64_t lfsr, uint8_t * pn, uint16_t len, uint16_t end);

#ifdef __cplusplus
}
#endif