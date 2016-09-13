#include "crapto1.h"
#include <stdio.h>

int main (void)
{
 struct Crypto1State *revstate;
 uint64_t lfsr;
 unsigned char* plfsr = (unsigned char*)&lfsr;


 uint32_t uid                = 0x9c599b32;
 uint32_t tag_challenge      = 0x82a4166c;
 uint32_t nr_enc             = 0xa1e458ce;
 uint32_t reader_response    = 0x6eea41e0;
 uint32_t tag_response       = 0x5cadf439;

 uint32_t ks2                = reader_response ^ prng_successor(tag_challenge, 64);
 uint32_t ks3                = tag_response ^ prng_successor(tag_challenge, 96);

 printf("nt' : %08x\n",prng_successor(tag_challenge, 64));
 printf("nt'': %08x\n",prng_successor(tag_challenge, 96));

 printf("ks2 : %08x\n",ks2);
 printf("ks3 : %08x\n",ks3);

 revstate = lfsr_recovery64(ks2, ks3);
 
 lfsr_rollback_word(revstate, 0, 0);
 lfsr_rollback_word(revstate, 0, 0);
 lfsr_rollback_word(revstate, nr_enc, 1);
 lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
 crypto1_get_lfsr(revstate, &lfsr);
 printf("Found Key: [%02x %02x %02x %02x %02x %02x]\n\n",plfsr[5],plfsr[4],plfsr[3],plfsr[2],plfsr[1],plfsr[0]);

 return 0;
}
