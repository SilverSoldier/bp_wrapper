#include "bp.h"
#include <stdint.h>
#include <stdio.h>
#include <math.h>

int main() {
  uint64_t num = 165;
  char commitment[32] = {0};
  size_t range = 8;
  char blinding [32] = {0};
  int exp_ps = (2 * log2(range) + 9) * 32;
  char *proof = (char*) malloc(sizeof(char) * exp_ps);
  size_t act_ps = gen_proof(num, range, commitment, blinding, proof);

  if (act_ps != 0) {
	printf("Expected: %d, Actual: %d\n", exp_ps, act_ps);
	bool verify = verify_proof(proof, act_ps, commitment, range);
	if(verify != 0) {
	  printf("Successfully verified proof.\n");
	}
  } else {
	printf("Error generating proof.\n");
  }
  return 0;
}
