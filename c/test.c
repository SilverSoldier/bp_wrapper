#include "bp.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>

int test_range_proof()
{
    uint64_t num = 210;
    char commitment[32] = { 0 };
    size_t range = 8;
    char blinding[32] = { 0 };
    int exp_ps = (2 * log2(range) + 9) * 32;
    char* proof = (char*)malloc(sizeof(char) * exp_ps);
    size_t act_ps = gen_proof(num, range, commitment, blinding, proof);

    if (act_ps != 0) {
	/* printf("Expected: %d, Actual: %d\n", exp_ps, act_ps); */
	bool verify = verify_proof(proof, act_ps, commitment, range);
	if (verify != 0) {
	    printf("Successfully verified proof.\n");
	}
    } else {
	printf("Error generating proof.\n");
    }
    return 0;
}

int test_gen_commitment() {
  char num1[32] = { 0 };
  char zero[32] = { 0 };
  char comm1[32] = { 0 };

  int i;
  for(i = 0; i < 32; i++){
	num1[i] = 10;
  	printf("%d\t", num1[i]);
  }

  printf("\n");

  fflush(stdout);

  gen_commitment(num1, zero, comm1);
  /* gen_commitment(num2, zero, comm2); */

  printf("\n\n");

  for(i = 0; i < 32; i++){
	printf("%d \t", comm1[i]);
  }
}

int main()
{
  /* test_range_proof(); */
  test_gen_commitment();
  return 0;
}
