#include "bp.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>

int test_range_proof() {
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
    return verify;
	}
	return 0;
}

int test_gen_commitment() {
  int i;
  char num1[32] = { 0 };
  char num2[32] = { 0 };
  char zero[32] = { 0 };
  char comm1[32] = { 0 };
  char comm2[32] = { 0 };

  num1[10] = 10;
  num2[10] = 10;
  
  gen_commitment(num1, zero, comm1);
  gen_commitment(num2, zero, comm2);

  for(i = 0; i < 32; i++){
	if (comm1[i] != comm2[i]) {
	  return 0;
	}
  }
  return 1;
}

int test_add_comm() {
  int i;
  char val10[32] = { 0 };
  char val20[32] = { 0 };
  char zero[32] = { 0 };
  char comm10[32] = { 0 };
  char exp_comm20[32] = { 0 };
  char act_comm20[32] = { 0 };

  // Put values in necessary arrays
  val10[0] = 10;
  val20[0] = 20;

  // Generate commitments for 10 and 20
  gen_commitment(val10, zero, comm10);
  gen_commitment(val20, zero, exp_comm20);

  // Generate multiplication of 10 and 2
  add_commitment(comm10, comm10, 0, act_comm20);
  
  for(i = 0; i < 32; i++){
	if (exp_comm20[i] != act_comm20[i]) {
	  return 0;
	}
  }
  return 1;
} 

int test_sub_comm() {
  int i;
  char val10[32] = { 0 };
  char zero[32] = { 0 };
  char comm10[32] = { 0 };
  char comm0[32] = { 0 };

  // Put values in necessary arrays
  val10[0] = 10;

  // Generate commitments for 10 and 20
  gen_commitment(val10, zero, comm10);

  // Generate multiplication of 10 and 2
  add_commitment(comm10, comm10, 1, comm0);
  
  for(i = 0; i < 32; i++){
	if (comm0[i] != zero[i]) {
	  return 0;
	}
  }
  return 1;
} 

int test_mult_comm() {
  int i;
  char val10[32] = { 0 };
  char val20[32] = { 0 };
  char zero[32] = { 0 };
  char comm10[32] = { 0 };
  char exp_comm20[32] = { 0 };
  char act_comm20[32] = { 0 };

  // Put values in necessary arrays
  val10[0] = 10;
  val20[0] = 20;

  // Generate commitments for 10 and 20
  gen_commitment(val10, zero, comm10);
  gen_commitment(val20, zero, exp_comm20);

  // Generate multiplication of 10 and 2
  mult_commitment(comm10, 2, act_comm20);
  
  for(i = 0; i < 32; i++){
	if (exp_comm20[i] != act_comm20[i]) {
	  return 0;
	}
  }
  return 1;
}

int main()
{
  srand(time(null));
  printf("Generate Commitment Equality Test: %s\n", test_gen_commitment() ? "Passed" : "Failed");

  printf("Add Commitment Test: %s\n", test_add_comm() ? "Passed" : "Failed");

  printf("Sub Commitment Test: %s\n", test_sub_comm() ? "Passed" : "Failed");

  printf("Mult Commitment Test: %s\n", test_mult_comm() ? "Passed" : "Failed");

  printf("Proof generation and verification test: %s\n", test_range_proof() ? "Passed" : "Failed");

  return 0;
}
