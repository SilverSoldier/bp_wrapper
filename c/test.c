#include "bp.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int test_range_proof()
{
  int i;
  uint64_t num = 210;
  size_t range = 8;
  char blinding[32] = { 0 };

  char commitment[32] = { 0 };
  char numarray[32] = { 0 };
  numarray[0] = num;
  gen_commitment(numarray, blinding, commitment);

  char dummy[32] = { 0 };
  int exp_ps = (2 * log2(range) + 9) * 32;
  char* proof = (char*)malloc(sizeof(char) * exp_ps);
  size_t act_ps = gen_proof(num, range, dummy, blinding, proof);

  if (act_ps == exp_ps) {
	bool verify = verify_proof(proof, act_ps, commitment, range);
	return verify;
  } else {
	printf("Actual proof size != expected proof size.\n");
	return 0;
  }
}

int test_gen_commitment()
{
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

  for (i = 0; i < 32; i++)
	printf("%d ", comm1[i]);

  for (i = 0; i < 32; i++) {
	if (comm1[i] != comm2[i]) {
	  return 0;
	}
  }
  return 1;
}

int test_add_comm()
{
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

  for (i = 0; i < 32; i++) {
	if (exp_comm20[i] != act_comm20[i]) {
	  return 0;
	}
  }
  return 1;
}

int test_sub_comm()
{
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

  for (i = 0; i < 32; i++) {
	if (comm0[i] != zero[i]) {
	  return 0;
	}
  }
  return 1;
}

int test_add_comm2()
{
  int i;
  char val[128] = { 0 };
  char zero[32] = { 0 };
  char comm[128] = { 0 };
  char val_exp[32] = { 0 };
  char comm_exp[32] = { 0 };
  char comm_act[32] = { 0 };

  // Put values in necessary arrays
  val[0] = 10;
  val[32] = 20;
  val[64] = 15;
  val[96] = 5;
  val_exp[0] = 50;

  // Generate commitments for all values
  for (i = 0; i < 4; ++i) {
	gen_commitment(val + 32 * i, zero, comm + 32 * i);
  }

  gen_commitment(val_exp, zero, comm_exp);

  // Compute sum of all commitments
  add_Ncommitments(comm, 4, comm_act);

  for (i = 0; i < 32; i++) {
	if (comm_act[i] != comm_exp[i]) {
	  return 0;
	}
  }
  return 1;
}

int test_mult_comm()
{
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

  for (i = 0; i < 32; i++) {
	if (exp_comm20[i] != act_comm20[i]) {
	  return 0;
	}
  }
  return 1;
}

int main()
{
  /* srand(time(NULL)); */
  /* printf("Proof generation and verification test: %s\n", test_range_proof() ? "Passed" : "Failed"); */

  /* printf("Generate Commitment Equality Test: %s\n", test_gen_commitment() ? "Passed" : "Failed"); */

  /* printf("Add Commitment Test: %s\n", test_add_comm() ? "Passed" : "Failed"); */

  /* printf("Sub Commitment Test: %s\n", test_sub_comm() ? "Passed" : "Failed"); */

  /* printf("Mult Commitment Test: %s\n", test_mult_comm() ? "Passed" : "Failed"); */

  printf("Add Multiple Commitments Test: %s\n", test_add_comm2() ? "Passed" : "Failed");

  return 0;
}
