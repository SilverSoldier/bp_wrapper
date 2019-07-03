#include <stdbool.h>
#include <stdlib.h>

size_t gen_proof(unsigned long int secret_value, size_t range, char* commitment_return, char* blinding_return, char* proof_return);
bool verify_proof(char* proof, size_t proof_size, char* commitment, size_t range);
void gen_commitment(char* value, char* blinding, char* commitment_return);
bool add_commitment(char* comm1, char* comm2, int op, char* commitment_return);
void mult_commitment(char* comm1, int scalar, char* commitment_return);
