extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use wrapper::curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto, ristretto::RistrettoPoint};
use self::merlin::Transcript;
use self::rand::{thread_rng};
use std::slice;

#[no_mangle]
/**
Function to generate range proof for a secret value.
Input:
secret_value: Value whose range proof is being generated.
range: Range of the value. Must be a power of 2.
Output:
commitment: Pederson commitment of the value.
blinding: Blinding factor for the Pederson commitment. Returned so that further computations can be performed.
proof: Range proof as a byte array
Return:
Size of proof. O in case of errors.
*/
pub extern "C" fn gen_proof(secret_value: u64, range: usize, commitment_return: *mut [u8;32], blinding_return: *mut [u8;32], proof_return: *mut [u8]) -> usize {

    if commitment_return.is_null() || blinding_return.is_null() || proof_return.is_null() {
        return 0;
    }

    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs, valid for proofs upto bitsize 64
    let bp_gens =  BulletproofGens::new(64, 1);

    // The API takes a blinding factor for the commitment.
    let blinding = Scalar::random(&mut thread_rng());

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"hello");

    let (proof, commitment) = match RangeProof::prove_single(&bp_gens, &pc_gens, &mut prover_transcript, secret_value, &blinding, range) {
        Ok(ret) => ret,
        Err(err) => {
            println!("{}", err.to_string());
            return 0;
        }
    };

    unsafe {
        *commitment_return = commitment.to_bytes();
        *blinding_return = blinding.to_bytes();
    }

    let proof_ref: &mut[u8] = unsafe { proof_return.as_mut().unwrap() };

    proof_ref.copy_from_slice(&proof.to_bytes());

    let proof_size_return = proof.to_bytes().len();

    return proof_size_return;
}

#[no_mangle]
pub extern "C" fn verify_proof(proof: *const u8, proof_size: usize, commitment: *const u8, range: usize) -> bool {
    let mut verifier_transcript = Transcript::new(b"hello");

    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs, valid for proofs upto bitsize 64
    let bp_gens =  BulletproofGens::new(64, 1);


    let proof_bytes = unsafe {
        if proof.is_null() {
            println!("Proof is null.");
            return false;
        }
        slice::from_raw_parts(proof, proof_size)
    };

    let commitment_bytes = unsafe {
        if commitment.is_null() {
            println!("Commitment is null.");
            return false;
        }
        slice::from_raw_parts(commitment, 32)
        // CompressedRistretto::from_slice(commitment)
    };

    let commitment = CompressedRistretto::from_slice(commitment_bytes);

    // println!("Commited Value: {:?}", commitment);

    let range_proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(proof) => proof,
        Err(err) => {
            println!("{}", err.to_string());
            return false
        }
    };

    match range_proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &commitment, range) {
        Ok(_) => return true,
        Err(err) => {
            println!("Error when verifying proof: {}", err.to_string());
            return false
        }
    }
}

#[no_mangle]
pub extern "C" fn gen_commitment(value: *const u8, blinding: *const u8, commitment_return: *mut [u8;32]) {
    if commitment_return.is_null() {
        return
    }

    let mut value_array = [0; 32];
    let mut blinding_array = [0; 32];

    let val_scalar = unsafe {
        if value.is_null() {
            println!("Value is null.");
            return
        }
        let value_bytes = slice::from_raw_parts(value, 32);
        value_array.copy_from_slice(value_bytes);
        Scalar::from_bytes_mod_order(value_array)
    };

    let blinding_scalar = unsafe {
        if blinding.is_null() {
            Scalar::zero();
        }
        let blinding_bytes = slice::from_raw_parts(blinding, 32);
        blinding_array.copy_from_slice(blinding_bytes);
        Scalar::from_bytes_mod_order(blinding_array)
    };

    let pc_gens = PedersenGens::default();

    let commitment = pc_gens.commit(val_scalar, blinding_scalar).compress();

    unsafe {
        *commitment_return = commitment.to_bytes();
    };
}

fn op_comm_helper(comm: *const u8) -> Option<RistrettoPoint> {
    let comm_bytes = unsafe {
        if comm.is_null() {
            println!("Commitment is null.");
            return None;
        }
        slice::from_raw_parts(comm, 32)
    };

    CompressedRistretto::from_slice(comm_bytes).decompress() 

}

/** Function to perform add/sub operation on the Pedersen Commitments.
 * Input:
comm1: operand 1
comm2: operand 2
op: the operation to perform (0: +, 1: -)
 */ 
#[no_mangle]
pub extern "C" fn add_commitment(comm1: *const u8, comm2: *const u8, op: i32, commitment_return: *mut [u8;32]) -> bool {
    let comm1_value = match op_comm_helper(comm1) {
        Some(val) => val,
        None => {
            println!("Error reading commitment");
            return false
        }
    };
    
    let comm2_value = match op_comm_helper(comm2) {
        Some(val) => val,
        None => {
            println!("Error reading commitment");
            return false
        }
    };

    let comm_result = match op {
        0 => comm1_value + comm2_value,
        1 => comm1_value - comm2_value,
        _ => {
            println!("Operation not defined. Only input 0 or 1");
            return false
        }
    };

    unsafe {
        *commitment_return = comm_result.compress().to_bytes();
    }
    return true;
}

#[no_mangle]
pub extern "C" fn mult_commitment(comm1: *const u8, scalar: i32, commitment_return: *mut [u8;32]) {
    let comm1_value = match op_comm_helper(comm1) {
        Some(val) => val,
        None => {
            println!("Error reading commitment");
            return 
        }
    };

    let mut scalar_bytes: [u8; 32] = [0;32];
    scalar_bytes[..4].copy_from_slice(&scalar.to_le_bytes());

    let scalar_value = Scalar::from_bytes_mod_order(scalar_bytes);
    let result = comm1_value * scalar_value;

    unsafe {
        *commitment_return = result.compress().to_bytes();
    }

}

// #[no_mangle]
// pub extern "C" fn gen_commitment0(value: [u8;32], commitment_return: *mut [u8;32]) {
//     let zero = Scalar::zero();
//     gen_commitment(value, zero.to_bytes(), commitment_return);
// }

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_comm_eq() {
        let pc_gens = PedersenGens::default();

        let mut val1 = [0; 32];
        val1[0] = 10;
        
        let mut val2 = [0; 32];
        val2[0] = 10;

        let blinding = Scalar::zero();

        let comm1 = pc_gens.commit(Scalar::from_bytes_mod_order(val1), blinding).compress();

        let comm2 = pc_gens.commit(Scalar::from_bytes_mod_order(val2), blinding).compress();

        assert_eq!(comm1, comm2);
    }


    #[test]
    fn test_comm_add() {
        let pc_gens = PedersenGens::default();

        let mut val1 = [0; 32];
        val1[31] = 10;
        
        let mut val2 = [0; 32];
        val2[31] = 20;

        let blinding = Scalar::zero();

        let comm1 = pc_gens.commit(Scalar::from_bytes_mod_order(val1), blinding);

        let comm2 = pc_gens.commit(Scalar::from_bytes_mod_order(val2), blinding);

        let comm3 = comm2 - comm1 - comm1;

        assert_eq!(comm3.compress().to_bytes(), [0;32]);
    }
}
