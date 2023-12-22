#ifndef BULLETPROOF_RANGEPROOF_H
#define BULLETPROOF_RANGEPROOF_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "secp256k1_generator.h"
#include "secp256k1_commitment.h"
#include "secp256k1_bulletproofs.h"

#define MAX_PROOF_SIZE 2000

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment **commit;
    const unsigned char **blind;
    unsigned char nonce[32];
    unsigned char **proof;
    secp256k1_bulletproof_generators *generators;
    secp256k1_generator *value_gen;
    secp256k1_generator blind_gen;
    size_t n_proofs;
    size_t plen;
    size_t *value;
    size_t n_commits;
    size_t nbits;
} bulletproof_rangeproof_t;

/**
 * Generates a specified number of secure random bytes.
 * 
 * This function reads random data from `/dev/urandom`, which is a special file
 * in Unix-like systems that serves as a pseudo-random number generator. It is
 * commonly used for generating cryptographic keys and other applications where 
 * high-quality randomness is required.
 * 
 * @param buffer A pointer to an array where the random bytes will be stored.
 * @param num_bytes The number of random bytes to generate.
 * 
 */
void generate_secure_random_bytes(unsigned char *buffer, size_t num_bytes);

/**
 * Initializes and sets up the bulletproof range proof structure.
 * 
 * This function is responsible for setting up the necessary components
 * for creating bulletproof range proofs. It initializes the secp256k1 context,
 * allocates scratch space, and creates bulletproof generators. Additionally, 
 * it handles the allocation and initialization of the proof, value generator, 
 * commitments, blinding factors, and values arrays.
 * 
 * The function generates random bytes for the nonce and generator blind, and 
 * sets up the blind generator. It also ensures that each value generator is 
 * properly generated and the necessary memory is allocated for storing proofs,
 * commitments, and blinding factors.
 * 
 * @param arg A void pointer to a bulletproof_rangeproof_t structure that will 
 *            be initialized for bulletproof range proof generation.
 * 
 * @note This function aborts the program if any critical operation such as 
 *       memory allocation or generator generation fails. It is important to 
 *       ensure that the provided argument is a valid pointer to a 
 *       bulletproof_rangeproof_t structure. The memory allocation for proofs, 
 *       commitments, blinding factors, and values is based on the number of 
 *       proofs (n_proofs) and commitments (n_commits) specified in the 
 *       bulletproof_rangeproof_t structure. The created secp256k1_context is 
 *       configured for both signing and verification purposes.
 */
static void bulletproof_rangeproof_setup(void* arg);

/**
 * Performs Pedersen commitments for the bulletproof range proof.
 * 
 * This function iterates over the number of commitments specified in the 
 * bulletproof_rangeproof_t structure and performs a Pedersen commitment for
 * each value. It starts by generating a random blinding factor and then modifies
 * it slightly for each commitment to ensure uniqueness.
 * 
 * Each commitment is calculated using the `secp256k1_pedersen_commit` function,
 * which combines the value to be committed, the blinding factor, and the
 * generators for the commitment calculation.
 * 
 * @param arg A void pointer to a bulletproof_rangeproof_t structure that contains
 *            the data required for performing Pedersen commitments, including
 *            the context, value generators, and blind generators.
 * 
 * @note The function aborts the program if the Pedersen commitment fails for
 *       any of the values. This could be due to memory allocation failures or
 *       issues with the commitment calculation. The commitments for each value
 *       are stored in the provided bulletproof_rangeproof_t structure, and each
 *       blinding factor is slightly modified to maintain uniqueness.
 */
static void bulletproof_rangeproof_pedersen_commit(void* arg);

/**
 * Cleans up and frees resources allocated for the bulletproof range proof.
 *
 * This function is responsible for safely deallocating all memory that was
 * allocated for a bulletproof range proof operation. It iterates through
 * the arrays of blinding factors, Pedersen commitments, proofs, and value
 * generators, freeing each element and then the array itself.
 *
 * The function ensures that all memory allocated during the bulletproof
 * range proof process is properly released, preventing memory leaks.
 *
 * @param arg A void pointer to a bulletproof_rangeproof_t structure that
 *            contains the data and resources allocated for the bulletproof
 *            range proof operation.
 *
 * @note This function should be called after the bulletproof range proof
 *       process is complete, to ensure that all allocated resources are
 *       released. Failing to call this function can result in memory leaks.
 */
static void bulletproof_rangeproof_teardown(void* arg);

/**
 * Generates bulletproof range proofs for a set of values.
 *
 * This function generates bulletproof range proofs for each value specified in
 * the bulletproof_rangeproof_t structure. These range proofs are cryptographic
 * proofs that ensure the values are within a specified range, without revealing
 * the values themselves. This function is part of the privacy-preserving features
 * of the bulletproof algorithm.
 *
 * @param arg A void pointer to a bulletproof_rangeproof_t structure containing
 *            the data necessary to generate the range proofs. This includes
 *            the context, scratch space, generators, values, blinding factors,
 *            and other parameters.
 *
 * @note This function will abort the program if the range proof generation fails.
 *       Ensure that all parameters are correctly set before calling this function.
 */
static void bulletproof_rangeproof_prove(void* arg);

/**
 * Verifies bulletproof range proofs for a set of commitments.
 *
 * This function performs the verification of bulletproof range proofs, ensuring
 * that the values committed to in the Pedersen commitments are within the
 * specified range. It is a crucial part of the verification process in
 * bulletproof-based systems, enabling the validation of data integrity without
 * compromising privacy.
 *
 * @param arg A void pointer to a bulletproof_rangeproof_t structure containing
 *            the range proofs, Pedersen commitments, and other data required
 *            for verification. This includes the context, scratch space,
 *            and generators.
 *
 * @note The function iterates through multiple iterations (as specified in
 *       the bulletproof_rangeproof_t structure) to perform the verification.
 *       It aborts the program if any of the range proofs fail verification.
 */
static void bulletproof_rangeproof_verify(void* arg);

#endif // BULLETPROOF_RANGEPROOF_H
