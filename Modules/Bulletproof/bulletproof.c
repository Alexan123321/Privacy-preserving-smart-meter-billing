#include "bulletproof_rangeproof.h"

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
void generate_secure_random_bytes(unsigned char *buffer, size_t num_bytes) {
    int fd = open("/dev/urandom", O_RDONLY);    //unix based not portable
    if (fd < 0) 
    {abort();}    // Error opening /dev/urandom

    ssize_t read_bytes = read(fd, buffer, num_bytes);   // Read specified number of bytes from the file descriptor into buffer
    close(fd);

    if (read_bytes < 0 || (size_t)read_bytes != num_bytes) 
    {abort();}    // Error reading the required number of bytes
}

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
static void bulletproof_rangeproof_setup(void* arg){
    bulletproof_rangeproof_t *data = (bulletproof_rangeproof_t*)arg;
    size_t i;

    data->blind_gen = secp256k1_generator_const_g;
    data->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data->scratch = secp256k1_scratch_space_create(data->ctx, 1024 * 1024 * 1024);
    data->generators = secp256k1_bulletproof_generators_create(data->ctx, &data->blind_gen, 64 * 1024);

    const unsigned char genbd[32];
    unsigned char u_nonce[32];
    unsigned char u_genbd[32];

    generate_secure_random_bytes(u_nonce, sizeof(u_nonce));  //Make u_nonce random
    
    generate_secure_random_bytes(u_genbd, sizeof(u_genbd));  //Make u_genbd random

    memcpy(data->nonce, u_nonce, 32);
    memcpy((unsigned char*) genbd, u_genbd, 32);

    data->proof = (unsigned char **)malloc(data->n_proofs * sizeof(*data->proof));                      //check this
    data->value_gen = (secp256k1_generator *)malloc(data->n_proofs * sizeof(*data->value_gen));
    if (data->proof == NULL || data->value_gen == NULL) {
        abort();
    }
    for (i = 0; i < data->n_proofs; i++) {
        data->proof[i] = (unsigned char *)malloc(MAX_PROOF_SIZE);
        if (data->proof[i] == NULL) {abort();}
        // Generate a value generator for each proof; abort if generation fails
        if(secp256k1_generator_generate(data->ctx, &data->value_gen[i], genbd) != 1) {abort();}
    }
    data->plen = MAX_PROOF_SIZE;
    
    //Pedersen init
    data->commit = (secp256k1_pedersen_commitment **)malloc(data->n_proofs * sizeof(*data->commit));    //check these
    data->blind = (const unsigned char **)malloc(data->n_commits * sizeof(*data->blind));
    data->value = (size_t *)malloc(data->n_commits * sizeof(*data->commit));
    if (data->commit == NULL || data->blind == NULL || data->value == NULL) {abort();}

    for (i = 0; i < data->n_proofs; i++) {
        data->commit[i] = (secp256k1_pedersen_commitment *)malloc(data->n_commits * sizeof(*data->commit[i]));
        if (data->commit[i] == NULL) {abort();}
    }
}

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
static void bulletproof_rangeproof_pedersen_commit(void* arg){
    bulletproof_rangeproof_t *data = (bulletproof_rangeproof_t*)arg;
    size_t i;

    unsigned char blind[32];

    generate_secure_random_bytes(blind, sizeof(blind));   //random init

    for (i = 0; i < data->n_commits; i++) {
        // Allocate memory for the blinding factor for each commitment
        data->blind[i] = malloc(32);
        // Modify the blinding factor to ensure uniqueness
        blind[0] = i;
        blind[1] = i >> 8;
        // Copy the modified blinding factor to the allocated memory
        memcpy((unsigned char*) data->blind[i], blind, 32);
        // Create a Pedersen commitment; abort if it fails
        if(secp256k1_pedersen_commit(data->ctx, &data->commit[0][i], data->blind[i], data->value[i], &data->value_gen[0], &data->blind_gen) != 1) {abort();}
    }
    // Duplicate the first set of commitments to other proofs if multiple proofs are present
    for (i = 1; i < data->n_proofs; i++) {
        memcpy(data->commit[i], data->commit[0], data->n_commits * sizeof(*data->commit[0]));
    }
}

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
static void bulletproof_rangeproof_teardown(void* arg) {
    bulletproof_rangeproof_t *data = (bulletproof_rangeproof_t*)arg;
    size_t i;

    if (data->blind != NULL) {
        for (i = 0; i < data->n_commits; i++) {
            free((unsigned char*) data->blind[i]);
        }
    }
    if (data->commit != NULL) {
        for (i = 0; i < data->n_proofs; i++) {
            free(data->commit[i]);
        }
        free(data->commit);
    }
    free(data->blind);
    free(data->value);

    for (i = 0; i < data->n_proofs; i++) {
        free(data->proof[i]);
    }
    free(data->proof);
    free(data->value_gen);
}

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
static void bulletproof_rangeproof_prove(void* arg) {
    bulletproof_rangeproof_t *data = (bulletproof_rangeproof_t*)arg;
    size_t i;

    for (i = 0; i < data->n_proofs; i++) {
        if(secp256k1_bulletproof_rangeproof_prove(data->ctx, data->scratch, data->generators, data->proof[i], &data->plen, data->value, NULL, data->blind, data->n_commits, data->value_gen, data->nbits, data->nonce, NULL, 0) != 1){abort();}
    }
}

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
static void bulletproof_rangeproof_verify(void* arg) {
    bulletproof_rangeproof_t *data = (bulletproof_rangeproof_t*)arg;
    size_t i;
    
    if(secp256k1_bulletproof_rangeproof_verify_multi(data->ctx, data->scratch, data->generators, (const unsigned char **) data->proof, data->n_proofs, data->plen, NULL, (const secp256k1_pedersen_commitment **) data->commit, data->n_commits, data->nbits, data->value_gen, NULL, 0) != 1){abort();}
    
}