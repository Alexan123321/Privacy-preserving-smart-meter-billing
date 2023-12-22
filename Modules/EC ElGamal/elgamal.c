#include "elgamal.h"

/**
 * The ElGamal key generation process (Elliptic Curve Version):
 * "Elliptic Curves: Number Theory and Cryptography", p. 175, Washington, 2008
 * 
 * Steps:
 * 1. Choose a random integer, s, from the range of the order of G_1.
 * 2. Compute B = P * s (scalar multiplication on the curve).
 *
 * The private key is s and the public key comprises three parameters E, Fq, P and the public key point B.
 */
int elgamal_keygen(bn_t s, ec_t B) {
    int result = RLC_OK;  // Variable to hold the result
    ec_t P;  // Variable to hold the generator of the group G1
    bn_t n;  // Variable to hold the order of the group G1

    // Initialize variables as null
    ec_null(P);
    ec_null(n);

    RLC_TRY {
        // Initialize and allocate memory for variables
        ec_new(P);
        bn_new(n);

        ec_curve_get_gen(P); // Get the generator of the group G1 and store it in g
        ec_curve_get_ord(n); // Get the order of the group G1 and store it in n

        bn_rand_mod(s, n);  // Generate a random private key in the range [1, n-1]
        ec_mul(B, P, s);  // Compute the public key as g*pri_key
    } 
    
    RLC_CATCH_ANY {
        result = RLC_ERR;
    } 
    
    RLC_FINALLY {
        bn_free(n);  // Free the memory allocated for n
        ec_free(P);  // Free the memory allocated for P
    }
    return result;
}


/**
 * The ElGamal encryption process (Elliptic Curve Version):
 * "Elliptic Curves: Number Theory and Cryptography", p. 175, Washington, 2008
 * 
 * Given:
 * - P: a base point of the elliptic curve group G_1
 * - B: the public key (a point on the curve)
 * - m: the message to be encrypted, represented as an integer
 *
 * Steps:
 * 1. Choose a random integer, k, from the range of the order of G_1.
 * 2. Compute M = mP, where m is the message to be encrypted, and P is the base point of the curve.
 * 3. Compute M1 = k * P (scalar multiplication on the curve).
 * 4. Compute h = B * k (scalar multiplication using the public key).
 * 5. Compute M2 = M + h (point addition on the curve).
 *
 * The ciphertext is then the tuple (M1, M2).
 */
int elgamal_encrypt(ec_t B, bn_t m, ec_t M1, ec_t M2) {
    int result = RLC_OK; // Variable to hold the result
    bn_t k;              // Secret random integer k
    ec_t P, h, M;        // Temporary variables. P is the base point of the curve.

    // Initialize variables as null
    bn_null(k);
    ec_null(P);
    ec_null(h);
    ec_null(M);

    RLC_TRY {
        // Initialize and allocate memory for variables
        bn_new(k);
        ec_new(P)
        ec_new(h)
        ec_new(M)

        // Generate a random integer k from the range of the order of G_1
        bn_rand(k, RLC_POS, RLC_BN_BITS);

        // Get the base point of the group G1 and store it in P
        ec_curve_get_gen(P);

        // Compute M = m*P
        ec_mul(M, P, m);
        // Compute M1 = k*P
        ec_mul(M1, P, k);
        // Compute h = B*k
        ec_mul(h, B, k);
        // Compute M2 = M + h
        ec_add(M2, M, h);
    }

    RLC_CATCH_ANY {
        result = RLC_ERR;
    }

    RLC_FINALLY {
        // Free the memory allocated for the variables
        bn_free(k);
        ec_free(P);
        ec_free(h);
        ec_free(M);
    }

    return result;
}



/**
 * The ElGamal decryption process (Elliptic Curve Version):
 * "Elliptic Curves: Number Theory and Cryptography", p. 175, Washington, 2008
 * 
 * Given:
 * - \( M1 \): the first component of the ciphertext
 * - \( M2 \): the second component of the ciphertext
 * - \( s \): the private key
 *
 * Steps:
 * 1. Compute \( h = M1 \times s \) (scalar multiplication using the private key).
 * 2. Compute \( M = M2 - h \) (point subtraction on the curve).
 * 3. Solve the elliptic curve discrete log problem to recover \( m \) from \( M \) using a brute force search if the set of possible \( m \) values is small.
 *
 * The message \( m \) is then recovered.
 */
int elgamal_decrypt(bn_t s, g1_t M1, g1_t M2, bn_t* m) {
    int result = RLC_OK;
    ec_t h, M;  // Temporary variables
    ec_t P;     // Base point of the group G1
    bn_t ord;   // Order of the group G1

    // Initialize variables as null
    ec_null(h);
    ec_null(M);
    ec_null(P);
    bn_null(ord);

    RLC_TRY {
        // Allocate memory for variables
        ec_new(h);
        ec_new(M);
        ec_new(P);
        bn_new(ord);

        // Get the base point of the group G1 and store it in P
        ec_curve_get_gen(P);
        // Get the order of the group G1 and store it in ord
        ec_curve_get_ord(ord);

        // Compute h = M1*s
        ec_mul(h, M1, s);
        // Compute M = M2 - h
        ec_sub(M, M2, h);

        // Solve the elliptic curve discrete log problem to recover m from M
        // This can be done using a brute force search if the set of possible m values is small
        for (bn_zero(*m); bn_cmp(*m, ord) != RLC_EQ; bn_add_dig(*m, *m, 1)) {
            // Compute h = P*m
            ec_mul(h, P, *m);
            // If h equals M, break the loop
            if (ec_cmp(h, M) == RLC_EQ) {
                break;
            }
        }
    }

    RLC_CATCH_ANY {
		result = RLC_ERR;
	}

    RLC_FINALLY {
        // Free the memory allocated for variables
        ec_free(h);
        ec_free(M);
        ec_free(P);
        bn_free(ord);
    }
}