#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <relic.h>

int elgamal_encrypt(ec_t B, bn_t m, ec_t M1, ec_t M2);
int elgamal_decrypt(bn_t s, g1_t M1, g1_t M2, bn_t* m);
int elgamal_keygen(bn_t s, ec_t B);

#endif // ELGAMAL_H