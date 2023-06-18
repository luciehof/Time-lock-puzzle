//
//  Squarings.h
//  Bachelor Project
//

#ifndef Squarings_h
#define Squarings_h

#include <stdio.h>
void e_mod_phi_n(mpz_t e, long long int nb_squarings, mpz_t phi_n);
void b_mod_n(mpz_t b, mpz_t a, mpz_t e, mpz_t n);
void encrypt_key(mpz_t key, long long int nb_squarings, mpz_t a, mpz_t enc_key, mpz_t n, mpz_t phi_n);
void decrypt_key(mpz_t a, long long int t, mpz_t n, mpz_t enc_key, mpz_t dec_key);

#endif /* Squarings_h */
