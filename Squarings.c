//
//  Squarings.c
//  Bachelor Project
//

#include <stdio.h>
#include <gmp.h>
#include "Squarings.h"

void e_mod_phi_n(mpz_t e, long long int nb_squarings, mpz_t phi_n) {
    mpz_t base;
    mpz_init(base);
    mpz_set_ui(base, 2);
    mpz_powm_ui(e, base, nb_squarings, phi_n);
    mpz_clear(base);
}

void b_mod_n(mpz_t b, mpz_t a, mpz_t e, mpz_t n){
    mpz_powm(b, a, e, n);
}

void encrypt_key(mpz_t key, long long int nb_squarings, mpz_t a, mpz_t enc_key, mpz_t n, mpz_t phi_n){
    mpz_t e, b;
    mpz_inits(e, b, NULL);
    
    e_mod_phi_n(e, nb_squarings, phi_n);    // compute e = 2^t mod phi(n), t=nb_squarings
    b_mod_n(b, a, e, n);    // compute b = a^e mod n, a is set to 2 in main.c

    mpz_add (enc_key, key, b);
    mpz_mod (enc_key, enc_key, n);    // key encryption = key + b mod n
    
    mpz_clears(e, b, NULL);
}

void decrypt_key(mpz_t a, long long int nb_squarings, mpz_t n, mpz_t enc_key, mpz_t dec_key){
    mpz_t e;
    mpz_init(e);
    mpz_setbit(e, nb_squarings); // Sets exponent = 2^t
    mpz_powm(a, a, e, n); // a = (a^e mod n) = (a^(2^t) mod n) -> t squarings
    mpz_sub(dec_key, enc_key, a);
    mpz_mod(dec_key, dec_key, n);   // compute key = enc_key - a^2^t mod n
}
