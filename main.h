//
//  main.h
//  Bachelor Project
//

#ifndef main_h
#define main_h


void generate_prime(mpz_t prime, size_t nb_bits);
void OTP_encrypt(mpz_t key, mpz_t ptext, mpz_t ctext);
void OTP_decrypt(mpz_t dec_key, mpz_t ctext, mpz_t dtext);
void generate_n_phi_n(mpz_t n, mpz_t phi_n);
long long int get_nb_squaring(int decryption_time);
void generate_key(mpz_t key, mpz_t n);
void generate_key_ofsize(mpz_t key, size_t nb_bits);
size_t get_plaintext_to_encrypt(char* plaintext);
int get_decryption_time(void);
void get_ASCIIstr_from_mpz(char* str, mpz_t mpz, size_t str_nb_bits);
void get_mpz_from_ASCIIstr(char* str, mpz_t mpz, int nb_chars);
void compute_squaringtime_modn(mpf_t time_for_1_squaring, size_t n_size_in_bits);
void message_encryption(void);
int image_encryption(void);
void encrypt_decrypt_file(unsigned char* key, unsigned char* iv, FILE* input_file, FILE* enc_file, unsigned int encrypt);


#endif /* main_h */
