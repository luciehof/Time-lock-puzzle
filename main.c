//
//  main.c
//  Bachelor Project
//  Source (file encryption) : https://medium.com/@amit.kulkarni/encrypting-decrypting-a-file-using-openssl-evp-b26e0e4d28d4


#include <math.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <gmp.h>
#include "Squarings.h"
#include <time.h>
#include <openssl/rand.h>
#include "main.h"


#define MAX_INPUT_SIZE 256
#define AES_256_KEY_SIZE 32 //32 byte key (256 bits key)
#define AES_BLOCK_SIZE 16 //16 byte block size (128 bits)
#define BUFFER_SIZE 1024
gmp_randstate_t state;


int main (void)
{
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(0));
    
    int main_ret_val = 0;
    int encryption_choice;
    do {
        printf("Do you want to encrypt a message (1) or an image (2) ?\n");
        scanf("%d", &encryption_choice);
        getc(stdin);
    } while (encryption_choice != 1 && encryption_choice != 2 && !feof(stdin) && !ferror(stdin));
    
    if(encryption_choice == 1) message_encryption();
    if(encryption_choice == 2) main_ret_val = image_encryption();

    return main_ret_val;
}

int image_encryption(){
    mpz_t k, enc_k, dec_k;
    mpz_inits(k, enc_k, dec_k, NULL);
    char* file_name = "chameaux.jpg";
    FILE *input_file, *enc_file, *dec_file;
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char dec_key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    memset(key, 0, AES_256_KEY_SIZE);
    memset(dec_key, 0, AES_256_KEY_SIZE);
    memset(iv, 0, AES_BLOCK_SIZE);
    
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }
    generate_key_ofsize(k, AES_256_KEY_SIZE*8); //256 bits key
    
    input_file = fopen(file_name, "rb");
    if (!input_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    enc_file = fopen("encrypted_image.txt", "wb");
    if (!enc_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    
    
    // Image symmetric encryption
    get_ASCIIstr_from_mpz(key, k, AES_256_KEY_SIZE);
    //printf("\nkey : %s\n", key);
    encrypt_decrypt_file(key, iv, input_file, enc_file, 1); // encrypt set to 1 (we want to encrypt)
    fclose(input_file);
    fclose(enc_file);
    
    /// COMPUTE NB SQUARINGS
    int decryption_time_d = get_decryption_time();
    long long int nb_squarings = get_nb_squaring(decryption_time_d); // for a 2048 bits composite modulus n
    
    // Key encryption
    /// GENERATE COMPOSITE MOD AND CORRESPONDING  TOTIENT AND SET PARAM A
    mpz_t n, phi_n, a;
    mpz_inits(n, phi_n, a, NULL);
    generate_n_phi_n(n, phi_n); // n of 2048 bits
    mpz_set_ui(a, 2); // base a for repeated squarings, here a is set to 2
    //gmp_printf("\nGENERATED KEY = %Zd\n", k);
    encrypt_key(k, nb_squarings, a, enc_k, n, phi_n);

    // Key decryption
    clock_t dec_time;
    dec_time = clock();
    decrypt_key(a, nb_squarings, n, enc_k, dec_k);
    dec_time = clock() - dec_time;
    //gmp_printf("DECRYPTED KEY = %Zd \n\n", dec_k);
    double decryption_runtime = ((double)dec_time)/CLOCKS_PER_SEC;
    
    printf("decrypt_key() took %f seconds to execute \n", decryption_runtime);
    
    
    // Image decryption
    get_ASCIIstr_from_mpz(dec_key, dec_k, AES_256_KEY_SIZE);
    //printf("\ndec_key : %s\n", dec_key);

    input_file = fopen("encrypted_image.txt", "rb");
    if (!input_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    dec_file = fopen("decrypted_image.jpg", "wb");
    if (!dec_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    encrypt_decrypt_file(dec_key, iv, input_file, dec_file, 0); // encrypt set to 0 (we want to decrypt)
    fclose(input_file);
    fclose(dec_file);
    
    mpz_clears(a, n, phi_n, k, enc_k, dec_k, NULL);
    
    return 0;
}

void encrypt_decrypt_file(unsigned char* key, unsigned char* iv, FILE* input_file, FILE* output_file, unsigned int encrypt){
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    //if(!encrypt)printf("\nBLOCK SIZE : %d bytes.\n", block_size);
    // GET INPUT FILE SIZE
    //fseek(input_file, 0, SEEK_END); // seek to end of file
    //size_t input_size = ftell(input_file); // get current file pointer
    //fseek(input_file, 0, SEEK_SET); // seek back to beginning of file
    //if(!encrypt)printf("\nINPUT SIZE : %zu bytes.\n", input_size);
    
    unsigned char buffer_in[BUFFER_SIZE], buffer_out[BUFFER_SIZE + block_size];
    memset(buffer_in, 0, BUFFER_SIZE);
    memset(buffer_out, 0, BUFFER_SIZE + block_size);
    int nb_read_bytes, buffer_out_len;
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
    }
    
    if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
    }
    
    do {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        nb_read_bytes = fread(buffer_in, sizeof(unsigned char), BUFFER_SIZE, input_file);
        if (ferror(input_file)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }
        if(nb_read_bytes <= 0){
            break;
        }
        if(!EVP_CipherUpdate(ctx, buffer_out, &buffer_out_len, buffer_in, nb_read_bytes)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
        }
        fwrite(buffer_out, sizeof(unsigned char), buffer_out_len, output_file);
        if (ferror(output_file)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }
    } while (1);
    
    // Now cipher the final block and write it out to file
    if(!EVP_CipherFinal_ex(ctx, buffer_out, &buffer_out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
    }
    fwrite(buffer_out, sizeof(unsigned char), buffer_out_len, output_file);
    if (ferror(output_file)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

void message_encryption(){
    /// GET MESSAGE AND TIME OF ENCRYPTION
    char plaintext[MAX_INPUT_SIZE + 1];
    memset(plaintext, 0, MAX_INPUT_SIZE + 1);
    size_t plaintext_len = get_plaintext_to_encrypt(plaintext); // plaintext_len is the length of the plaintext
    char ciphertext[plaintext_len + 1];
    memset(ciphertext, 0, plaintext_len + 1);
    char decryptedtext[plaintext_len + 1];
    memset(decryptedtext, 0, plaintext_len + 1);
    
    /// COMPUTE NB OF SQUARINGS
    long long int nb_squarings = get_nb_squaring(get_decryption_time()); // for a 2048 bits composite modulus n
    
    /// INITIALIZATION OF MPZ NBS
    mpz_t key, ptext, ctext, enc_key, dec_key, dtext, n, phi_n, a; // ptext: mpz plaintext, ctext: mpz ciphertext, dtext: mpz decrypted text
    mpz_inits(key, ptext, ctext, enc_key, dec_key, dtext, n, phi_n, a, NULL);
    get_mpz_from_ASCIIstr(plaintext, ptext, plaintext_len);// ptext is the mpz integer corresponding ASCII string plaintext
    generate_n_phi_n(n, phi_n); // n of 2048 bits
    mpz_set_ui(a, 2); // base a for repeated squarings, here a is set to 2
    
    /// GENERATE KEY
    generate_key(key, n);
    //gmp_printf("\nGENERATED KEY = %Zd\n", key);
    
    /// ENCRYPT M WITH K
    OTP_encrypt(key, ptext, ctext);
    get_ASCIIstr_from_mpz(ciphertext, ctext, plaintext_len);
    
    /// ENCRYPT KEY WITH REPEATED SQUARINGS
    encrypt_key(key, nb_squarings, a, enc_key, n, phi_n);
    
    /// OUTPUT (n, a, t=nb_squarings, C_K=encrypted key, C_M=encrypted message)
    gmp_printf("n = %Zd \n", n);
    gmp_printf("a (base of for squarings a^2^t) = %Zd \n", a);
    printf("t (number of squaring operations) = %lld \n", nb_squarings);
    printf("encrypted message = %s \n", ciphertext);
    gmp_printf("encrypted key = %Zd\n\n", enc_key);
    
    /// ERASE PARAMETERS phi_n, key (now we are sure we cannot use them for decryption)
    mpz_clears(phi_n, key, NULL);
    
    /// SOLVE PUZZLE TO GET DECRYPTED KEY WITH (n, a, t, C_K)
    clock_t dec_time;
    dec_time = clock();
    decrypt_key(a, nb_squarings, n, enc_key, dec_key); // run time increases with nb of chars in plaintext --> n size depends on plaintext size
    dec_time = clock() - dec_time;
    gmp_printf("DECRYPTED KEY = %Zd \n\n", dec_key);
    double decryption_runtime = ((double)dec_time)/CLOCKS_PER_SEC;
    printf("decrypt_key() took %f seconds to execute \n", decryption_runtime);

    /// DECRYPT MESSAGE USING DECRYPTED KEY
    OTP_decrypt(dec_key, ctext, dtext);
    get_ASCIIstr_from_mpz(decryptedtext, dtext, plaintext_len);

    
    printf("\nDecrypted text is:\n");
    printf("%s\n\n", decryptedtext);

    mpz_clears(a, n, enc_key, dec_key, ctext, dtext, NULL);
}

size_t get_plaintext_to_encrypt(char* plaintext) {
    size_t len;
    do {
        printf("Write the message to encrypt (max size = %d) :\n", MAX_INPUT_SIZE);
        fgets(plaintext, MAX_INPUT_SIZE + 1, stdin);
        len = strlen(plaintext) - 1; // don't count the '\n' character
        if (len >= 1 && plaintext[len] == '\n') {
            plaintext[len] = '\0';
        }
        //printf("plaintext to be encrypted is : %s\n\n", plaintext);
    } while (len<1 && !feof(stdin) && !ferror(stdin));
    return len;
}

int get_decryption_time(void){
    int decryption_time = -1;
    do {
        printf("Write desired encryption time in seconds :\n");
        scanf("%d", &decryption_time);
        if (decryption_time <= 0) {
            printf("Decryption time should be positive ! \n");
        }
    } while (decryption_time <= 0 && !feof(stdin) && !ferror(stdin));
    getc(stdin);
    return decryption_time;
}

void generate_n_phi_n(mpz_t n, mpz_t phi_n){
    mpz_t p, q, p_1, q_1;
    mpz_inits(p, q, p_1, q_1, NULL);
    generate_prime(p, 1024); // primes of 2048/ 2 bits to get a 2048 bits modulus n
    generate_prime(q, 1024);
    mpz_mul(n, p, q);
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(phi_n, p_1, q_1);
    mpz_clears(p, q, p_1, q_1, NULL);
}

long long int get_nb_squaring(int decryption_time){
    mpz_t nb_squarings_mpz;
    mpf_t time_for_1_squaring, decryption_time_mpf, nb_squarings_mpf;
    mpz_init(nb_squarings_mpz);
    mpf_inits(time_for_1_squaring, decryption_time_mpf, nb_squarings_mpf, NULL);
    mpf_set_str(time_for_1_squaring, "0.000001134553", 10); // 0.000001134553 = computed time for N of size 2048 bits
    mpf_set_ui(decryption_time_mpf, decryption_time);
    mpf_div(nb_squarings_mpf, decryption_time_mpf, time_for_1_squaring); // nb squarings = decryption time / time for 1 squaring
    mpz_set_f(nb_squarings_mpz, nb_squarings_mpf);
    gmp_printf("\n Number of squarings is : %Zd\n\n", nb_squarings_mpz);
    long long int nb_squarings_ui = mpz_get_ui(nb_squarings_mpz);
    mpf_clears(time_for_1_squaring, decryption_time_mpf, nb_squarings_mpf, NULL);
    mpz_clear(nb_squarings_mpz);
    return nb_squarings_ui;
}

void OTP_encrypt(mpz_t key, mpz_t ptext, mpz_t ctext){
    mpz_xor(ctext, key, ptext); // ciphertext = key xor plaintext
}

void OTP_decrypt(mpz_t dec_key, mpz_t ctext, mpz_t dtext){
    mpz_xor(dtext, dec_key, ctext); // decrypted text = dec_key xor ciphertext
}

void generate_prime(mpz_t prime, size_t nb_bits) {
    do {
        mpz_urandomb(prime, state, nb_bits);
        // Generate a uniformly distributed random
        // integer in the range 0 to 2^length-1, inclusive
    } while (mpz_probab_prime_p(prime, 20) == 0);
}

void generate_key(mpz_t key, mpz_t n){   
    mpz_urandomm(key, state, n);
}

void generate_key_ofsize(mpz_t key, size_t nb_bits){ //code copy...
    mpz_urandomb(key, state, nb_bits);
}

void get_ASCIIstr_from_mpz(char* str, mpz_t mpz, size_t str_nb_chars){
    
    int nb_bits = mpz_sizeinbase(mpz, 2); // number of bits in the mpz to convert
    mpz_t mask, current_byte_mpz;
    mpz_inits(mask, current_byte_mpz, NULL);
    mpz_set_ui(mask, 255); // 0b1111_1111, mask to get each byte of mpz
    
    int byte_index = 0; // index (of character corresponding to byte) in the string resulting of conversion
    int right_shift = 0; // indicates how many right shifts by 8 we need to put the current byte as the lowest one
    for (int i = nb_bits; i > 0 && byte_index<str_nb_chars; i=i-8){
        mpz_and(current_byte_mpz, mpz, mask); // get the byte corresponding to the byte_index character in str
        mpz_tdiv_q_2exp(current_byte_mpz, current_byte_mpz, right_shift*8); // current_byte_mpz >> right_shift*8
        str[byte_index] = mpz_get_ui(current_byte_mpz);
        byte_index++;
        mpz_mul_2exp(mask, mask, 8); // mask << 8
        right_shift++;
    }
    str[str_nb_chars] = '\0';
}

void get_mpz_from_ASCIIstr(char* str, mpz_t mpz, int nb_chars){
    mpz_t current_char;
    mpz_init(current_char);
    mpz_set_ui(mpz, 0);
    for (int i = nb_chars; i > -1; --i){
        mpz_mul_2exp(mpz, mpz, 8); // mpz << 8
        mpz_set_ui(current_char, str[i]);
        mpz_ior(mpz, mpz, current_char); // mpz | str[i]
    }
}

