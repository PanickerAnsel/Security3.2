#include "common.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>

std::string pre_shared = "ThisIsASecretKeyThatIs32Bytes!!!"; // pre-shared key used to send public keys

void handleErrors() {
    std::cerr << "Error: Failed to initialize OpenSSL." << std::endl;
    exit(EXIT_FAILURE);
}

void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len,
                    unsigned char* iv, unsigned char *sessionKey) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Create and initialize the context. Then call the handleErrors() method
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize encryption operation. Then call the handleErrors() method
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sessionKey, iv))
        handleErrors();

    // Encrypt plaintext. Then call the handleErrors() method
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()))
        handleErrors();

    // Finalize encryption. Then call the handleErrors() method
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len))
        handleErrors();
    
    // Add the final length to the total ciphertext length
    *ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void decryptMessage(const unsigned char* encryptedData, int encryptedLen,
                    const unsigned char* sessionKey, const unsigned char* iv, unsigned char* decryptedBuffer) {
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize decryption context with AES-256-CBC
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sessionKey, iv)) handleErrors();

    int decryptedLen;
    // Decrypt the encrypted data
    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &decryptedLen, encryptedData, encryptedLen)) handleErrors();

    int finalDecryptedLen;
    // Finalize decryption
    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + decryptedLen, &finalDecryptedLen)) handleErrors();

    decryptedLen += finalDecryptedLen;

    decryptedBuffer[decryptedLen] = '\0'; // Null-terminate the decrypted message

    EVP_CIPHER_CTX_free(ctx);
}

void encryptWithPSK(const unsigned char* publicKey, int publicKeyLen,
                    const unsigned char* psk, unsigned char* ciphertext, unsigned char* iv, int& ciphertextLen) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Create and initialize the context. Then call the handleErrors() method
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();  

    // Initialize encryption operation. Then call the handleErrors() method
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, psk, iv))
        handleErrors();

    // Encrypt the public key. Then call the handleErrors() method
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, publicKey, publicKeyLen))
        handleErrors();
    ciphertextLen = len;

    // Finalize encryption. Then call the handleErrors() method
   if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertextLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void decryptWithPSK(const unsigned char* ciphertext, int ciphertextLen,
                    const unsigned char* psk, unsigned char* decryptedText, unsigned char* iv, int& decryptedLen) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Initialize decryption context. Then call the handleErrors() method
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize decryption operation. Then call the handleErrors() method
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, psk, iv))
        handleErrors();

    // Decrypt the ciphertext. Then call the handleErrors() method
    if (1 != EVP_DecryptUpdate(ctx, decryptedText, &len, ciphertext, ciphertextLen))
        handleErrors();
    decryptedLen = len;

    // Finalize decryption. Then call the handleErrors() method
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedText + len, &len))
        handleErrors();
    decryptedLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}