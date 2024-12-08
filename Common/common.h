#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <string>

constexpr int BUFFER_SIZE = 1024;
constexpr int PORT = 8080;
extern std::string pre_shared;

void handleErrors();
void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len, unsigned char* iv, unsigned char *sessionKey);
void decryptMessage(const unsigned char* encryptedData, int encryptedLen, const unsigned char* sessionKey, const unsigned char* iv, unsigned char* decryptedBuffer);
void encryptWithPSK(const unsigned char* publicKey, int publicKeyLen,
                    const unsigned char* psk, unsigned char* ciphertext, unsigned char* iv, int& ciphertextLen);
void decryptWithPSK(const unsigned char* ciphertext, int ciphertextLen,
                    const unsigned char* psk, unsigned char* decryptedText, unsigned char* iv, int& decryptedLen);
#endif // COMMON_H