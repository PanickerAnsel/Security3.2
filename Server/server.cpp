#include "server.h"
#include <iomanip>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <cstring>
#include <unistd.h>
#include <iostream>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Handles client communication
void handleClient(int clientSocket) {

    // Step 1: Take the client's encrypted public key and decrypt it
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int bytesRead;

    // TODO: read the iv from the client
    bytesRead = recv(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);
    if (bytesRead != EVP_MAX_IV_LENGTH) {
        std::cerr << "Error: Failed to receive IV from client." << std::endl;
        close(clientSocket);
        return;
    }

    unsigned char encryptedBuffer[BUFFER_SIZE];
    // TODO: read the encrypted message from the client and store it in bytesRead
    bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);
    if (bytesRead <= 0) {
        std::cerr << "Error: Failed to receive encrypted public key from client." << std::endl;
        close(clientSocket);
        return;
    }

    unsigned char decryptedBuffer[BUFFER_SIZE];
    int decryptedLen;

    decryptWithPSK(encryptedBuffer, bytesRead, (unsigned char*)pre_shared.c_str(), decryptedBuffer, iv, decryptedLen);
    
    std::cout << "Decrypted Client's Public Key (Hex): ";
    for (int i = 0; i < decryptedLen; i++) {
        printf("%02x", decryptedBuffer[i]);
    }
    std::cout << std::endl;

    // Step 2: Generate DH key pairs and send the public key to the client
    DH *privkey;
    int codes;
    int secret_size;

    // TODO: Call DH_get_2048_256() to generate DH parameters
    // You should use that method, so the server and client will use the same p and g
    // and store it in privkey. Then call handleErrors()
    privkey = DH_get_2048_256();
    if (privkey == NULL) {
        std::cerr << "Error: Failed to generate DH parameters." << std::endl;
        handleErrors();
    }

    // TODO: Write a method to generate the public and private key pair
    if (DH_generate_key(privkey) != 1) {
        std::cerr << "Error: Failed to generate DH key pair." << std::endl;
        handleErrors();
    }

    const BIGNUM *pubkey = NULL;
    // TODO: Write a method to extract the public key from privkey and store it in pubkey
    // HINT: DH_get0_pub_key()
    pubkey = DH_get0_pub_key(privkey);
    if (pubkey == NULL) {
        std::cerr << "Error: DH public key is NULL." << std::endl;
        handleErrors();
    }

    std::cout << "Server's Public Key: ";
    BN_print_fp(stdout, pubkey);
    std::cout << "\n";

    // Convert the public key's type from BigNumber to binary
    unsigned char *pubkey_bin = NULL;
    int pubkey_len = BN_num_bytes(pubkey);
    pubkey_bin = (unsigned char *)OPENSSL_malloc(pubkey_len);
    if (pubkey_bin == NULL) {
        std::cerr << "Error: Memory allocation failed." << std::endl;
        handleErrors();
    }
    BN_bn2bin(pubkey, pubkey_bin);

    // Necessary variables to encrypt the public key and send it to the client
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    unsigned char IV[EVP_MAX_IV_LENGTH];

    if (RAND_bytes(IV, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error: Failed to generate random IV." << std::endl;
        close(clientSocket);
        return;
    }

    encryptWithPSK(pubkey_bin, pubkey_len, (unsigned char*)pre_shared.c_str(), ciphertext, IV, ciphertext_len);
    
    // TODO: send the iv to the client
    if (send(clientSocket, IV, EVP_MAX_IV_LENGTH, 0) != EVP_MAX_IV_LENGTH) {
        std::cerr << "Error: Failed to send IV to client." << std::endl;
        close(clientSocket);
        return;
    }

    // TODO: send the ciphertext to the client
    if (send(clientSocket, ciphertext, ciphertext_len, 0) != ciphertext_len) {
        std::cerr << "Error: Failed to send encrypted public key to client." << std::endl;
        close(clientSocket);
        return;
    }
    
    std::cout << "Encrypted public key sent to client." << std::endl;

    // Step 3: Compute the session key (shared secret)
    BIGNUM *clientPubKey = BN_bin2bn(decryptedBuffer, decryptedLen, NULL);
    unsigned char *sharedSecret = (unsigned char *)OPENSSL_malloc(DH_size(privkey));
    if (sharedSecret == NULL) {
        std::cerr << "Error: Memory allocation for shared secret failed." << std::endl;
        handleErrors();
    }

    // TODO: compute the shared secret and store it in secret_size
    // HINT: using DH_compute_key()
    secret_size = DH_compute_key(sharedSecret, clientPubKey, privkey);
    if (secret_size <= 0) {
        std::cerr << "Error: Failed to compute shared secret." << std::endl;
        handleErrors();
    }

    std::cout << "Shared Secret (Hex): ";
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", sharedSecret[i]);
    }
    std::cout << std::endl;

    unsigned char iv_new[EVP_MAX_IV_LENGTH];
    int readbytes;
    while ((readbytes = recv(clientSocket, iv_new, EVP_MAX_IV_LENGTH, 0)) > 0) {
        unsigned char encryptedMsg[BUFFER_SIZE];
        readbytes = recv(clientSocket, encryptedMsg, BUFFER_SIZE, 0);
        if (readbytes <= 0) {
            std::cerr << "Error: Failed to receive encrypted message from client." << std::endl;
            break;
        }

        unsigned char decryptedMsg[BUFFER_SIZE];
        decryptMessage(encryptedMsg, readbytes, sharedSecret, iv_new, decryptedMsg);
        
        std::cout << "Received encrypted message: ";
        for(int i = 0; i < readbytes; i++) {
            printf("%02x", encryptedMsg[i]);
        }
        std::cout << std::endl;

        std::cout << "Decrypted message: " << decryptedMsg << std::endl;

        // Echo back the decrypted message to the client
        // Encrypt the message before sending
        unsigned char response_ciphertext[BUFFER_SIZE];
        int response_ciphertext_len;
        unsigned char response_iv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(response_iv, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error: Failed to generate random IV for response." << std::endl;
            break;
        }

        encryptMessage(reinterpret_cast<std::string>(reinterpret_cast<char*>(decryptedMsg)), response_ciphertext, &response_ciphertext_len, response_iv, sharedSecret);

        // Send IV and encrypted response
        if (send(clientSocket, response_iv, EVP_MAX_IV_LENGTH, 0) != EVP_MAX_IV_LENGTH) {
            std::cerr << "Error: Failed to send IV for response." << std::endl;
            break;
        }
        if (send(clientSocket, response_ciphertext, response_ciphertext_len, 0) != response_ciphertext_len) {
            std::cerr << "Error: Failed to send encrypted response to client." << std::endl;
            break;
        }
    }
    close(clientSocket);
}