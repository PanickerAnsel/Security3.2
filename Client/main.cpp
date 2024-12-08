#include "client.h"
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/dh.h>
#include <iomanip>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Default server IP address and port number if not specified
constexpr const char* DEFAULT_SERVER_IP = "127.0.0.1";
constexpr int DEFAULT_SERVER_PORT = 8080;


void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}


int main() {
    int clientSocket = connectToServer(DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT);
    if (clientSocket == -1) {
        std::cout << "Error in connecting to socket" << std::endl;
        return 1;
    }

    // Step 1: Generate DH key pairs and send the public key to the server
    // Diffie-Hellman components
    DH *privkey;
    int codes;
    int secret_size;

    // TODO: Call DH_get_2048_256() to generate DH parameters
    // You should use that method, so the server and client will use the same p and g
    // and store it in privkey. Then call handleErrors()
    DH* dh = DH_get_2048_256();
    if (dh == NULL) {
        printf("Error: Failed to generate DH parameters\n");
        handleErrors();
    }
    
    // TODO: Write a method to generate the public and private key pair
    if (DH_generate_key(dh) != 1) {
        printf("Error: Failed to generate DH key pair\n");
        handleErrors();
    }

    // TODO: Write a method to extract the public key from privkey and store it in pubkey
    // HINT: DH_get0_pub_key()
    const BIGNUM *pubkey = NULL;
    pubkey = DH_get0_pub_key(privkey);

    if (pubkey == NULL) {
        printf("Error: DH public key is NULL\n");
        handleErrors();
    }

    printf("Client's Public Key: ");
    BN_print_fp(stdout, pubkey);
    printf("\n");

    // Convert the public key's type from BigNumber to binary
    unsigned char *pubkey_bin = NULL;
    int pubkey_len = BN_num_bytes(pubkey);
    pubkey_bin = (unsigned char *)OPENSSL_malloc(pubkey_len);
    if (pubkey_bin == NULL) {
        printf("Error: Memory allocation failed\n");
        handleErrors();
    }
    BN_bn2bin(pubkey, pubkey_bin);

    // Necessary variables to encrypt the public key and send it to the server
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error: Failed to generate random IV." << std::endl;
        close(clientSocket);
        return 1;
    }
    // Encrypt the public key
    encryptWithPSK(pubkey_bin, pubkey_len, (unsigned char*)pre_shared.c_str(), ciphertext, iv, ciphertext_len);

    // TODO: send the iv to the server
    if (send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0) != EVP_MAX_IV_LENGTH) {
        std::cerr << "Error: Failed to send IV to server." << std::endl;
        close(clientSocket);
        return 1;
    }
    // TODO: send the ciphertext to the server
    if (send(clientSocket, ciphertext, ciphertext_len, 0) != ciphertext_len) {
        std::cerr << "Error: Failed to send encrypted public key to server." << std::endl;
        close(clientSocket);
        return 1;
    }

    std::cout << "Encrypted public key sent to server." << std::endl;

    // Step 2: Take the server's encrypted public key and decrypt it
    // read IV from the server 
    unsigned char IV[EVP_MAX_IV_LENGTH];
    int bytesRead;

    // TODO: receive the IV from the server
    bytesRead = recv(clientSocket, IV, EVP_MAX_IV_LENGTH, 0);
    if (bytesRead != EVP_MAX_IV_LENGTH) {
        std::cerr << "Error: Failed to receive IV from server." << std::endl;
        close(clientSocket);
        return 1;
    }
    
    unsigned char encryptedBuffer[BUFFER_SIZE];
    // TODO: receive the encrypted message from the server and store it in bytesRead
    bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);
    if (bytesRead <= 0) {
        std::cerr << "Error: Failed to receive encrypted public key from server." << std::endl;
        close(clientSocket);
        return 1;
    }
    unsigned char decryptedBuffer[BUFFER_SIZE];
    int decryptedLen;

    // decrypt the encrypted public key
    decryptWithPSK(encryptedBuffer, bytesRead, (unsigned char*)pre_shared.c_str(), decryptedBuffer, IV, decryptedLen);
        
    std::cout << "Decrypted Server's Public Key (Hex): ";
    for (int i = 0; i < decryptedLen; i++) {
        printf("%02x", decryptedBuffer[i]);
    }
    std::cout << std::endl;

    // Step 3: Compute the session key (shared secret)
    BIGNUM *serverPubKey = BN_bin2bn(decryptedBuffer, decryptedLen, NULL);
    unsigned char *sharedSecret = (unsigned char *)OPENSSL_malloc(DH_size(privkey));

    // TODO: compute the shared secret and store it in secret_size
    // HINT: using DH_compute_key()
    secret_size = DH_compute_key(sharedSecret, serverPubKey, privkey);
    if (secret_size <= 0) {
        printf("Error: Failed to compute shared secret\n");
        handleErrors();
    }

    std::cout << "Shared Secret (Hex): ";
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", sharedSecret[i]);
    }
    std::cout << std::endl;
    std::cout << "Shared key was established. Enter message 'quit' to exit: \n";

    while (true) {

        // Stores client input as message string
        std::string message;
        std::getline(std::cin, message);

        // Breaks the client application if message is 'quit'
        if (message == "quit") {
            break;
        }

        // Generate random IV and closes application if error
        unsigned char iv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error: Failed to generate random IV." << std::endl;
            close(clientSocket);
            return 1;
        }

        // Encrypt message
        unsigned char ciphertext[BUFFER_SIZE];
        int ciphertext_len;
        encryptMessage(message, ciphertext, &ciphertext_len, iv, sharedSecret);

        // Send IV and encrypted message to server
        send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);
        send(clientSocket, ciphertext, ciphertext_len, 0);
        std::cout << "Sent encrypted message to server." << std::endl;
    }
    close(clientSocket);
}
