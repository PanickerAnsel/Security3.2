#include "server.h"
#include <iomanip>
#include <openssl/dh.h>
#include <openssl/rand.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Handles client communication
void handleClient(int clientSocket) {

    // Step 1: Take the client's encrypted public key and decrypt it
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int bytesRead;

    // TODO: read the iv from the client
    

    unsigned char encryptedBuffer[BUFFER_SIZE];
    // TODO: read the encrypted message from the client and store it in bytesRead
   

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
    

    // TODO: Write a method to generate the public and private key pair
    
    
    const BIGNUM *pubkey = NULL;
    // TODO: Write a method to extract the public key from privkey and store it in pubkey
    // HINT: DH_get0_pub_key()
    

    if (pubkey == NULL) {
        printf("Error: DH public key is NULL\n");
        handleErrors();
    }

    printf("Server's Public Key: ");
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
    
    // TODO: send the ciphertext to the client
    
    
    std::cout << "Encrypted public key sent to client." << std::endl;

    // Step 3: Compute the session key (shared secret)
    BIGNUM *clientPubKey = BN_bin2bn(decryptedBuffer, decryptedLen, NULL);
    unsigned char *sharedSecret = (unsigned char *)OPENSSL_malloc(DH_size(privkey));

    // TODO: compute the shared secret and store it in secret_size
    // HINT: using DH_compute_key()
    

    std::cout << "Shared Secret (Hex): ";
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", sharedSecret[i]);
    }
    std::cout << std::endl;
    
    unsigned char iv_new[EVP_MAX_IV_LENGTH];
    int readbytes;
    while ((readbytes = recv(clientSocket, iv_new, EVP_MAX_IV_LENGTH, 0)) > 0) {
        unsigned char encryptedBuffer[BUFFER_SIZE];
        readbytes = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);

        unsigned char decryptedBuffer[BUFFER_SIZE];
        decryptMessage(encryptedBuffer, readbytes, sharedSecret, iv_new, decryptedBuffer);
        
        std::cout << "Received encrypted message: ";
        std::cout.write(reinterpret_cast<const char*>(encryptedBuffer), readbytes);
        std::cout << std::endl;

        std::cout << "Decrypted message: " << decryptedBuffer << std::endl;

        // Echo back the decrypted message to the client
        send(clientSocket, decryptedBuffer,  strlen(reinterpret_cast<const char*>(decryptedBuffer)), 0);
    }
    close(clientSocket);
}
