#include "server.h"

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Failed to create socket." << std::endl;
        return EXIT_FAILURE;
    }

    // Set server address and port
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind socket then print address and port
    if (bind(serverSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
        std::cerr << "Error: Failed to bind socket to address." << std::endl;
        close(serverSocket);
        return EXIT_FAILURE;
    }
    std::cout << "Server socket bound to address: " << inet_ntoa(serverAddr.sin_addr) << ", port: " << ntohs(serverAddr.sin_port) << std::endl;

    // Listen for incoming connections
    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error: Failed to listen for incoming connections." << std::endl;
        close(serverSocket);
        return EXIT_FAILURE;
    }
    std::cout << "Server started. Listening on port " << PORT << "..." << std::endl;

    while (true) {
        // Accept incoming connection and print address and port
        clientSocket = accept(serverSocket, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrLen);
        if (clientSocket == -1) {
            std::cerr << "Error: Failed to accept incoming connection." << std::endl;
            close(serverSocket);
            return EXIT_FAILURE;
        }
        std::cout << "Accepted incoming connection from client: " << inet_ntoa(clientAddr.sin_addr) << ", port: " << ntohs(clientAddr.sin_port) << std::endl;

        // Handle client communication in a separate thread
        handleClient(clientSocket);
    }
}
