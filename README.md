Be sure to have OpenSSL library installed. If you run this project on Hopper, you don't need to install anything.
!!! Tasks needed to complete:
+ Go to common.cpp under the Common folder, write code in the encryptWithPSK() and decryptWithPSK() methods
+ Go to main.cpp under the Client folder, complete all the parts marked with TODO
+ Go to server.cpp under the Server folder, complete all the parts marked with TODO

*Notes: 
+ The encryptedwithPSK() and decryptWithPSK() methods are very similar with the encryptMessage() and decryptMessage()methods. The only difference is that those take the session key rather than the pre_shared key.
+ Most of the TODO parts in main.cpp are the same as those in server.cpp. Pay attention to the variables' names!
+ This is the source that you can use to complete the TODO tasks: https://wiki.openssl.org/index.php/Diffie_Hellman

To run the chat application:
1. In the project3_part1 directory, run the following commands:
   + mkdir build
   + cd build
   + cmake ..
   + make
2. Run the client and server (you can have multiple client instances):
+ In the build directory, run the server by: (run the server first)
  + cd Server
  + ./server_executable
+ Open another terminal, in the build directory, run the client by:
  + cd Client
  + ./client_executable
   
Testing:
Check the following:
+ Client's Public Key in the client = Decrypted Client's Public Key in the server (regardless of uppercase or lowercase)
+ Server's Public Key = Decrypted Server's Public Key (regardless of uppercase or lowercase)
+ Shared Secret in the client matches Shared Secret in the server
After the session is made, then do the following:
+ In the client terminal, type a message
+ In the server terminal, an encrypted message and the message you just typed in the client terminal will show up
If both messages match, then you do all the methods correctly


