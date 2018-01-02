README.TXT for Original Needham Schroeder Reflection Attack
-----------------------------------------------------------

This includes three .cpp files.
(1)alice3nnr.cpp
(2)bobsnnr.cpp


Description:
(2) .cpp program has to be run before the socket client program (1).
Here Bob is server and Alice is the client

Pre-Defined Variables:
- Bob's Key in (2)
- Alice and Bob's Shared Key in (1),(2)
- Shared key in Alice is used for demo purposes only. Just to generate Kab(N2)

Openssl Functions:

DES_ecb3_encrypt() - to encrypt input data using 3DES ECB with DES_ENCRYPT flag
DES_ecb3_encrypt() - to decrypt the data using 3DES ECB with DES_DECRYPT flag


Functions:
----(1,2)----
error() - throws error message when forked process fails.

read_from_pipe() - Reads data from pipe.

write_to_pipe() - Write data to pipe.

newsoc() - process forked to communicate with another session of Bob in a different port

main() - performs socket programming. /*Pass 2 port numbers to connect to Bob1 and Bob2*/
1 Trudy has stored Kab(N2). This is generated in (1) for demo purposes.
2. Trudy establishes connection with Bob1 and sends Kab(N2).
3. Bob1 receives Kab(N2).
-  Bob1 decrypts Kab(N2) and calculates N2-1
-  Bob1 generates N4.
4. Bob1 encrypts Kab(N2-1,N4) and sends Alice (Trudy) Kab(N2-1,N4)
5. Trudy receives Kab(N2-1,N4) and parses Kab(N4)
ii)Trudy opens another connection with Bob2 and sends Kab(N4)
iii)Bob2 receives Kab(N4).
-  Bob2 decrypts Kab(N4) and calculates N4-1
-  Bob2 generates N5.
iv)Bob2 encrypts Kab(N4-1,N5) and sends Alice (Trudy) Kab(N4-1,N5)
6. Trudy disconnects new connection and pareses Kab(N4-1) and sends Bob Kab(N4-1)
7. Bob receives Kab(N4-1) and checks it with N4 and authenticates Alice (Trudy)


@param argv[] - Enter the port number while executing the program. The range is 0-65535. This is passed as argument to main()


To compile: (Needs to have openssl package installed)
        g++ bobsnnr.cpp -lssl -lcrypto -o bobsnnrobj 
	g++ alice3nnr.cpp -lssl -lcrypto -o alicennrobj
	
To execute:
	./bobsnnrobj 1331
	./bobsnnrobj 1332
 	./alicennrobj 1331 1332

NOTE:

When the connection is force terminated and if the server program and client program is run again, please use different <port_number> while executing to avoid port conflicts. 
The previously assigned port number will take time to get released.

If there's binding error while running it for 1st time, then please use different <port_number> while executing to avoid port conflicts. 
