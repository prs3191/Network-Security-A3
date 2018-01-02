README.TXT for Original Needham Schroeder CBC
---------------------------------------------

This includes three .cpp files.
(1)alice3nn.cpp
(2)bobsnn.cpp
(3)kdc3nn.cpp


Description:
(1) & (3) .cpp program has to be run before the socket client program (2).
Here Alice, KDC is server and Bob is the client

Pre-Defined Variables:
- Alice's Key in (1)
- Bob's Key in (2)
- Alice and Bob's Shared Key in (1),(2)
- KDC has all above keys

Openssl Functions:

DES_ede3_cbc_encrypt() - to encrypt input data using 3DES CBC with DES_ENCRYPT flag
DES_ede3_cbc_encrypt() - to decrypt the data using 3DES CBC with DES_DECRYPT flag


Functions:
----(1,2)----
error() - throws error message when forked process fails.

read_from_pipe() - Reads data from pipe.

write_to_pipe() - Write data to pipe.

tokenizer() - Its a parser.

decrypt_kdc_msg() - decrypt message from Bob,KDC.

newsoc() - process forked to communicate with another session of Bob in a different port

main() - performs socket programming. /*Pass 2 port numbers to connect to Bob and KDC*/


@param argv[] - Enter the port number while executing the program. The range is 0-65535. This is passed as argument to main()


To compile: (Needs to have openssl package installed)
	 g++ alice3nn.cpp -lssl -lcrypto -o alicennobj
	 g++ bob3nn.cpp -lssl -lcrypto -o bobnnobj
	 g++ kdc3nn.cpp -lssl -lcrypto -o kdcnnobj
	
To execute:
 	./alicennobj 1540 1541
	./kdcnnobj 1541
	./bobnnobj 1540

NOTE:

When the connection is force terminated and if the server program and client program is run again, please use different <port_number> while executing to avoid port conflicts. 
The previously assigned port number will take time to get released.

If there's binding error while running it for 1st time, then please use different <port_number> while executing to avoid port conflicts. 
