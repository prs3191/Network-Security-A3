README.TXT for Expanded Needham Schroeder
--------------------------------------------

This includes three .cpp files.
(1)alice3.cpp
(2)bob3.cpp
(3)kdc3.cpp

Description:
(1) and (2) .cpp programs has to be run before the socket client program (3).
Here ALice, KDC are server and Bob is the client

Pre-Defined Variables:
- Alice's key in (1)
- Bob's Key in (2)
- Alice and Bob's Shared Key in (1),(2)
- KDC has all above keys.

Openssl Functions:

DES_ede3_cbc_encrypt() - to encrypt input data using 3DES CBC with DES_ENCRYPT flag
DES_ede3_cbc_encrypt() - to decrypt the data using 3DES CBC with DES_DECRYPT flag


Functions:
----(1,2,3)----
error() - throws error message when forked process fails.

read_from_pipe() - Reads data from pipe.

write_to_pipe() - Write data to pipe.

tokenizer() - Its a parser.

decrypt_kdc_msg() - decrypt message from Bob,KDC.

newsoc() - process forked to communicate with KDC

main() - performs socket programming. /*Pass 2 port numbers to connect to Bob and KDC*/

@param argv[] - Enter the port number while executing the program. The range is 0-65535. This is passed as argument to main()


To compile: (Needs to have openssl package installed)
	 g++ alice3.cpp -lssl -lcrypto -o aliceobj
	 g++ bob3.cpp -lssl -lcrypto -o bobobj
	 g++ kdc3.cpp -lssl -lcrypto -o kdcobj
To execute:
 	./aliceobj 1300 1301
	./kdcobj 1300
	./bobobj 1301
NOTE:

When the connection is force terminated and if the server program and client program is run again, please use different <port_number> while executing to avoid port conflicts. 
The previously assigned port number will take time to get released.

If there's binding error while running it for 1st time, then please use different <port_number> while executing to avoid port conflicts. 
