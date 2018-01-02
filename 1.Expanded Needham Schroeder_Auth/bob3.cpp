#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<iostream>
#include<stdlib.h>
#include<sstream>
#include<openssl/rand.h>
#include<openssl/des.h>
#define BUFSIZE 512
#define SOCBUFSIZE 8000
using namespace std;

char *tokenizer(char *input, char *delimiter) {
    static char *string;
    if (input != NULL)
        string = input;		//assign ststic string before 1st split and after every split

    if (string == NULL){
    	cout<<"\nparsed:"<<string;
       return string;		//final null char in original string
	}
     

    char *end = strstr(string, delimiter);  //pointer to 1st occurance of delim
    if (end == NULL) {
        char *temp = string;
        string = NULL;
       	cout<<"\nparsed:"<<temp;
        return temp;	  //when entire string is parsed
    }

    char *temp = string;

    *end = '\0';
    string = end + strlen(delimiter);
   	cout<<"\nparsed:"<<temp;
    return temp;
}

//pass port number to connect to Alice
int main(int argc, char * argv[])    {


    int sockfd,numbytes;
    struct sockaddr_in thieraddr;
    char sendbuf[SOCBUFSIZE],recbuf[SOCBUFSIZE];
    
    unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE], nonce[8];
	unsigned char *e = out;
	int len,random_n;

	DES_cblock key1, key2, key3;
	DES_cblock seed = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	DES_cblock ivecb,ivecab;
	DES_key_schedule ksb1, ksb2, ksb3;
	DES_key_schedule ksab1, ksab2, ksab3;
  
  	//Bob's Keys
    static char *keystrb1 = "0123456789abcdea";
    static char *keystrb2 = "0123456789abcdeb";
    static char *keystrb3 = "0123456789abcdec";
    static char *ivecstrb = "0123456789abcdef";
	
	//Shared Key
 	static char *keystrab1 = "0123456789qwerty";
    static char *keystrab2 = "0123456789qwerta";
    static char *keystrab3 = "0123456789qwertb";
    static char *ivecstrab = "0123456789qwertc";

    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));
 
    RAND_seed(seed, sizeof(DES_cblock));

   // cout<<"random_n:"<<random_n;
   // cout<<"\nnonce="<<nonce;
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
    
    //Initialize Bob's Keys
    DES_set_key((C_Block *)keystrb1, &ksb1);
    DES_set_key((C_Block *)keystrb2, &ksb2);
    DES_set_key((C_Block *)keystrb3, &ksb3);	
	
	
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	
    int port_num=atoi(argv[1]);
    cout<<"\nEntered port number:"<<port_num;
    //To delete the newline character entered after executing the program. Clears the input stream
    cin.clear();fflush(stdin);							
	
    thieraddr.sin_family=AF_INET;
    thieraddr.sin_port=htons(port_num);
    thieraddr.sin_addr.s_addr=INADDR_ANY;

    memset(&thieraddr.sin_zero,'\0',8);
   
    connect(sockfd,(struct sockaddr *)&thieraddr,sizeof(struct sockaddr));	//connect to Bob
    
    numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);								//Receive hi msg from Alice
    recbuf[numbytes+1]='\0';	
    cout<<"\n1.Received from Alice:"<<recbuf;
    
     //64 bits of random nonce
    RAND_bytes(nonce,sizeof(nonce));										//random NB
    //unsigned char bob_nb[8];
    //memcpy(bob_nb,nonce,8);
    memcpy(in, nonce, BUFSIZE);
    string b_nonce((char*) in);
    cout<<"\nBob's Nb w/o encryp:"<<in;
    len = strlen((char *)in)+1;
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
    DES_ede3_cbc_encrypt(in, out, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_ENCRYPT);	//encrypt Nb using Bob's Key
    string sendstr((char *)out);
    cout<<"\n2.Bob's Kb(Nb):"<<sendstr;
	strncpy(sendbuf,sendstr.c_str(),sizeof(sendbuf));						//send Alice Kb(NB)
    sendbuf[sizeof(sendbuf)-1]='\0';
    if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)
   	 cout<<"\nSend error\n";
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    sendstr.clear();
	
	numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);				//receives ticket and Kab(N2) from Alice
    recbuf[numbytes+1]='\0';
    cout<<"\n5.Bob receives Ticket, Kab(N2) from Alice: "<<recbuf;
    char de[]="/////";	
	char *c=tokenizer(recbuf,de); string str1((char *)c);	    //Kb(Kab1)
	c=tokenizer(NULL,de); string str2((char *)c);			//Kb(Kab2)
	c=tokenizer(NULL,de); string str3((char *)c);			//Kb(Kab3)
	c=tokenizer(NULL,de); string str4((char *)c);		    //Kb(Nb)
	c=tokenizer(NULL,de); string str5((char *)c);           //Kab(N2)
	c=tokenizer(NULL,de); string str6((char *)c);           //Kb(Alice)
    recbuf[0]='\0';
    
    memcpy(out,str1.c_str(),BUFSIZE);											//Kb(Kab1)
	len = strlen((char *)out);
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
//    //Initialize Bob's Keys
//    DES_set_key((C_Block *)keystr1, &ks1);
//    DES_set_key((C_Block *)keystr2, &ks2);
//    DES_set_key((C_Block *)keystr3, &ks3);			
	DES_ede3_cbc_encrypt(out, back, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_DECRYPT);  //decrypt Kb(Kab1)
	string kab1_str((char *) back);												//Kab1_str
	//cout<<"\nout:"<<out<<"\n";		
    //cout<<"\noutlen:"<<strlen((char *)out);	
	//cout<<"\nlen:"<<kab1_str.length();	
    cout<<"\nDecrypted kab1_str:"<<kab1_str;
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));							//Kb(Kab2)
    memcpy(out,str2.c_str(),BUFSIZE);
	len = strlen((char *)out);
	DES_ede3_cbc_encrypt(out, back, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_DECRYPT);  //decrypt Kb(Kab2) from Alice								
	string kab2_str((char *) back);											//Kab2_str
	//cout<<"\nout:"<<out<<"\n";		
    //cout<<"\noutlen:"<<strlen((char *)out);	
	//cout<<"\nlen:"<<kab2_str.length();	
    cout<<"\nDecrypted kab2_str:"<<kab2_str;	    
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	 
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));							//Kb(Kab3)
    memcpy(out,str3.c_str(),BUFSIZE);
	len = strlen((char *)out);
	DES_ede3_cbc_encrypt(out, back, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_DECRYPT);  //decrypt Kb(Kab3) from Alice
	string kab3_str((char *) back);											//Kab3_str
	//cout<<"\nout:"<<out<<"\n";		
    //cout<<"\noutlen:"<<strlen((char *)out);	
	//cout<<"\nlen:"<<kab3_str.length();		
	cout<<"\nDecrypted kab3_str:"<<kab3_str;	       
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));
    
    
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));							//Kb(Nb)
    memcpy(out,str4.c_str(),BUFSIZE);
	len = strlen((char *)out);
	DES_ede3_cbc_encrypt(out, back, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_DECRYPT);  //decrypt Kb(Kab3) from Alice
	string nb_str((char *) back);										     	//nb_str
	//cout<<"\nout:"<<out<<"\n";		
    //cout<<"\noutlen:"<<strlen((char *)out);	
	//cout<<"\nlen:"<<kab3_str.length();		
	cout<<"\nDecrypted nb_str:"<<nb_str;	       
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));
    
	
    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));							//Kb(Alice)
    memcpy(out,str6.c_str(),BUFSIZE);
	len = strlen((char *)out);
	DES_ede3_cbc_encrypt(out, back, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_DECRYPT);  //decrypt Kb(Kab3) from Alice
	string alice_str((char *) back);										     	//alice
	//cout<<"\nout:"<<out<<"\n";		
    //cout<<"\noutlen:"<<strlen((char *)out);	
	//cout<<"\nlen:"<<alice_str.length();		
	cout<<"\nDecrypted alice_str:"<<alice_str;	       
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
	

	//cout<<"\nbob_nb:"<<bob_nb;									//Verify if ticket has been received from Alice, which Alice received from KDC
	cout<<"\nGenerated nb_nonce:"<<b_nonce;
	cout<<"\nDecrypted nb_str:"<<nb_str;
	if(b_nonce == nb_str) {
        cout << "\nNb equals from ticket. "<<alice_str<<" VERIFIED.";
	}
	else cout <<"\nNb not equals from ticket. "<<alice_str<<" not Verified.";
	
	//initialise keys with Kab recived from Alice
    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));	
    DES_set_key((C_Block *)kab1_str.c_str(), &ksab1);
    DES_set_key((C_Block *)kab2_str.c_str(), &ksab2);
    DES_set_key((C_Block *)kab3_str.c_str(), &ksab3);
						 					 		 	   					//Kab(N2)
    memcpy(out,str5.c_str(),BUFSIZE);
	len = strlen((char *)out);
	DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt Kab(N2) from Alice
	cout<<"\nDecrypted Kab(N2):"<<back;
	char nonce2[8];
	memcpy(nonce2,back,BUFSIZE);					//store N2 in nonce2[]
    recbuf[0]='\0';
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in)); 

    nonce2[7]='\0';									//calculate N2-1
    cout<<"\nGenerated N2-1 from N2:"<<nonce2;
	memcpy(in,nonce2,BUFSIZE);
    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	len = strlen((char *)in)+1;
	DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);  //encrypt N2-1 using Kab
	string sendstr4((char *)out);
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
	sendbuf[0]='\0';

     /* 64 bits of random nonce*/
    RAND_bytes(nonce,sizeof(nonce));				//random N3 and stored in nonce[]
    memcpy(in, nonce, BUFSIZE);
    string n3_str((char *) in);
    cout<<"\nGenerated N3:"<<nonce;
    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	len = strlen((char *)in)+1;
	DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);  //encrypt using Kab and send Alice Kab(N3)
	string sendstr5((char *)out);
	cout<<"\nEncrypted Kab(N3):"<<sendstr5;
	
	string kab_n2mi_n3=sendstr4+"/////"+sendstr5;
	cout<<"\n6.Bob sends Kab(N2-1,N3):"<<kab_n2mi_n3;
	strncpy(sendbuf,kab_n2mi_n3.c_str(),sizeof(sendbuf));			//send Alice Kab(N2-1, N3)
    sendbuf[sizeof(sendbuf)-1]='\0';
    if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)
            cout<<"\nSend error\n";
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    sendbuf[0]='\0';
    
   	numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);				//receives Kab(N3-1) from Alice
    recbuf[numbytes+1]='\0';
    cout<<"\n7.Received from Alice Kab(N3-1):"<<recbuf;
    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
    memcpy(out,recbuf,BUFSIZE);
	len = strlen((char *)out);
	memset(back, 0, sizeof(back));
	DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt Kab(N3-1)
	string n3mi_str((char *)back);
	cout<<"\nDecrypted Kab(N3-1):"<<back;
    recbuf[0]='\0';
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in));
    
    
    cout<<"\nsent N3:"<<n3_str;
    cout<<"\nreceived n3-1"<<n3mi_str;
    if(n3_str == n3mi_str)
    		  cout<<"\nAlice Authenticated..Send encrypted message";
 
    
     /*communicate with client. Terminated when force closed*/
	 while(1){
	 											
	 											
	    cout<<"\nClient: ";
        cin.clear();fflush(stdin);
        string sendstr2;
        getline(cin,sendstr2);
		memcpy(in,sendstr2.c_str(),BUFSIZE);
        memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
		len = strlen((char *)in)+1;	
		DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);
		string sendstr3((char *)out);
		strncpy(sendbuf,sendstr3.c_str(),sizeof(sendbuf));
        sendbuf[sizeof(sendbuf)-1]='\0';
        if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)
                cout<<"\nSend error";
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        sendbuf[0]='\0';
        
        
        numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);
        recbuf[numbytes+1]='\0';
        cout<<"\nAlice: "<<recbuf;
	    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	    memcpy(out,recbuf,BUFSIZE);
  		len = strlen((char *)out);			
		DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt received message from Alice
		cout<<"\nDecrypted Text:"<<back;
        recbuf[0]='\0';
        memset(out, 0, sizeof(out));
        memset(back, 0, sizeof(back));
	        
	
	}
    close(sockfd);
    return 0;

}
