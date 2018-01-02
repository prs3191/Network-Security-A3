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

unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE], nonce[8];
unsigned char *e = out;
int len,random_n;

DES_cblock key1, key2, key3;
DES_cblock seed = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
DES_cblock iveca,ivecb,ivecab;
DES_key_schedule ksa1, ksa2, ksa3;
DES_key_schedule ksb1, ksb2, ksb3;
DES_key_schedule ksab1, ksab2, ksab3;

static char *keystra1 = "0123456789asdfgq";			//Alice's Key Ka
static char *keystra2 = "0123456789asdfgw";
static char *keystra3 = "0123456789asdfge";
static char *ivecstra = "0123456789asdfgh";

static char *keystrb1 = "0123456789abcdef";			//Bob's Key Kb
static char *keystrb2 = "0123456789abcdeg";
static char *keystrb3 = "0123456789abcdeh";
static char *ivecstrb = "0123456789abcdei";
                                                   //Shared Key
static char *keystrab1 = "0123456789qwerty";
static char *keystrab2 = "0123456789qwerta";
static char *keystrab3 = "0123456789qwertb";
static char *ivecstrab = "0123456789qwertc";

//parser
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
int main(int argc, char *argv[])    {


       int sockfd,newfd;
       char sendbuf[SOCBUFSIZE],recbuf[SOCBUFSIZE];
       struct sockaddr_in myaddr,thieraddr;
       int numbytes;
	   string sendstr;
       unsigned int sin_size;
	   
	   
       int port_num=atoi(argv[1]);
       cout<<"\nEntered port number:"<<port_num;
       //To delete the newline character entered after executing the program. Clears the input stream
       cin.clear();											
       fflush(stdin);

	   
       sockfd=socket(AF_INET,SOCK_STREAM,0);

       myaddr.sin_family=AF_INET;
       myaddr.sin_port=htons(port_num);
       myaddr.sin_addr.s_addr=INADDR_ANY;

       memset(&myaddr.sin_zero,'\0',8);

       if( bind(sockfd,(struct sockaddr *)&myaddr,sizeof(struct sockaddr )) < 0){
	   	cout<<"\nBinding error..";
	   }
       else cout<<"\nBinding successful..";
       
	   listen(sockfd,5);

       sin_size=sizeof(struct sockaddr_in);

       newfd=accept(sockfd,(struct sockaddr *)&thieraddr,&sin_size);
       if(newfd < 0) cout<<"\nError accepting connection..";
       else cout<<"\nConnection accepted..";
       
	    memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));
		memset(back, 0, sizeof(back));
		RAND_seed(seed, sizeof(DES_cblock));	
		
		//Initialize with Bob's Key
		memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
		DES_set_key((C_Block *)keystrb1, &ksb1);
		DES_set_key((C_Block *)keystrb2, &ksb2);
		DES_set_key((C_Block *)keystrb3, &ksb3);	

	 	numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);				//receives from Alice - N1,some msg
	    recbuf[numbytes+1]='\0';
	    cout<<"\n1.Received from Alice: "<<recbuf;
	    
		char de[]="/////";
		char *c=tokenizer(recbuf,de); string str1_n1((char *)c);	    //N1
		c=tokenizer(NULL,de); string str2((char *)c);			//Alice wants Bob   

//Now KDC sends Alice ticket to bob, Ka(Kab)
		string kab1_str=keystrab1; string kab2_str=keystrab2; string kab3_str=keystrab3;	//shared keys to Alice
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca)); 
		DES_set_key((C_Block *)keystra1, &ksa1);
		DES_set_key((C_Block *)keystra2, &ksa2);
		DES_set_key((C_Block *)keystra3, &ksa3);
	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memcpy(in, kab1_str.c_str(), BUFSIZE);											//Kab1_str
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);    //encrypt Kab1_str using Ka
	    string ka_kab1_str((char *)out);
	    //cout<<"\nin:"<<in;
	    //cout<<"\nout:"<<out;
	    cout<<"\nKa(Kab1):"<<ka_kab1_str;
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);
        //cout<<"\nlen:"<<ka_kab1_str.length();
	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca)); 
	    memcpy(in, kab2_str.c_str(), BUFSIZE);											//Kab2_str
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);    //encrypt Kab2_str using Ka
	    string ka_kab2_str((char *)out);
	    //cout<<"\nin:"<<in;
	    //cout<<"\nout:"<<out;
	    cout<<"\nKa(Kab2):"<<ka_kab2_str;
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);	    
        //cout<<"\nlen:"<<ka_kab2_str.length();

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca)); 
	    memcpy(in, kab3_str.c_str(), BUFSIZE);											//Kab3_str
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);    //encrypt Kab3_str using Ka
	    string ka_kab3_str((char *)out);
  	    //cout<<"\nin:"<<in;
	    //cout<<"\nout:"<<out;
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);
	    cout<<"\nKa(Kab3):"<<ka_kab3_str;
        //cout<<"\nlen:"<<ka_kab3_str.length();

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));

		
	    memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));  			   					//calculate Ka(Kb(Kab))

	    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));  	
		memcpy(in, kab1_str.c_str(), BUFSIZE);										    //Kab1_str
		//cout<<"\nkab1_str:"<<kab1_str<<"\n";
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_ENCRYPT);    //encrypt kab1_str using Kb
	    //cout<<"\nout:"<<out<<"\n";
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    len = strlen((char *)out)+1;		
	    DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);  //encrypt Kb(kab1_str) using Ka
	    string ka_kb_kab1_str((char *)back);											//ka_kb_kab1_str		
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);
		cout<<"\nKa(Kb(Kab1)):"<<ka_kb_kab1_str;		
        //cout<<"\nlen:"<<ka_kb_kab1_str.length();

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
   		memcpy(in, kab2_str.c_str(), BUFSIZE);											//Kab2_str
		//cout<<"\nkab2_str:"<<kab2_str<<"\n";	    
		len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_ENCRYPT);    //encrypt kab2_str using Kb
	    //cout<<"\nout:"<<out<<"\n";
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
  	    len = strlen((char *)out)+1;
	    DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);  //encrypt Kb(kab2_str) using Ka
	    string ka_kb_kab2_str((char *)back);											//ka_kb_kab2_str	
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);		
		cout<<"\nKa(Kb(Kab2))"<<ka_kb_kab2_str;  
        //cout<<"\nlen:"<<ka_kb_kab2_str.length();

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
   		memcpy(in, kab3_str.c_str(), BUFSIZE);											//Kab3_str
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_ENCRYPT);    //encrypt kab2_str using Kb
		//cout<<"\nkab3_str:"<<kab3_str<<"\n";  
	    //cout<<"\nout:"<<out<<"\n";
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
  	    len = strlen((char *)out)+1;
	    DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);  //encrypt Kb(kab2_str) using Ka
	    string ka_kb_kab3_str((char *)back);											//ka_kb_kab3_str
		cout<<"\nKa(Kb(Kab3)):"<<ka_kb_kab3_str;  					
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);        
		//cout<<"\nlen:"<<ka_kb_kab3_str.length();

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
		memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca)); 
	    memcpy(in, str1_n1.c_str(), BUFSIZE);											//N1
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);    //encrypt Ka(N1)
	    string ka_n1_str((char *)out);
  	    //cout<<"\nin:"<<in;
	    //cout<<"\nout:"<<out;
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);
	    cout<<"\nKa(N1):"<<ka_n1_str;
        //cout<<"\nlen:"<<ka_n1_str.length();
        
	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
		memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca)); 
	    memcpy(in, "Bob", BUFSIZE);											//"Bob"
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);    //encrypt Ka(Bob)
	    string ka_bob_str((char *)out);
  	    //cout<<"\nin:"<<in;
	    //cout<<"\nout:"<<out;
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);
	    cout<<"\nKa(Bob):"<<ka_bob_str;
        //cout<<"\nlen:"<<ka_bob_str.length();        

	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    memcpy(ivecb, (C_Block *)ivecstrb, sizeof(ivecb));
   		memcpy(in, "Ailce", BUFSIZE);											//"Alice"
	    len = strlen((char *)in)+1;
	    DES_ede3_cbc_encrypt(in, out, len, &ksb1, &ksb2, &ksb3, &ivecb, DES_ENCRYPT);    //encrypt Kb(Alice) 
	    //cout<<"\nin:"<<in;
		//cout<<"\nout:"<<out<<"\n";
	    memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
  	    len = strlen((char *)out)+1;
	    DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_ENCRYPT);  //encrypt Ka(Kb(Alice))
	    string ka_kb_alice_str((char *)back);											//ka_kb_alice_str
		cout<<"\nKa(Kb(Alice)):"<<ka_kb_alice_str;  					
	    //cout<<"\ninlen:"<<strlen((char *)in);
	    //cout<<"\noutlen:"<<strlen((char *)out);        
		//cout<<"\nlen:"<<ka_kb_alice_str.length();	    
	    
    
string kdc_reply=ka_kab1_str+"/////"+ka_kab2_str+"/////"+ka_kab3_str+"/////"+ka_kb_kab1_str+"/////"+ka_kb_kab2_str+"/////"+ka_kb_kab3_str+"/////"+ka_n1_str+"/////"+ka_bob_str+"/////"+ka_kb_alice_str;
	    cout<<"\n2. KDC to Alice:"<<kdc_reply;
	   	strncpy(sendbuf,kdc_reply.c_str(),sizeof(sendbuf));	
	    sendbuf[sizeof(sendbuf)-1]='\0';
	    if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)
	   	 cout<<"\nSend error..";
	    memset(in, 0, sizeof(in));
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        sendbuf[0]='\0';

//       while(1){											/*communicate with client. Terminated when force closed*/

 /*       numbytes=recv(newfd,recbuf,999,0);
        recbuf[numbytes+1]='\0';
       	cout<<"\nClient: "<<recbuf<<"\n";
       	recbuf[0]='\0';

		cout<<"\nServer:";
       	getline(cin,sendstr);

       	strncpy(sendbuf,sendstr.c_str(),sizeof(sendbuf));
       	sendbuf[sizeof(sendbuf)-1]=0;
       	if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)   {
               cout<<"\nsend error\n";
               exit(1);
        	   }
        sendbuf[0]='\0';
		}
*/
		
	   close(newfd);
       close(sockfd);
       

       return 0;
}


