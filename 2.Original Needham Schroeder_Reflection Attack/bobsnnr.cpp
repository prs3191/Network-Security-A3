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
DES_key_schedule ksa1, ksa2, ksa3;
DES_key_schedule ksb1, ksb2, ksb3;
DES_key_schedule ksab1, ksab2, ksab3;


static char *keystrb1 = "0123456789abcdef";			//Bob's Key Kb
static char *keystrb2 = "0123456789abcdeg";
static char *keystrb3 = "0123456789abcdeh";
static char *ivecstrb = "0123456789abcdei";
                                                   //Shared Key
static char *keystrab1 = "0123456789qwerty";
static char *keystrab2 = "0123456789qwerta";
static char *keystrab3 = "0123456789qwertb";
static char *ivecstrab = "0123456789qwertc";


//pass port number to connect to Alice
int main(int argc, char *argv[])    {

   int sockfd,newfd;
   char sendbuf[SOCBUFSIZE],recbuf[SOCBUFSIZE],nonce[8];
   struct sockaddr_in myaddr,thieraddr;
   int numbytes;
   string sendstr;
   unsigned int sin_size;

   int port_num=atoi(argv[1]);
   //int port_num2=atoi(argv[2]);
   cout<<"\nEntered port number to Bob1:"<<port_num;
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
	DES_set_key((C_Block *)keystrab1, &ksab1);
	DES_set_key((C_Block *)keystrab2, &ksab2);
	DES_set_key((C_Block *)keystrab3, &ksab3);	

 	numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);				//receives from Trudy - ticket,Kab(N2) //also Kab(N4)
    recbuf[numbytes+1]='\0';
    cout<<"\nReceived from Alice:"<<recbuf;

	//decrypte Kab(N2) //Kab(N4)
    memcpy(out,recbuf,BUFSIZE);
 	len = strlen((char *)out);
 	//cout<<"\noutlen:"<<len;
	for(int i=0;i<len;i+=8){
       DES_ecb3_encrypt((C_Block *)(out + i),(C_Block *)(back + i), &ksab1, &ksab2, &ksab3, DES_DECRYPT);   //decrypt Kab(N2) from Alice //also Kab(N4) from Trudy
    }
	//cout<<"\nDecrypted Text:"<<back;
	//cout<<"\nabove len:"<<strlen((char *)back);
	unsigned char nonce2[8];
	memcpy(nonce2,back,BUFSIZE);					//store N2 in nonce2[] //also N4
    cout<<"\nDecrypted Text:nonce2/4:"<<nonce2;
	recbuf[0]='\0';
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in)); 

   // unsigned char dupnonce2[7];									//calculate N2-1  //also N4-1
  //  memcpy(dupnonce2,nonce2,sizeof(dupnonce2));
    nonce2[7]='\0';
	cout<<"\nGenerated N2/4-1 from N2/4:"<<nonce2;
	//cout<<"\nlen:"<<strlen((char *)nonce2);
    string n2((char *)nonce2); 
    //cout<<"\nn2_str len:"<<n2.length();
	memcpy(in,n2.c_str(),BUFSIZE);
	//cout<<"\ninlen:"<<strlen((char *)in);
	len = strlen((char *)in);
	for(int i=0;i<len;i+=8){
        DES_ecb3_encrypt((C_Block *)(in + i),(C_Block *)(out + i), &ksab1, &ksab2, &ksab3, DES_ENCRYPT);   //encrypt Kab(N2-1) //also Kab(N4-1)
    }
   	string kab_n2mi_str((char *)out);
	cout<<"\nKab(N2/4-1) from Bob:"<<kab_n2mi_str;
	//cout<<"\nlen:"<<kab_n2mi_str.length();
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in)); 
    
    
    unsigned char nonce4[8];
    RAND_bytes(nonce4,sizeof(nonce4));				//random N4 and stored in nonce[] //also N5
    string n4((char *)nonce4);
    cout<<"\nGenerated N4:"<<n4;
   	//cout<<"\nlen:"<<strlen((char *)nonce4);
    memcpy(in,n4.c_str(),BUFSIZE);
    len = strlen((char *)in);
	for(int i=0;i<len;i+=8){
        DES_ecb3_encrypt((C_Block *)(in + i),(C_Block *)(out + i), &ksab1, &ksab2, &ksab3, DES_ENCRYPT);   //encrypt Kab(N4) //also Kab(N5)
    }
   	string kab_n4_str((char *)out);
	cout<<"\nKab(N4/N5) from Bob:"<<kab_n4_str;
	//cout<<"\nlen:"<<kab_n4_str.length();
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in)); 
	
    string kab_n2min4_str=kab_n2mi_str+"/////"+kab_n4_str;
	cout<<"\nKab(N2/4-1,N4/5) from Bob:"<<kab_n2min4_str;
	//cout<<"\nlen:"<<kab_n2min4_str.length();
	sendbuf[0]='\0';
   	strncpy(sendbuf,kab_n2min4_str.c_str(),sizeof(sendbuf));	    //send Kab(N2-1,N4)  //also Kab(N4-1,N5)
    sendbuf[sizeof(sendbuf)-1]='\0';
    if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)
   	 cout<<"\nSend error";
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
	sendbuf[0]='\0';
	
 	numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);				//receives from Trudy - Kab(N4-1)
    recbuf[numbytes+1]='\0';
    cout<<"\nReceived from Alice:Kab(N4-1):"<<recbuf;

	//decrypte Kab(N4-1)
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
	memset(back, 0 ,sizeof(back));
    memcpy(out,recbuf,BUFSIZE);
 	len = strlen((char *)out);
	for(int i=0;i<len;i+=8){
       DES_ecb3_encrypt((C_Block *)(out + i),(C_Block *)(back + i), &ksab1, &ksab2, &ksab3, DES_DECRYPT);   //decrypt also Kab(N4-1) from Trudy
    }
	cout<<"\nDecrypted Text:N4-1:"<<back;
    cout<<"\nlen:"<<strlen((char *)back);
    string check_n4mi((char *) back);					//received N4-1 
    recbuf[0]='\0';
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));	
    memset(in, 0, sizeof(in)); 
    
    unsigned char check_n4[8];
    memcpy(check_n4,nonce4,8);			//sent N4 and calculate N4-1
    check_n4[7]='\0';
    string check_sent_n4_str((char *)check_n4);
    cout<<"\nsent n4:"<<check_sent_n4_str;
    cout<<"\nreceived n4-1:"<<check_n4mi;
    if(check_n4mi == check_sent_n4_str) cout <<"\nTrudy Impersonated Alice..";
	else cout <<"\nReflection attack missed";

	while(1){											/*communicate with client. Terminated when force closed*/

	cout<<"\nBob:";
	getline(cin,sendstr);
	
	strncpy(sendbuf,sendstr.c_str(),sizeof(sendbuf));
	sendbuf[sizeof(sendbuf)-1]=0;
	if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)   {
	       cout<<"\nsend error\n";
	       exit(1);
		   }
	sendbuf[0]='\0';
	
	numbytes=recv(newfd,recbuf,999,0);
	recbuf[numbytes+1]='\0';
	cout<<"\nClient: "<<recbuf<<"\n";
	recbuf[0]='\0';
	
	
	}
	
	close(newfd);
	close(sockfd);


       return 0;
}


