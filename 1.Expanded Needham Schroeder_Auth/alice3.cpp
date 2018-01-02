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
#include <sys/wait.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include<openssl/des.h>
#include<openssl/rand.h>

#define BUFSIZE 512
#define SOCBUFSIZE 8000

using namespace std;


unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE], nonce[8];
unsigned char *e = out;
char rec[SOCBUFSIZE];
int len,random_n;

DES_cblock key1, key2, key3;
DES_cblock seed = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
DES_cblock iveca,ivecab;
DES_key_schedule ksa1, ksa2, ksa3;
DES_key_schedule ksab1, ksab2, ksab3;

//Alice's Keys
static char *keystra1 = "0123456789asdfga";
static char *keystra2 = "0123456789asdfgb";
static char *keystra3 = "0123456789asdfgc";
static char *ivecstra = "0123456789asdfgh";

//Shared Keys
static char *keystrab1 = "0123456789qwerty";
static char *keystrab2 = "0123456789qwerta";
static char *keystrab3 = "0123456789qwertb";
static char *ivecstrab = "0123456789qwertc";
static string kab1_str_g,kab2_str_g,kab3_str_g,alice_n1_g,alice_n1check_g,a_bob_str_g;
static string kb_kab1_g, kb_kab2_g, kb_kab3_g,kb_nb_g,kb_alice_g;
char msg_from_bob[SOCBUFSIZE];


//thrwo error when forked
void error(char msg[100])
{
    perror(msg);
    exit(1);
}

void read_from_pipe (int file)
{
  FILE *stream;
  int c;
  stream = fdopen (file, "r");
  int i=0;
  while ((c = fgetc (stream)) != EOF){
    rec[i]=c;
    putchar (c);
    i++;
  }
  fclose (stream);
}

void write_to_pipe (int file,char s2[])
{
  FILE *stream;
  stream = fdopen (file, "w");
  fprintf (stream,"%s",s2);
  fclose (stream);
}

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



void decrypt_kdc_msg(char s2[]){
        
		char de[]="/////";
		char *c=tokenizer(s2,de); string str1((char *)c);	    //Ka(Kab1)
		c=tokenizer(NULL,de); string str2((char *)c);			//Ka(Kab2)
    	c=tokenizer(NULL,de); string str3((char *)c);			//Ka(Kab3)
    	c=tokenizer(NULL,de); string str4((char *)c);		    //Ka(Kb(Kab1))
    	c=tokenizer(NULL,de); string str5((char *)c);		    //Ka(Kb(Kab2))    
    	c=tokenizer(NULL,de); string str6((char *)c);	     	//Ka(Kb(Kab3))    
       	c=tokenizer(NULL,de); string str7((char *)c);			//Ka(Kb(Nb))    
		c=tokenizer(NULL,de); string str8((char *)c);			//Ka(N1)        			                        
		c=tokenizer(NULL,de); string str9((char *)c);			//Ka(Bob)
		c=tokenizer(NULL,de); string str10((char *)c);			//Ka(Kb(Alice))
				
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
		//Initialize Alice's Keys		
		DES_set_key((C_Block *)keystra1, &ksa1);
		DES_set_key((C_Block *)keystra2, &ksa2);
		DES_set_key((C_Block *)keystra3, &ksa3);       
		 
	    memcpy(out,str1.c_str(),BUFSIZE);												//Ka(Kab1)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kab1) from KDC
		string kab1_str((char *) back);													//Kab1_str
		kab1_str_g=kab1_str;
		//cout<<"\nout:"<<out<<"\n";
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kab1_str_g.length();
		cout<<"\nDecrypted Ka(Kab1):"<<kab1_str_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));	 
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str2.c_str(),BUFSIZE);												//Ka(Kab2)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kab2) from KDC
		string kab2_str((char *) back);													////Kab2_str
		kab2_str_g=kab2_str;
		//cout<<"\nout:"<<out<<"\n";		
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kab2_str_g.length();
		cout<<"\nDecrypted Ka(Kab2):"<<kab2_str_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str3.c_str(),BUFSIZE);												//Ka(Kab3)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kab3) from KDC
		string kab3_str((char *) back);													//Kab3_str
		kab3_str_g=kab3_str;
		//cout<<"\nout:"<<out<<"\n";
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kab3_str_g.length();
		cout<<"\nDecrypted Ka(Kab3):"<<kab3_str_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str4.c_str(),BUFSIZE);												//Ka(Kb(Kab1))
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kb(Kab1)) from KDC
		string kb_kab1_str((char *) back);
		kb_kab1_g=kb_kab1_str;
		//cout<<"\nout:"<<out<<"\n";
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kb_kab1_g.length();
		cout<<"\nDecrypted Ka(Kb(Kab1)):"<<kb_kab1_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str5.c_str(),BUFSIZE);												//Ka(Kb(Kab2))
		len = strlen((char *)out);
		//cout<<"\nout:"<<out<<"\n";
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kb(Kab2)) from KDC
		string kb_kab2_str((char *) back);
		kb_kab2_g=kb_kab2_str;
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kb_kab2_g.length();
		cout<<"\nDecrypted Ka(Kb(Kab2)):"<<kb_kab2_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str6.c_str(),BUFSIZE);												//Ka(Kb(Kab3))
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kb(Kab3)) from KDC
		string kb_kab3_str((char *) back);
		kb_kab3_g=kb_kab3_str;
		//cout<<"\nout:"<<out<<"\n";
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kb_kab3_g.length();
		cout<<"\nDecrypted Ka(Kb(Kab3)):"<<kb_kab3_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str7.c_str(),BUFSIZE);												//Ka(Kb(Nb))
		len = strlen((char *)out);
		//cout<<"\nout:"<<out<<"\n";
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kb(Nb)) from KDC
		string kb_nb((char *) back);
		kb_nb_g=kb_nb;
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kb_nb_g.length();
		cout<<"\nDecrypted Ka(Kb(Nb)):"<<kb_nb_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str8.c_str(),BUFSIZE);												//Ka(N1)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(N1) from KDC
		string n1_str((char *) back);													//n1_str
		alice_n1check_g=n1_str;
		//cout<<"\nout:"<<out<<"\n";		
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<n1_str.length();
		cout<<"\nDecrypted Ka(N1):"<<alice_n1check_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str9.c_str(),BUFSIZE);												//Ka(Bob)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Bob) from KDC
		string a_bob_str((char *) back);													////a_bob_str
		a_bob_str_g=a_bob_str;
		//cout<<"\nout:"<<out<<"\n";		
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<a_bob_str_g.length();
		cout<<"\nDecrypted Ka(Bob):"<<a_bob_str_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));
	    
        memcpy(iveca, (C_Block *)ivecstra, sizeof(iveca));
	    memcpy(out,str10.c_str(),BUFSIZE);												//Ka(Kb(Alice))
		len = strlen((char *)out);
		//cout<<"\nout:"<<out<<"\n";
		DES_ede3_cbc_encrypt(out, back, len, &ksa1, &ksa2, &ksa3, &iveca, DES_DECRYPT);  //decrypt Ka(Kb(Alice)) from KDC
		string kb_alice((char *) back);
		kb_alice_g=kb_alice;
	    //cout<<"\noutlen:"<<strlen((char *)out);	
  		//cout<<"\nlen:"<<kb_alice_g.length();
		cout<<"\nDecypted Ka(Kb(Alice)):"<<kb_alice_g;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));


}
//process forked to communicate with KDC
void newsoc(int port_num2, int mypipe){
        
       	struct sockaddr_in thieraddr2;
	    char sendbuf2[SOCBUFSIZE],recbuf2[SOCBUFSIZE];
      	int sockfd2,newfd2;
      	//unsigned char nonce[8];

      
        sockfd2=socket(AF_INET,SOCK_STREAM,0);

        cout<<"\nport number to KDC:"<<port_num2<<"\n";
        //To delete the newline character entered after executing the program. Clears the input stream
        cin.clear();fflush(stdin);							
		
        thieraddr2.sin_family=AF_INET;
        thieraddr2.sin_port=htons(port_num2);
        thieraddr2.sin_addr.s_addr=INADDR_ANY;

        memset(&thieraddr2.sin_zero,'\0',8);
       
        connect(sockfd2,(struct sockaddr *)&thieraddr2,sizeof(struct sockaddr));
        
		string s1=alice_n1_g;								//N1
		string s2="Alice wants Bob";
		string s3(msg_from_bob);
		string alice_to_kdc=s1+"/////"+s2+"/////"+s3;		//N1,Alice wants Bob, msg_from_Bob
		cout<<"\n3.Alice to KDC:"<<alice_to_kdc;
		strncpy(sendbuf2,alice_to_kdc.c_str(),sizeof(sendbuf2));	//send to KDC, Kb(Nb) which was received from Bob and stored in msg_from Bob
		sendbuf2[sizeof(sendbuf2)-1]='\0';
		//cout<<"\nalice_to_kdc sendbuf val:"<<sendbuf2;
		if(send(sockfd2,sendbuf2,strlen(sendbuf2)+1,0)==1)
		 cout<<"\nSend error\n";
		sendbuf2[0]='\0';
		
        int numbytes=recv(sockfd2,recbuf2,SOCBUFSIZE,0);				//receive ticket from KDC
        recbuf2[numbytes+1]='\0';
       	cout<<"\n4.Reply from KDC:"<<recbuf2;
        write_to_pipe(mypipe,recbuf2);
		
		close(sockfd2);

}


//pass 2 port numbers to connect to Bob and KDC
int main(int argc, char *argv[])    {


       int sockfd,newfd;
       char sendbuf[SOCBUFSIZE],recbuf[SOCBUFSIZE];
       struct sockaddr_in myaddr;
	   struct sockaddr_in thieraddr;
       int numbytes;
	   string sendstr;
       pid_t pid;
       int mypipe[2];
       char de[]="/////";

       unsigned int sin_size;
	   

       int port_num=atoi(argv[1]); 					//port number to Bob
       int port_num2=atoi(argv[2]);					//port number to KDC
       cout<<"\nEntered port number:"<<port_num<<", port to connect kdc:"<<port_num2;
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

       newfd=accept(sockfd,(struct sockaddr *)&thieraddr,&sin_size);	//newfd to communicate with Bob
       if(newfd < 0) cout<<"\nError accepting connection..";
       else cout<<"\nConnection accepted..";
       
       sendstr="I want to talk to you";
       cout<<"\n1. Alice sends:"<<sendstr;
       strncpy(sendbuf,sendstr.c_str(),sizeof(sendbuf)); 				//Send inital hi msg to Bob
       sendbuf[sizeof(sendbuf)-1]='\0';
       if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)   {   
               cout<<"\nsend error\n";
               exit(1);
        	   }
        sendbuf[0]='\0';
        
        numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);						//receive Kb(Nb) from Bob
        recbuf[numbytes+1]='\0';
       	cout<<"\n2.Received Bob's Kb(Nb):"<<recbuf;
//       	char msg_from_bob[SOCBUFSIZE];
       	strncpy(msg_from_bob,recbuf,sizeof(recbuf));   					//forward Kb(Nb) to KDC from Alice
       	recbuf[0]='\0';
        
        
        // 64 bits of random nonce
        RAND_bytes(nonce,sizeof(nonce));			    	//random N1 and stored in nonce[]
		string s1((char *)nonce);
		alice_n1_g=s1;
        cout<<"\nAlice's N1:"<<alice_n1_g;
         
		 //Create the pipe to read from forked process. ie., pipe to read reply from KDC
		if (pipe (mypipe))
	    {
	      fprintf (stderr, "\nPipe failed.");
	      return EXIT_FAILURE;
	    }
        
       //open another connection to KDC
         pid = fork();
        if (pid < (pid_t) 0){
     	     char temp[100]="ERROR on fork";
             error(temp);
        }
         if (pid == (pid_t) 0)  {
            close(sockfd);
            close (mypipe[0]);
            cout<<"\ntrying to connect KDC..";
         	newsoc(port_num2,mypipe[1]);								//pass port number to connect to KDC and Kb(Nb)
         	exit(0);
		 }
		 else{
		  wait(NULL);
		  close (mypipe[1]);
		  read_from_pipe (mypipe[0]);
		  cout<<"\nKDC connc terminated..Bob connection still exists..";
	     }
        
        //cout<<"\nrec read from child:"<<rec;
        decrypt_kdc_msg(rec);
   	    if(alice_n1check_g==alice_n1_g) cout <<"\nN1 equals. KDC Verified";
		
	
		memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
		
		//Initialise shared keys Kab received from KDC
		DES_set_key((C_Block *)kab1_str_g.c_str(), &ksab1);
		DES_set_key((C_Block *)kab2_str_g.c_str(), &ksab2);
		DES_set_key((C_Block *)kab3_str_g.c_str(), &ksab3);
       
	   // 64 bits of random nonce
		RAND_bytes(nonce,sizeof(nonce));	//random N2
		memcpy(in, nonce, BUFSIZE);
		
		cout<<"\nN2 by Alice:"<<in;
		len = strlen((char *)in)+1;
		DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);     //encrypt N2 using Kab
		string kab_n2((char *)out);
		cout<<"\nKab(N2):"<<kab_n2;
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));
//		memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
		string ticket_kab_n2=kb_kab1_g+"/////"+kb_kab2_g+"/////"+kb_kab3_g+"/////"+kb_nb_g+"/////"+kab_n2+"/////"+kb_alice_g;			//ticket_kab_n2
		cout<<"\n5.Alice sends ticket,kab_n2 to Bob:"<<ticket_kab_n2;
		sendbuf[0]='\0';
		strncpy(sendbuf,ticket_kab_n2.c_str(),sizeof(sendbuf));						//send Bob ticket_kab_n2
		sendbuf[sizeof(sendbuf)-1]='\0';
		if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)
	    cout<<"\nSend error\n";
	    sendbuf[0]='\0';
//		kab_n2.clear();

        numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);
        recbuf[numbytes+1]='\0';
       	cout<<"\n6.Received Bob:Kab(N2-1, N3): "<<recbuf;
		char *c=tokenizer(recbuf,de);string str11((char *)c);           //Kab(N2-1)
		c=tokenizer(NULL,de); string str22((char *)c);				    //Kab(N3)			
        recbuf[0]='\0';

        memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	    memcpy(out,str11.c_str(),BUFSIZE);												//Kab(N2-1)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt Kab(N2-1) from Bob
		string kab_n2mi_str((char *) back);													//kab_n2mi_str
		cout<<"\nDecrypted Kab(N2-1):"<<back;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));	 
        memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	    memcpy(out,str22.c_str(),BUFSIZE);												//Kab(N3)
		len = strlen((char *)out);
		DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt Kab(N3) from Bob
		string kab_n3_str((char *) back);												//kab_n3_str
		cout<<"\nDecrypted Kab(N3):"<<back;
	    memset(out, 0, sizeof(out));
	    memset(back, 0, sizeof(back));	 
	    

	    int kab_n3_len=kab_n3_str.length();
	    kab_n3_str[kab_n3_len-1]='\0';				    //calculate N3-1
  		memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
		memset(in, 0, sizeof(in));
	    memcpy(in, kab_n3_str.c_str(), BUFSIZE);
	    cout<<"\nGenerated N3-1 from N3:"<<in;
		len = strlen((char *)in)+1;
		DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);     //encrypt N3-1 using Kab
		string kab_n3_mi((char *)out);
		cout<<"\n7.Alice sends Encrypted Kab(N3-1):"<<kab_n3_mi;
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));
		strncpy(sendbuf,kab_n3_mi.c_str(),sizeof(sendbuf));						//send Bob ticket_kab_n2
		sendbuf[sizeof(sendbuf)-1]='\0';
		if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)
             cout<<"\nSend error\n";
	    sendbuf[0]='\0';


       while(1){											/*communicate with client. Terminated when force closed*/

        numbytes=recv(newfd,recbuf,SOCBUFSIZE,0);
        recbuf[numbytes+1]='\0';
        cout<<"\nBob:"<<recbuf;
		memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
	    memcpy(out,recbuf,BUFSIZE);
  		len = strlen((char *)out);			
		DES_ede3_cbc_encrypt(out, back, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_DECRYPT);  //decrypt received message from Bob
		cout<<"\nDecrypted Text:"<<back;
        recbuf[0]='\0';
        memset(out, 0, sizeof(out));
        memset(back, 0, sizeof(back));
       	//cout<<"\nClient: "<<recbuf<<"\n";
       	//recbuf[0]='\0';

		cout<<"\nAlice:";
		sendstr.clear();
       	getline(cin,sendstr);
		memcpy(in,sendstr.c_str(),BUFSIZE);
        memcpy(ivecab, (C_Block *)ivecstrab, sizeof(ivecab));
		len = strlen((char *)in)+1;	
		DES_ede3_cbc_encrypt(in, out, len, &ksab1, &ksab2, &ksab3, &ivecab, DES_ENCRYPT);
		string sendstr3((char *)out);
		strncpy(sendbuf,sendstr3.c_str(),sizeof(sendbuf));
       	sendbuf[sizeof(sendbuf)-1]=0;
       	if(send(newfd,sendbuf,strlen(sendbuf)+1,0)==1)   {
               cout<<"\nsend error";
               exit(1);
        	   }
        sendbuf[0]='\0';
		}

		
     //  close(sockfd2);
  	    close(newfd);
//       close(sockfd);
       

       return 0;
}


