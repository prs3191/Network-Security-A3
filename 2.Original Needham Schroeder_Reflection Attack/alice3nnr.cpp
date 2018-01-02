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
DES_key_schedule ksa1, ksa2, ksa3;
DES_key_schedule ksab1, ksab2, ksab3;

//Alice's Keys //not used in this program as Trudy is impersonation Alice.
static char *keystra1 = "0123456789asdfgq";
static char *keystra2 = "0123456789asdfgw";
static char *keystra3 = "0123456789asdfge";
static char *ivecstra = "0123456789asdfgh";

//Shared Keys
/*for demo purposes only*/
static char *keystrab1 = "0123456789qwerty";
static char *keystrab2 = "0123456789qwerta";
static char *keystrab3 = "0123456789qwertb";
static char *ivecstrab = "0123456789qwertc";

static string kab1_str_g,kab2_str_g,kab3_str_g,alice_n1_g,alice_n1check_g,a_bob_str_g;
static string kb_kab1_g, kb_kab2_g, kb_kab3_g,kb_nb_g,kb_alice_g;
char msg_from_bob[SOCBUFSIZE];


//throw error when forked
void error(char msg[100])
{
    perror(msg);
    exit(1);
}

//read data from pipe
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

//write data to pipe
void write_to_pipe (int file,char s2[])
{
  FILE *stream;
  stream = fdopen (file, "w");
  fprintf (stream,"%s",s2);
  fclose (stream);
}

//process forked to communicate with another session of Bob at different port
void newsoc(int port_num2, int mypipe, string s22){
        
       	struct sockaddr_in thieraddr2;
	    char sendbuf2[SOCBUFSIZE],recbuf2[SOCBUFSIZE];
      	int sockfd2,newfd2;
      	//unsigned char nonce[8];

        sockfd2=socket(AF_INET,SOCK_STREAM,0);

        cout<<"\nport number to Bob:"<<port_num2;
        //To delete the newline character entered after executing the program. Clears the input stream
        cin.clear();fflush(stdin);							
		
        thieraddr2.sin_family=AF_INET;
        thieraddr2.sin_port=htons(port_num2);
        thieraddr2.sin_addr.s_addr=INADDR_ANY;

        memset(&thieraddr2.sin_zero,'\0',8);
       
        connect(sockfd2,(struct sockaddr *)&thieraddr2,sizeof(struct sockaddr));
        
		
		strncpy(sendbuf2,s22.c_str(),sizeof(sendbuf2));	//send to Bob Kab(N4)
		sendbuf2[sizeof(sendbuf2)-1]='\0';
		cout<<"\nTrudy to Bob:Kab(N4):"<<sendbuf2;
		if(send(sockfd2,sendbuf2,strlen(sendbuf2)+1,0)==1)
		 cout<<"\nSend error..";
		sendbuf2[0]='\0';
		
        int numbytes=recv(sockfd2,recbuf2,SOCBUFSIZE,0);				//receive Kab(N4-1,N5) from Bob
        recbuf2[numbytes+1]='\0';
       	cout<<"\nReply from Bob:Kab(N4-1,N5):"<<recbuf2;
        write_to_pipe(mypipe,recbuf2);
		cout<<"\nclosing dup Bob connc..";
		close(sockfd2);

}


//pass 2 port numbers to connect to Bob and KDC
int main(int argc, char *argv[])    {


       int sockfd;
       char sendbuf[SOCBUFSIZE],recbuf[SOCBUFSIZE];
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

       thieraddr.sin_family=AF_INET;
       thieraddr.sin_port=htons(port_num);
       thieraddr.sin_addr.s_addr=INADDR_ANY;

       memset(&thieraddr.sin_zero,'\0',8);

       connect(sockfd,(struct sockaddr *)&thieraddr,sizeof(struct sockaddr));	//connect to Bob
         
		/*for demo purposes only*/   
		/*generating Kab(N2) here*/
        // 64 bits of random nonce
        RAND_bytes(nonce,sizeof(nonce));			    	//random N2 and stored in nonce[]
		string s1((char *)nonce);

	    /*for demo purposes only*/ 
		//Initialise shared keys Kab received from KDC
		DES_set_key((C_Block *)keystrab1, &ksab1);
		DES_set_key((C_Block *)keystrab2, &ksab2);
		DES_set_key((C_Block *)keystrab3, &ksab3);
		
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));
		memset(out, 0, sizeof(back));
  		memcpy(in, nonce, BUFSIZE);
		//cout<<"\nN2 by Alice:"<<in;
		//cout<<"\ninlen:"<<strlen((char *)in);
		len = strlen((char *)in);

		for(int i=0;i<len;i+=8){ 									//block by block encryption
				DES_ecb3_encrypt((C_Block *)(in + i),(C_Block *)(out + i), &ksab1, &ksab2, &ksab3, DES_ENCRYPT);  //encrypt N2 using Kab
	    }
		string ticket_kab_n2((char *)out);
		cout<<"\nStored Kab(N2):"<<ticket_kab_n2;
		//cout<<"\noutlen:"<<strlen((char *)out);
		memset(in, 0, sizeof(in));
		memset(out, 0, sizeof(out));
		sendbuf[0]='\0';
		strncpy(sendbuf,ticket_kab_n2.c_str(),sizeof(sendbuf));						//send Bob ticket_kab_n2
		sendbuf[sizeof(sendbuf)-1]='\0';
		if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)
            cout<<"\nSend error\n";
	    sendbuf[0]='\0';
//		kab_n2.clear();
  
  		numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);				//receives Kab(N2-1,N4) from Alice
		recbuf[numbytes+1]='\0';
		cout<<"\nfrom Bob:Kab(N2-1,N4):"<<recbuf;
		string bstr(recbuf);
		string str11=bstr.substr(0,8);						//Kab(N2-1)
		string str22=bstr.substr(13,bstr.length()-1);	   //Kab(N4)
		cout<<"\nparsed ebc Kab(N2-1):"<<str11;
		cout<<"\nparsed ebc:Kab(N4):"<<str22;		
        recbuf[0]='\0';
        
         //Create the pipe. 
		if (pipe (mypipe))
	    {
	      fprintf (stderr, "\nPipe failed.");
	      return EXIT_FAILURE;
	    }
        
       //open another connection to Bob
         pid = fork();
        if (pid < (pid_t) 0){
     	     char temp[100]="ERROR on fork";
             error(temp);
        }
         if (pid == (pid_t) 0)  {
            close(sockfd);
            close (mypipe[0]);
            cout<<"\nTrudy starts another process..";
         	newsoc(port_num2,mypipe[1],str22);								//pass port number to connect Bob,Kab(N4)
         	exit(0);
		 }
		 else{
		  wait(NULL);
		  close (mypipe[1]);
		  cout<<"\nread from pipe..";
		  read_from_pipe (mypipe[0]);
		  cout<<"\nfinshed reading from pipe..";
	     }
        
        //cout<<"\nrec read from child Kab(N4-1,N5):"<<rec;
        string str(rec);
		string kab_n4mi=str.substr(0,8);
		string str2=str.substr(8,str.length()-1);
		cout<<"\nparsed ebc Kab(N4-1):"<<kab_n4mi;								//Kab(N4-1)
		cout<<"\nparsed ebc other:"<<str2;
   	    cout<<"\nFound Kab(N4-1) and send:"<<kab_n4mi;
		sendbuf[0]='\0';
		strncpy(sendbuf,kab_n4mi.c_str(),sizeof(sendbuf));						//send Bob kab_n4mi
		sendbuf[sizeof(sendbuf)-1]='\0';
		if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)
	    cout<<"\nSend error\n";
	    sendbuf[0]='\0';

       while(1){											/*communicate with client. Terminated when force closed*/

        numbytes=recv(sockfd,recbuf,SOCBUFSIZE,0);
        recbuf[numbytes+1]='\0';
       	cout<<"\nClient: "<<recbuf<<"\n";
       	recbuf[0]='\0';

		cout<<"\nServer:";
       	getline(cin,sendstr);

       	strncpy(sendbuf,sendstr.c_str(),sizeof(sendbuf));
       	sendbuf[sizeof(sendbuf)-1]=0;
       	if(send(sockfd,sendbuf,strlen(sendbuf)+1,0)==1)   {
               cout<<"\nsend error\n";
               exit(1);
        	   }
        sendbuf[0]='\0';
		}
    close(sockfd);
       

       return 0;
}


