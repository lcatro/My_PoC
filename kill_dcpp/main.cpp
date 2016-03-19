
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <string>

#include <winsock.h>

#pragma comment (lib,"ws2_32")

using std::vector;
using std::string;

#define SERVER_IP  "172.16.6.108"
#define RECV_LOOPS 6

typedef vector<string> list;

list userlist;

static int reservedchar(unsigned char c)
{
    return((c == 0) || (c == 5) || (c == 124) || (c == 96) || (c == 126) || (c == 36));
}

static char *dcmakekey(char *lock)
{
    int i, len, offset;
    char *buf, *key;
    char save;
    
    /* Step 1: Compute key */
    buf =(char*) malloc(strlen(lock));
    save = 5;
    len = 0;
    for(i = 0; lock[i]; i++) {
        buf[i] = lock[i] ^ save;
        buf[i] = ((buf[i] & 0x0F) << 4) | ((buf[i] & 0xF0) >> 4);
        save = lock[i];
        if((i != 0) && reservedchar(buf[i]))
            len += 10;
        else
            len++;
    }
    buf[0] ^= buf[i - 1];
    if(reservedchar(buf[0]))
        len += 10;
    else
        len++;
    
    /* Step 2: Quote reserved characters */
    key =(char*) malloc(len + 1);
    offset = 0;
    for(i = 0; lock[i] != 0; i++) {
        if(reservedchar(buf[i]))
            offset += sprintf(key + offset, "/%%DCN%03i%%/", buf[i]);
        else
            key[offset++] = buf[i];
    }
    key[offset] = 0;
    free(buf);
    
    /* Observe: The caller will have to free the memory */
    return(key);
}

static void get_user(char* recv_buffer) {
    char* point=strchr(recv_buffer,'|');
    while (true) {
        if (NULL==point)
            break;
        char command[8]={0};
        memcpy(command,&point[1],7);
        if (!strcmp("$MyINFO",command)) {
            point+=14;
            char* space=strchr(point,' ');
            char username_[32]={0};
            memcpy(username_,point,space-point);
            userlist.push_back(username_);
        } else
            point+=1;
        point=strchr(point,'|');
    }
}

void main(void) {
    WSADATA init={0};
    WSAStartup(1,&init);

    SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    sockaddr_in remote;
    remote.sin_addr.S_un.S_addr=inet_addr(SERVER_IP);
    remote.sin_family=AF_INET;
    remote.sin_port=htons(411);
    if (SOCKET_ERROR!=connect(sock,(const sockaddr*)&remote,sizeof(remote))) {
        char* username="wanan";
        char* password="19950105";
/*        char username[0x10]={0};
        char password[0x10]={0};

        printf("username:");
        scanf("%s",username);
        printf("password:");
        scanf("%s",password);
*/
        char recv_buffer[1024*10]={0};
        recv(sock,recv_buffer,1024,0);
//        printf("%s\n",recv_buffer);

        char* login_supports="$Supports UserCommand NoGetINFO NoHello UserIP2 TTHSearch ZPipe0 TLS |";
        char lock_key[0x47]={0};
        memcpy(lock_key,&recv_buffer[6],0x3C);
        char  login_key[128]={0};
        char* calcu_key=dcmakekey(lock_key);
        memcpy(login_key,"$Key ",5);
        memcpy(&login_key[5],calcu_key,strlen(calcu_key));
        login_key[strlen(login_key)]='|';
        string login_name("$ValidateNick ");
        login_name+=username;
        login_name+="|";
        char  login_pack[1024]={0};
        memcpy(login_pack,login_supports,70);
        memcpy(&login_pack[70],login_key,strlen(login_key));
        memcpy(&login_pack[70+strlen(login_key)],login_name.c_str(),login_name.length());
        send(sock,login_pack,strlen(login_pack),0);

        recv(sock,recv_buffer,1024*2,0);
        printf("%s\n",recv_buffer);
        memset(recv_buffer,0,1024*2);

        string login_pass("$MyPass ");
        login_pass+=password;
        login_pass+="|";
        send(sock,login_pass.c_str(),login_pass.size(),0);

        recv(sock,recv_buffer,1024,0);
        printf("%s\n",recv_buffer);
        if (NULL==strstr(recv_buffer,"$Hello")) {
            printf("Password Error\n");
            closesocket(sock);
            return;
        }
        memset(recv_buffer,0,1024);

        char  report[128]={0};
        char* local_version="$Version 1,0091|";
        char* get_list="$GetNickList|";
        char* info_1="$MyINFO $ALL ";
        char* info_2=" <DC++ V:1.1 For HR-NA ,M:A,H:0/1/0,S:3>$ $100.$$37095116006$|";
        memcpy(report,local_version,strlen(local_version));
        strcat(report,get_list);
        strcat(report,info_1);
        strcat(report,username);
        strcat(report,info_2);

        send(sock,report,strlen(report),0);

        Sleep(100);

        recv(sock,recv_buffer,1024,0);
        printf("%s\n",recv_buffer);  //  get network information ..
        memset(recv_buffer,0,1024);

        for (int recv_index=1;recv_index<=RECV_LOOPS;++recv_index) {
            recv(sock,recv_buffer,1024*10,0);  //  get user list ..
//            printf("%s\n",recv_buffer);
            get_user(recv_buffer);
            memset(recv_buffer,0,1024*10);
        }

        printf("user number:%d\n",userlist.size());
        unsigned long user_index=1;
        for (list::iterator userlist_iterator =userlist.begin();
                            userlist_iterator!=userlist.end();
                            ++userlist_iterator) {
                                if ("paulpan"==*userlist_iterator || "ะกะกอþ"==*userlist_iterator)
                                    continue;
            string message_send("$To: ");
            message_send+=*userlist_iterator;
            message_send+=" From: ";
            message_send+=username;
            message_send+=" $<";
            message_send+=username;
            message_send+=">  |";
            printf("%d:%s\n",user_index,message_send.c_str());
            ++user_index;
            send(sock,message_send.c_str(),message_send.length(),0);
            Sleep(5000);
        }
        closesocket(sock);

        recv(sock,recv_buffer,1024,0);
        printf("%s\n",recv_buffer);  //  get network information ..
        memset(recv_buffer,0,1024);

        printf("Exit attack!\n");

  
    } else
        printf("SOCKET init ERROR!\n");


}

