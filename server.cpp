#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

#include <cstring>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
using namespace oabe;
using namespace oabe::crypto;

#define BUF_SIZE 1024

void errorhandling(char *message);

int main(int argc, char *argv[])
{
    InitializeOpenABE();
    OpenABECryptoContext cpabe("CP-ABE");
    //    OpenPKEContext pke;
    string ct, ct2, pt1, pt2;
    cpabe.generateParams();
    cpabe.keygen("|attr1|attr2", "key0");

    //   export key to a base64 encoded string
    //    std::string key0Blob;
    //    cpabe.exportUserKey("key0", key0Blob);
    //    cout<<"key0Blob="<<key0Blob<<endl;
    //    char *key0 = (char*)key0Blob.c_str();

    // export master public params
    std::string mpk;
    cpabe.exportPublicParams(mpk);
    //    cout<<"mpk="<<endl<<mpk<<endl;
    //    cout<<"The length of mpk:"<<mpk.length()<<endl;
    //    cout<<"The size of mpk:"<<mpk.size()<<endl;
    char *mpkparam = (char *)mpk.c_str();
    //    cout<<"The size of mpk.c_str():"<<mpk.size()<<endl;

    //    pke.keygen("user0");

    /*
     OpenABECryptoContext kpabe("KP-ABE");
     string ct,ct2, pt1, pt2;
     kpabe.generateParams();
     kpabe.keygen("attr1 and attr2", "key0");
*/
    int serv_socket;
    int clnt_socket;
    int id = 1, str_len;
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;

    char message[BUF_SIZE];

    if (argc != 2)
    {
        cout << "Usage : " << argv[0] << " <port> " << endl;
        exit(0);
    }

    serv_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_socket == -1)
    {
        errorhandling("socket() error!");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); //自动获取计算机的IP地址
    serv_addr.sin_port = htons(atoi(argv[1])); //atoi (表示ascii to integer)是把字符串转换成整型数的一个函数

    if (bind(serv_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        errorhandling("bind() error");
    }
    if (listen(serv_socket, 5) == -1)
    {
        errorhandling("listen() error");
    }
    clnt_addr_size = sizeof(clnt_addr);

    //处理五次连接请求
    for (int i = 0; i < 5; ++i)
    {
        clnt_socket = accept(serv_socket, (sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_socket == -1)
            errorhandling("accept error");
        else
        {
            cout << "Conneted client " << id << endl;
        }

        // server send key to client
        //        write(clnt_socket, key0,strlen(key0) );

        //server send master public param to client
        write(clnt_socket, mpkparam, strlen(mpkparam));
        //      cout<<"mpkparam="<<endl<<mpkparam<<endl;
        //      cout<<"strlen(mpkparam)="<<strlen(mpkparam)<<endl;
        //      cout<<"The size of  strlen(mpkparam)="<<sizeof(mpkparam)<<endl;

        while ((str_len = read(clnt_socket, message, BUF_SIZE)) != 0)
        {
            cout << "client message length:" << str_len << endl;
            cout << "Message from client:" << endl
                 << message << endl;
            // printf("Message from client :\n  %s", message);
            //           write(clnt_socket, message, str_len);

            ct = message;
            //        cpabe.encrypt("attr1 and attr2", "alice", ct2);
            //          kpabe.encrypt("|attr1|attr2", "alice", ct2);
            //          pke.encrypt("user0", "alice", ct2);

            //        cout<<"ct2:"<<endl<<ct2<<endl;
            //        cout<<"ct?=ct2:"<<(ct==ct2)<<endl;
            cpabe.decrypt("key0", ct, pt2);
            //          kpabe.decrypt("key0", ct, pt2);
            //          pke.decrypt("user0", ct, pt2);

            //        cout<<endl<<"The ciphertext:"<<endl<<ct<<endl;
            //        pt1 = message;
            //        cout<<"The plaintext is:"<<pt1<<endl;
            //        cpabe.encrypt("attr1 and attr2", pt1, ct);
            //        cout<<"The ciphertext is:"<<ct<<endl;
            //        bool result = cpabe.decrypt("key0", ct, pt2);
            //        assert(result && pt1 == pt2);

            cout << "decrypt message: " << pt2 << endl;

            memset(message, 0, sizeof(message));
        }
        id++;

        close(clnt_socket);
    }
    /*
    clnt_socket = accept(serv_socket, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(clnt_socket == -1){
        errorhandling("accept error");
        }
    write(clnt_socket, message, sizeof(message));
    */

    close(serv_socket);

    ShutdownOpenABE();
    return 0;
}

void errorhandling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
