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
    string ct, pt1, pt2;
    //    cpabe.generateParams();
    //    cpabe.keygen("|attr1|attr2", "key0");

    //    std::string key0Blob;
    //    cpabe.exportUserKey("key0", key0Blob);
    //    cout<<"key0Blob="<<key0Blob<<endl;
    //    char key0[BUF_SIZE];

    std::string mpk;
    char mpkparam[BUF_SIZE];

    //    OpenPKEContext pke;
    //    pke.keygen("user0");

    /*
    OpenABECryptoContext kpabe("KP-ABE");
    string ct, pt1, pt2;
    kpabe.generateParams();
    kpabe.keygen("attr1 and attr2", "key0");
*/
    int sock;
    struct sockaddr_in serv_addr;
    char message[BUF_SIZE];
    int str_len = 0, idx = 0, read_len = 0;

    if (argc != 3)
    {
        cout << "Usage : " << argv[0] << "<IP> <port> " << endl;
        exit(0);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        errorhandling("socket() error;");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]); //转换网络主机地址
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        errorhandling("connect error!");
    }
    else
    {
        cout << "connected....." << endl;
    }

    //receive the key from server
    //      read(sock, key0, BUF_SIZE - 1);
    //      cout<<"The key from server is:"<<key0<<endl;
    //      key0Blob = key0;
    //      cpabe.importUserKey("key0", key0Blob);

    //receive the master public param from server
    read(sock, mpkparam, 663);
    //      cout<<"The master public param from server is:"<<endl<<mpkparam<<endl;
    mpk = mpkparam;
    //      cout<<"mpk="<<endl<<mpk<<endl;
    cpabe.importPublicParams(mpk);

    while (1)
    {
        //        cout << "Input Q/q to exit." << endl;
        fgets(message, BUF_SIZE, stdin);

        pt1 = message;
        cout << "The plaintext is:" << pt1 << endl;
        cpabe.encrypt("attr1 and attr2", pt1, ct);

        //        pke.encrypt("user0", pt1, ct);
        //      kpabe.encrypt("|attr1|attr2", pt1, ct);

        cout << "The Ciphertext is:" << endl
             << ct << endl;

        if (!strcmp(message, "q\n") || !strcmp(message, "Q\n"))
            break;

        char *message2 = (char *)ct.c_str();
        //        cout<<message2<<endl;
        write(sock, message2, strlen(message2));
        //        write(sock, message, strlen(message));

        //        str_len = read(sock, message2, BUF_SIZE - 1);
        //        message2[str_len] = '\0';

        //       printf("Message from server : %s", message);
    }

    close(sock);

    /*
    while(read_len =read(sock, &message[idx++], 1)){
        if(read_len == -1){
            errorhandling("read error");
        }
        str_len += read_len;
    }
    cout << "message from server: " << message <<endl;
    cout << "read function call " << str_len << "times" <<endl;
    */
//    close(sock);

    ShutdownOpenABE();
    return 0;
}

void errorhandling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
