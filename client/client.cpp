#include <iostream>
#include <string>
#include <winsock2.h>  
#include <thread>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define SERVER_PORT 54321
#define CLIENT_PORT 8888
#define SERVER_IP "192.168.124.212"
#define CLIENT_IP "192.168.124.1"
#define  BUFFER_SIZE 1024

static void proc_output(SOCKET client_socket);

void proc_output(SOCKET client_socket)
{
    while (true) {
        char recv_data[BUFFER_SIZE] = {};
        int ret = recv(client_socket, recv_data, BUFFER_SIZE, 0);
        if (ret < 0) {
            cout << "[!] failed to receive data!" << endl;
            break;
        }

        cout << recv_data;
    }
}

int main() {
    WORD winsock_version = MAKEWORD(2, 2);
    WSADATA wsa_data;
    if (WSAStartup(winsock_version, &wsa_data) != 0) {
        cout << "[!] failed to init socket dll!" << endl;
        return 0;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        cout << "[!] failed to create server socket!" << endl;
        return 0;
    }

    sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.S_un.S_addr = inet_addr(CLIENT_IP);
    if (bind(client_socket, (LPSOCKADDR)&client_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cout << "[!] failed to bind port!" << endl;
        return 0;
    }

    cout << "[*] bind to address:" << CLIENT_IP << ": " << CLIENT_PORT << " successfully!" << endl;
    if (connect(client_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cout << "[!] failed to connect server!" << endl;
        return 0;
    }

    cout << "[*] connect to address:" << SERVER_IP << ": " << SERVER_PORT << " successfully!" << endl;
    thread output_thread = thread(proc_output, client_socket);
    output_thread.detach();
    if (send(client_socket, "shell_start", strlen("shell_start"), 0) < 0) {
        cout << "[!] failed to send data!" << endl;
    }    
    cout << "[*] shell start" << endl;
    while (true) {
        string data;
        cin >> data;
        data += "\r\n";
        if (send(client_socket, data.c_str(), data.size(), 0) < 0) {
            cout << "[!] failed to send data!" << endl;
            break;
        }
    }

    closesocket(client_socket);
    WSACleanup();

    return 0;
}