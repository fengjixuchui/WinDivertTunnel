#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>

#include <winsock2.h>  

#pragma comment(lib, "ws2_32.lib")  

#define PORT 8888
#define  BUFFER_SIZE 256

static const std::string kExitFlag = "-1";


int main() {
    WORD winsock_version = MAKEWORD(2, 2);
    WSADATA wsa_data;
    if (WSAStartup(winsock_version, &wsa_data) != 0) {
        std::cout << "Failed to init socket dll!" << std::endl;
        return 1;
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        std::cout << "Failed to create server socket!" << std::endl;
        return 2;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.S_un.S_addr = INADDR_ANY;

    if (bind(server_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cout << "Failed to bind port!" << std::endl;
        return 3;
    }

    if (listen(server_socket, 10)) {
        std::cout << "Failed to listen!" << std::endl;
        return 4;
    }

    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    std::cout << "Wait for connecting..." << std::endl;

    SOCKET client_socket = accept(server_socket, (SOCKADDR*)&client_addr, &client_addr_len);
    if (client_socket == INVALID_SOCKET) {
        std::cout << "Failed to accept!" << std::endl;
        return 5;
    }

    std::cout << "Succeed to receive a connection: " << inet_ntoa(client_addr.sin_addr) << std::endl;

    char recv_buf[BUFFER_SIZE] = {};
    while (true) {
        memset(recv_buf, BUFFER_SIZE, 0);
        int ret = recv(client_socket, recv_buf, BUFFER_SIZE, 0);
        if (ret < 0) {
            std::cout << "Failed to receive data!" << std::endl;
            break;
        }

        std::cout << "Receive from Client: " << recv_buf << std::endl;
        if (kExitFlag == recv_buf) {
            std::cout << "Exit!" << std::endl;
            break;
        }

        // 发送数据给客户端。
        char send_data[] = "Hello, Tcp Client!\n";
        send(client_socket, send_data, strlen(send_data), 0);
    }

    // 关闭套接字。
    closesocket(client_socket);
    closesocket(server_socket);

    // 释放dll。
    WSACleanup();

    return 0;
}