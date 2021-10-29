#include <iostream>
#include <sstream>
#include <string>
#include <ws2tcpip.h>
#include <winsock2.h>  
#include <thread>
#include <iomanip>
#include <fstream>
#include "aes.h"

#define BUFFER_SIZE 2000	
#define FILE_SIZE	1024	// better less than 1460(MSS)
#define SHELL_START "shell_start"

using namespace std;

SOCKET g_client_socket;
SOCKET g_listen_socket;
AES_CONTEXT g_aes_ctx;
bool g_ondownload;
string g_srcfile, g_dstfile;
static void proc_output();
void file_download();
void file_upload();
bool g_use_encrypt = false;

void send_data(const char* data_buf, size_t data_len = 0); 
size_t recv_data(shared_ptr<char[]>& buf_data);
void encrypt_payload(const char* original_buf, char* encrypt_buf, UINT buf_len);
void decrypt_payload(shared_ptr<char[]> buf_data, UINT buf_len);
bool check_download(string download_str);
bool check_upload(string upload_str);
void refresh();
void progress(int cur, int max);
void show_help();
