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

class client
{
private:
	bool m_use_encrypt = false;
	int m_lport = 8888;
	int m_rport = 54321;
	SOCKET m_client_socket;
	SOCKET m_listen_socket;
	AES_CONTEXT m_aes_ctx;
	bool m_direct_mode;
	string m_target_address;
	bool m_ondownload;
	string m_srcfile, m_dstfile;
	bool m_use_encrypt = false;
	void file_download();
	void file_upload();
	void send_data(const char* data_buf, size_t data_len = 0);
	size_t recv_data(shared_ptr<char[]>& buf_data);
	void encrypt_payload(const char* original_buf, char* encrypt_buf, UINT buf_len);
	void decrypt_payload(shared_ptr<char[]> buf_data, UINT buf_len);
	bool check_download(string download_str);
	bool check_upload(string upload_str);
	void refresh();
	void progress(int cur, int max);
	static void show_help();
public:
	void proc_output();
	void input_handle();
	bool start();
	bool build_connect();
};