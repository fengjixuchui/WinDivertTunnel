#include "client.h"

#pragma comment(lib, "ws2_32.lib")

static uint8 key[16] = {
	0x0f,0x15,0x71,0xc9,
	0x47,0xd9,0xe8,0x59,
	0x0c,0xb7,0xad,0xd6,
	0xaf,0x7f,0x67,0x98
};

void proc_output()
{
	shared_ptr<char[]> data_buf;
	while (true) {
		recv_data(data_buf);
		if (!strcmp(data_buf.get(), "download_start")) {
			file_download();
			refresh();
		}
		else if (!strcmp(data_buf.get(), "file_no_exist")) {
			cout << "[*] target file no exist" << endl;
			refresh();
		}
		else if (!strcmp(data_buf.get(), "upload_start")) {
			file_upload();
			refresh();
		}
		else {
			cout << data_buf.get();
		}
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

	g_client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (g_client_socket == INVALID_SOCKET) {
		cout << "[!] failed to create server socket!" << endl;
		return 0;
	}

	sockaddr_in client_addr;
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(CLIENT_PORT);
	client_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	if (bind(g_client_socket, (LPSOCKADDR)&client_addr, sizeof(server_addr)) == SOCKET_ERROR) {
		cout << "[!] failed to bind port!" << endl;
		return 0;
	}

	if (connect(g_client_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
		cout << "[!] failed to connect server!" << endl;
		return 0;
	}

	cout << "[*] connect to address:" << SERVER_IP << ": " << SERVER_PORT << " successfully!" << endl;
	thread output_thread = thread(proc_output);
	output_thread.detach();

	send_data(SHELL_START);
	string input;
	while (true) {
		getline(cin, input);
		if (input.empty()) {
			continue;
		}
		if (input.find("download") != string::npos) {
			if (!check_download(input)) {
				cout << "[!] usage: download [src_file] [dst_file]" << endl;
				input = "\r\n";
			}
		}
		else if (input.find("upload") != string::npos) {
			if (!check_upload(input)) {
				cout << "[!] usage: upload [src_file] [dst_file]" << endl;
				input = "\r\n";
			}
		}
		else {
			input += "\r\n";
		}

		send_data(input.c_str());
	}

	closesocket(g_client_socket);
	WSACleanup();

	return 0;
}

void encrypt_payload(const char* original_buf, char* encrypt_buf, UINT buf_len)
{
	if (!encrypt_buf)
		return;
	memcpy(encrypt_buf, original_buf, buf_len);
	char* tmp = encrypt_buf;
	for (int i = 0; i != buf_len; i += 16) {
		aes_encrypt(&g_aes_ctx, (uint8*)tmp);
		tmp += 16;
	}
}

void decrypt_payload(shared_ptr<char[]> buf_data, UINT buf_len)
{
	auto tmp = buf_data.get();
	for (int i = 0; i != buf_len; i += 16) {
		aes_decrypt(&g_aes_ctx, (uint8*)tmp);
		tmp += 16;
	}
}

bool check_download(string download_str)
{
	string word;
	if (download_str.empty()){
		return false;
	}

	stringstream str_stream(download_str);
	str_stream >> word;
	str_stream >> g_srcfile;
	str_stream >> g_dstfile;
	if (g_srcfile.empty() || g_dstfile.empty()){
		return false;
	}
	cout << "[*] download file " << g_srcfile << " to " << g_dstfile << endl;
	return true;
}

bool check_upload(string upload_str)
{
	string word;
	if (upload_str.empty()) {
		return false;
	}

	stringstream str_stream(upload_str);
	str_stream >> word;
	str_stream >> g_srcfile;
	str_stream >> g_dstfile;
	if (g_srcfile.empty() || g_dstfile.empty()) {
		return false;
	}
	if (auto fp = fopen(g_srcfile.c_str(), "r")) {
		fclose(fp);
		cout << "[*] upload file " << g_srcfile << " to " << g_dstfile << endl;
	}
	else {
		cout << "[!] src file " << g_srcfile << " not exist!" << endl;
		return false;
	}
	return true;
}

void file_download()
{
	cout << "[*] start download" << endl;
	FILE* fp = fopen(g_dstfile.c_str(), "wb");
	if (!fp) {
		return;
	}
	while (true)
	{
		shared_ptr<char[]> data_buf;
		recv_data(data_buf);
		if (!strcmp(data_buf.get(), "download_finish")) {
			cout << "[*] finish download" << endl;
			fclose(fp);
			break;
		}
		else {
			size_t len = *(size_t*)data_buf.get();
			cout << "[*] recv file data " << len << " bytes" << endl;
			fwrite(data_buf.get() + 4, len, 1, fp);
			//send_data("ok");
		}
	}
}

void file_upload()
{
	cout << "[*] start upload" << endl;
	ifstream fin(g_srcfile, ios::binary);	
	if (!fin.is_open()) {
		cout << "[!] failed to open file (" << GetLastError() << ")!" << endl;
		return;
	}
	fin.seekg(0, ios::end);
	auto file_size = fin.tellg();
	fin.seekg(0, ios::beg);
	int cur_num = 0;
	size_t need_read = FILE_SIZE - 10;
	auto max_num = file_size / need_read;

	while (true) {
		char file_buf[FILE_SIZE];
		fin.read(file_buf + 4, need_read);
		auto real_read = fin.gcount();
		*(size_t*)file_buf = real_read;
		send_data(file_buf, real_read);
		shared_ptr<char[]> data_buf;
		recv_data(data_buf);
		if (!strcmp(data_buf.get(), "recv_ok")) {
			progress(cur_num, max_num);
			cur_num++;
		}
		if (real_read != need_read){
			fin.close();
			cout << endl << "[*] upload finish" << endl;
			send_data("upload_finish");
			return;
		}
	}
}

void refresh()
{
	send_data("\r\n");
}

void send_data(const char* buf_data, size_t buf_len/* = 0*/)
{
	if (!buf_len) {
		buf_len = strlen(buf_data);
	}
	buf_len = (buf_len / 16 + 1) * 16;
	shared_ptr<char[]> crypt_data(new char[buf_len]);
	encrypt_payload(buf_data, crypt_data.get(), buf_len);
	if (send(g_client_socket, crypt_data.get(), buf_len, 0) < 0) {
		cout << "[!] failed to send data(" << GetLastError() << ")!" << endl;
	}
}

size_t recv_data(shared_ptr<char[]>& buf_data)
{
	size_t buf_len = 0;
	char recv_data[BUFFER_SIZE]{};
	buf_len = recv(g_client_socket, recv_data, BUFFER_SIZE, 0);
	if (buf_len < 0) {
		cout << "[!] failed to receive data (" << GetLastError() << ")!" << endl;
	}
	else {
		buf_data = shared_ptr<char[]>(new char[buf_len] {});
		memcpy(buf_data.get(), recv_data, buf_len);
		decrypt_payload(buf_data, buf_len);
	}
	return buf_len;
}

void progress(int cur, int max)
{
	int percent = cur * 100 / max;
	cout << "progress:[" << setfill('#') << setw(percent + 1) << "]" << percent << "%\r";
}
