#include "client.h"
#pragma comment(lib, "ws2_32.lib")
using namespace std;
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

int main(int argc, char** argv)
{
	std::string target_address = "";
	int lport = 8888;
	int rport = 54321;
	bool direct_mode = false;
#ifndef NDEBUG
	direct_mode = true;
	// target_address = "192.168.154.129";		// IPv4
	target_address = "fd15:4ba5:5a2b:1008:501c:e55:c0b:f4bd";	// IPv6
#else
	if (argc == 1)
	{
		show_help();
		return 0;
	}
	for (int i = 1; i < argc; ++i)
	{
		if (!_stricmp(argv[i], "-c") || !_stricmp(argv[i], "--connect"))
		{
			direct_mode = true;
			target_address = argv[i + 1];
		}
		else if (!_stricmp(argv[i], "-l") || !_stricmp(argv[i], "--lport"))
		{
			lport = atoi(argv[i + 1]);
		}
		else if (!_stricmp(argv[i], "-r") || !_stricmp(argv[i], "--rport"))
		{
			rport = atoi(argv[i + 1]);
		}
		else if (!_stricmp(argv[i], "-e") || !_stricmp(argv[i], "--encrypt"))
		{
			g_use_encrypt = true;
		}
		else if (!_stricmp(argv[i], "-h") || !_stricmp(argv[i], "--help"))
		{
			show_help();
			return 0;
		}
	}
#endif

	if (g_use_encrypt) {
		aes_set_key(&g_aes_ctx, key, 128);
	}
	WORD winsock_version = MAKEWORD(2, 2);
	WSADATA wsa_data;
	if (WSAStartup(winsock_version, &wsa_data) != 0) {
		cout << "[!] failed to init socket dll!" << endl;
		return 0;
	}

	//连接ip
	char target_ip[128];
	memset(target_ip, 0, sizeof(target_ip));
	strcpy(target_ip, target_address.c_str());

	void* svraddr = nullptr;
	void* cltaddr = nullptr;
	int error = -1, svraddr_len, cltaddr_len;
	bool ret = true;
	struct sockaddr_in svraddr_4, cltaddr_4;
	struct sockaddr_in6 svraddr_6, cltaddr_6;

	if (direct_mode)
	{
		cout << "[*] on direct mode" << endl;
		//获取网络协议
		struct addrinfo* result;
		if (getaddrinfo(target_ip, NULL, NULL, &result) != 1) {
			cout << "[!] IP address error" << endl;
		}
		const struct sockaddr* sa = result->ai_addr;
		socklen_t maxlen = 128;
		switch (sa->sa_family) {
		case AF_INET://ipv4
			if ((g_client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				cout << "[!] failed to create client socket!" << endl;
				ret = false;
				break;
			}

			cout << "[*] socket created ipv4" << endl;
			svraddr_4.sin_family = AF_INET;
			svraddr_4.sin_addr.s_addr = inet_addr(target_ip);
			svraddr_4.sin_port = htons(lport);
			svraddr_len = sizeof(svraddr_4);
			svraddr = &svraddr_4;


			cltaddr_4.sin_family = AF_INET;
			cltaddr_4.sin_addr.s_addr = INADDR_ANY;
			cltaddr_4.sin_port = htons(rport);
			cltaddr_len = sizeof(cltaddr_4);
			cltaddr = &cltaddr_4;
			break;
		case AF_INET6://ipv6
			if ((g_client_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
				cout << "[!] failed to create client socket!" << endl;
				ret = false;
				break;
			}

			cout << "[*] socket created ipv6" << endl;
			memset(&svraddr_6, 0, sizeof(svraddr_6));
			svraddr_6.sin6_family = AF_INET6;
			svraddr_6.sin6_port = htons(lport);
			if (inet_pton(AF_INET6, target_ip, &svraddr_6.sin6_addr) < 0) {
				ret = false;
				break;
			}
			svraddr_len = sizeof(svraddr_6);
			svraddr = &svraddr_6;

			cltaddr_len = sizeof(cltaddr_6);
			memset(&cltaddr_6, 0, cltaddr_len);
			cltaddr_6.sin6_family = AF_INET6;
			cltaddr_6.sin6_addr = IN6ADDR_ANY_INIT;
			//if (inet_pton(AF_INET6, "::1", &cltaddr_6.sin6_addr) < 0) {
				//ret = false;
				//break;
			//}
			cltaddr_6.sin6_port = htons(rport);
			cltaddr = &cltaddr_6;
			break;

		default:
			cout << "[*] unknown IP type" << endl;
			ret = false;
		}
		freeaddrinfo(result);
		if (ret) {
			if (!bind(g_client_socket, (struct sockaddr*)cltaddr, cltaddr_len)) {
				if (connect(g_client_socket, (struct sockaddr*)svraddr, svraddr_len)) {	// If no error occurs, connect returns zero.
					cout << "[!] cannot connect the server" << endl;
					return 0;
				}
				else {
					cout << "[*] connect to address:" << target_address << ": " << rport << " successfully!" << endl;
				}
			}
			else {
				cout << "[!] bind error" << endl;
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		cout << "[*] on reverse mode" << endl;
		g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (g_listen_socket == INVALID_SOCKET) {
			cout << "[!] failed to create listen socket!" << endl;
			return 0;
		}

		if (SOCKET_ERROR == bind(g_listen_socket, (SOCKADDR*)&cltaddr, cltaddr_len)) {
			cout << "[!] failed to bind server socket!" << endl;
			return 0;
		}

		if (listen(g_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
			cout << "[!] listen failed with error:WSAGetLastError()" << endl;
			closesocket(g_listen_socket);
			return 1;
		}
		cout << "[*] waiting for incoming connections..." << endl;
		g_client_socket = accept(g_listen_socket, NULL, NULL);
		if (g_client_socket == INVALID_SOCKET) {
			cout << "[!] accept failed with error code : " << WSAGetLastError() << endl;
			return 0;
		}

		cout << "[*] connection accepted" << endl;
	}

	/*
	if (direct_mode)
	{
		g_client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (g_client_socket == INVALID_SOCKET) {
			cout << "[!] failed to create client socket!" << endl;
			return 0;
		}

		//if (bind(g_client_socket, addr->ai_addr, addr->ai_addrlen) == SOCKET_ERROR) {
		if (bind(g_client_socket, (sockaddr*)& client_addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
			cout << "[!] failed to bind port!" << endl;
			return 0;
		}
		//if (connect(g_client_socket, addr2->ai_addr, addr2->ai_addrlen) == SOCKET_ERROR) {
		if (connect(g_client_socket, (sockaddr*)&server_addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
			cout << "[!] failed to connect server!" << endl;
			return 0;
		}

		//freeaddrinfo(addr);
		//freeaddrinfo(addr2);
		cout << "[*] connect to address:" << target_address << ": " << rport << " successfully!" << endl;
	}
	else
	{
		g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (g_listen_socket == INVALID_SOCKET) {
			cout << "[!] failed to create listen socket!" << endl;
			return 0;
		}

		if (SOCKET_ERROR == bind(g_listen_socket, (SOCKADDR*)&client_addr, sizeof(client_addr))) {
			cout << "[!] failed to bind server socket!" << endl;
			return 0;
		}

		if (listen(g_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
			cout << "[!] listen failed with error:WSAGetLastError()" << endl;
			closesocket(g_listen_socket);
			return 1;
		}
		cout << "[*] waiting for incoming connections..." << endl;
		g_client_socket = accept(g_listen_socket, NULL, NULL);
		if (g_client_socket == INVALID_SOCKET) {
			cout << "[!] accept failed with error code : " << WSAGetLastError() << endl;
			return 0;
		}

		cout << "[*] connection accepted" << endl;
	}*/
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

void show_help()
{
	cout << endl << "Usage: client [-c address][-l port][-r port][-e]" << endl << endl;
	cout << "Options:" << endl;
	cout << "\t-c address	connect to host Remote host address.(only direct mode)" << endl;
	cout << "\t-l port		the port on local side.(default 8888)" << endl;
	cout << "\t-r port		the port on remote host.(default 54321)" << endl;
	cout << "\t-e			use AES encrypt." << endl;
	cout << "\t-h			show this help info" << endl;
}

void encrypt_payload(const char* original_buf, char* encrypt_buf, UINT buf_len)
{
	if (!encrypt_buf)
		return;
	memcpy(encrypt_buf, original_buf, buf_len);
	if (!g_use_encrypt)
		return;
	char* tmp = encrypt_buf;
	for (int i = 0; i != buf_len; i += 16) {
		aes_encrypt(&g_aes_ctx, (uint8*)tmp);
		tmp += 16;
	}
}

void decrypt_payload(shared_ptr<char[]> buf_data, UINT buf_len)
{
	if (!g_use_encrypt)
		return;
	auto tmp = buf_data.get();
	for (int i = 0; i != buf_len; i += 16) {
		aes_decrypt(&g_aes_ctx, (uint8*)tmp);
		tmp += 16;
	}
}

bool check_download(string download_str)
{
	string word;
	if (download_str.empty()) {
		return false;
	}

	stringstream str_stream(download_str);
	str_stream >> word;
	str_stream >> g_srcfile;
	str_stream >> g_dstfile;
	if (g_srcfile.empty() || g_dstfile.empty()) {
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
			// cout << "[*] recv file data " << len << " bytes" << endl;
			fwrite(data_buf.get() + 4, len, 1, fp);
			// progress(cur_num, max_num);
			send_data("ok");
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
			progress(cur_num++, max_num);
		}
		if (real_read != need_read) {
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
		if (buf_data == NULL)
		{
			cout << "[!] failed to allocate buffer!" << endl;
		}
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
