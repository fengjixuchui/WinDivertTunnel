#include "server_ipv6.h"

void server_ipv6::send_response_packet(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
	UINT payload_len;
	WinDivertHelperParsePacket(packet, recv_len, NULL , &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		&payload_len, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip6_header->DstAddr, ip6_header->SrcAddr);
	UINT16 ip_length = WinDivertHelperNtohs(ip6_header->Length) - payload_len;
	ip6_header->Length = WinDivertHelperHtons(ip_length);
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

void server_ipv6::set_packet_template(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
	UINT payload_len;

	WinDivertHelperParsePacket(packet, recv_len, NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		&payload_len, NULL, NULL);
	m_template_packet_len = recv_len - payload_len;
	m_packet_template = shared_ptr<char[]>(new char[m_template_packet_len] {});
	if (m_packet_template == NULL) {
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return;
	}
	memcpy(m_packet_template.get(), packet, m_template_packet_len);
	WinDivertHelperParsePacket(m_packet_template.get(), recv_len, NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip6_header->DstAddr, ip6_header->SrcAddr);
	UINT16 ip_length = WinDivertHelperNtohs(ip6_header->Length) - payload_len;
	ip6_header->Length = WinDivertHelperHtons(ip_length);
	tcp_header->Psh = 0;
	tcp_header->Ack = 0;
	tcp_header->Syn = 0;
	UINT32 original_seq = WinDivertHelperNtohl(tcp_header->SeqNum) + payload_len;
	tcp_header->SeqNum = tcp_header->AckNum;
	tcp_header->AckNum = WinDivertHelperHtonl(original_seq);

	WinDivertHelperCalcChecksums(packet, recv_len, NULL, 0);
}

void server_ipv6::send_data_packet(const char* payload_buf, int payload_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
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

	WinDivertHelperParsePacket(reponse_packet.get(), packet_len, NULL, &ip6_header, 
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	// rebuild ip header
	UINT16 ip_length = WinDivertHelperNtohs(ip6_header->Length) + send_payload_len;
	ip6_header->Length = WinDivertHelperHtons(ip_length);

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

void server_ipv6::send_connect_reponse(PVOID packet, UINT recv_len)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
	WinDivertHelperParsePacket(packet, recv_len, NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);

	swap(tcp_header->DstPort, tcp_header->SrcPort);
	swap(ip6_header->DstAddr, ip6_header->SrcAddr);
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

void server_ipv6::print_ip_info(PVOID ip6_header)
{
	char dst_addr[64];
	char src_addr[64];
	if (WinDivertHelperFormatIPv6Address(((PWINDIVERT_IPV6HDR)ip6_header)->DstAddr, dst_addr, 64) &&
		WinDivertHelperFormatIPv6Address(((PWINDIVERT_IPV6HDR)ip6_header)->SrcAddr, src_addr, 64)) {
		cout << "[*] dst addr:" << dst_addr << "; src addr:" << src_addr << endl;
	}
	else {
		cout << "[!] prase address error!" << endl;
	}
}


bool server_ipv6::recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf)
{
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
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
	WinDivertHelperParsePacket(packet_buf, recv_len, NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, payload_buf,
		payload_len, NULL, NULL);
	if (ip6_header)
	{
		print_ip_info(ip6_header);
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

void server_ipv6::wait_for_connect()
{
	UINT recv_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;

	auto packet = shared_ptr<char[]>(new char[WINDIVERT_MTU_MAX]());
	cout << "[*] waiting for connect..." << endl;

	while (TRUE)
	{
		if (!WinDivertRecv(m_divert_handle, packet.get(), WINDIVERT_MTU_MAX, &recv_len, &addr))
		{
			continue;
		}

		WinDivertHelperParsePacket(packet.get(), recv_len, NULL, &ip6_header,
			NULL, NULL, NULL, &tcp_header, NULL, NULL,
			NULL, NULL, NULL);
		if (ip6_header)
		{
			print_ip_info(ip6_header);
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

bool server_ipv6::connect_to_target()
{
	build_packet_template();
	build_addr_template();

	// 1.send SYN apcket (handshake 1)
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
	int packet_len = m_template_packet_len + 12;		// options 12 bytes
	auto syn_packet = unique_ptr<char[]>(new char[packet_len]());
	if (!syn_packet)
	{
		cout << "[!] failed to allocate buffer (" << GetLastError() << ")!" << endl;
		return false;
	}
	memcpy(syn_packet.get(), m_packet_template.get(), m_template_packet_len);
	WinDivertHelperParsePacket(syn_packet.get(), m_template_packet_len, NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);
	tcp_header->HdrLength = 8;
	tcp_header->Syn = 1;
	ip6_header->Length = WinDivertHelperHtons(52);
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

		WinDivertHelperParsePacket(syn_ack_packet.get(), recv_len, NULL, &ip6_header,
			NULL, NULL, NULL, &tcp_header, NULL, NULL,
			NULL, NULL, NULL);
		if (ip6_header)
		{
			print_ip_info(ip6_header);
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
	WinDivertHelperParsePacket(ack_packet.get(), m_template_packet_len, NULL, &ip6_header,
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

void server_ipv6::build_packet_template()
{
	m_template_packet_len = sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR);
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
	} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;
	*/
	WINDIVERT_IPV6HDR iphdr{ 0 };





	/****************************
	* TODO!!!!!!
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
	iphdr.DstAddr = *(PUINT32)m_raddr;
	*********************************/






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

	memcpy(m_packet_template.get(), &iphdr, sizeof(WINDIVERT_IPV6HDR));
	memcpy(m_packet_template.get() + sizeof(WINDIVERT_IPV6HDR), &tcphdr, sizeof(WINDIVERT_TCPHDR));
	WinDivertHelperCalcChecksums(m_packet_template.get(), m_template_packet_len, NULL, 0);
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_IPV6HDR ip6_header;
	WinDivertHelperParsePacket(m_packet_template.get(), m_template_packet_len,  NULL, &ip6_header,
		NULL, NULL, NULL, &tcp_header, NULL, NULL,
		NULL, NULL, NULL);
}

void server_ipv6::build_addr_template()
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
	m_addr_template->IPv6 = 1;
	LARGE_INTEGER ticks;
	QueryPerformanceCounter(&ticks);
	m_addr_template->Timestamp = ticks.QuadPart;
}


bool server_ipv6::set_laddr(std::string laddr)
{
	return 1 != inet_pton(AF_INET6, laddr.c_str(), m_laddr);
}

bool server_ipv6::set_raddr(std::string raddr)
{
	return 1 != inet_pton(AF_INET6, raddr.c_str(), m_raddr);
}