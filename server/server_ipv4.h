#pragma once
#include "server_base.h"

class server_ipv4 :public server_base
{
public:
	virtual bool set_laddr(std::string laddr);
	virtual bool set_raddr(std::string raddr);

private:
	virtual bool connect_to_target();
	virtual void build_packet_template();
	virtual void build_addr_template();
	virtual void print_ip_info(PVOID ip_header);
	virtual bool recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf);
	virtual void wait_for_connect();
	virtual void send_connect_reponse(PVOID packet, UINT recv_len);								// ģ��tcp��������
	virtual void set_packet_template(PVOID packet, UINT recv_len);								// ��ʽ����׼���Ͱ�
	virtual void send_response_packet(PVOID packet, UINT recv_len);								// ����ȷ�հ�
	virtual void send_data_packet(const char* payload_buf, int payload_len = 0);				// �������ݰ�
};

