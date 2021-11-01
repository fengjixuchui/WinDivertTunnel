#include "main.h"

static uint8 key[16] = {
	0x0f,0x15,0x71,0xc9,
	0x47,0xd9,0xe8,0x59,
	0x0c,0xb7,0xad,0xd6,
	0xaf,0x7f,0x67,0x98
};

int main(int argc, char** argv)
{
	server_base* port_reuse;

	port_reuse = new server_ipv6();
	//if (argc == 1)
	//{
		//port_reuse->show_help();
		//return 0;
	//}
	for (int i = 1; i < argc; ++i)
	{
		if (!_stricmp(argv[i], "-raddr") )
		{
			if (!port_reuse->set_raddr(argv[i + 1])) {
				cout << "[!] address invalid" << endl;
				return 0;
			}
		}		
		if (!_stricmp(argv[i], "-laddr"))
		{
			if (!port_reuse->set_laddr(argv[i + 1])) {
				cout << "[!] address invalid" << endl;
				return 0;
			}
		}
		else if (!_stricmp(argv[i], "-lport"))
		{
			port_reuse->set_lport(atoi(argv[i + 1]));
		}
		else if (!_stricmp(argv[i], "-rport"))
		{
			port_reuse->set_rport(atoi(argv[i + 1]));
		}
		else if (!_stricmp(argv[i], "-e"))
		{
			port_reuse->set_use_encrypt(true);
		}
		else if (!_stricmp(argv[i], "-h"))
		{
			port_reuse->show_help();
			return 0;
		}
	}
	port_reuse->start();
	return 0;
}
