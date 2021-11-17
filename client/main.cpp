#include "client.h"

int main(int argc, char** argv)
{
	if (!init())
	{
		return 0;
	}
	client* m_client = new client();
	m_client->start();

	WSACleanup();

	return 0;
}

bool init()
{
	WORD winsock_version = MAKEWORD(2, 2);
	WSADATA wsa_data;
	if (WSAStartup(winsock_version, &wsa_data) != 0) {
		cout << "[!] failed to init socket dll!" << endl;
		return false;
	}
	return true;
}