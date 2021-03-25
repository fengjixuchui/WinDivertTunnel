#ifndef uint8
#define uint8 unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct _AES_CONTEXT {
	int nr;
	uint32 erk[64];
	uint32 drk[64];
}AES_CONTEXT, * PAES_CONTEXT;

int aes_set_key(PAES_CONTEXT ctx, uint8* key, int nbits);
void aes_encrypt(PAES_CONTEXT ctx, uint8 data[16]);
void aes_decrypt(PAES_CONTEXT ctx, uint8 data[16]);
