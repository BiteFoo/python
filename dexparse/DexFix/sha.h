#ifndef MERAK_SHA_SHA1_H_
#define MERAK_SHA_SHA1_H_

#include <string.h>

namespace Merak {
namespace sha {

#define SHA_ROTATE(X,n) (((X) << (n)) | ((X) >> (32-(n))))
struct SHA_CTX;
void SHA1_Transform(SHA_CTX *ctx);
void SHA1_Init(SHA_CTX *ctx);
void SHA1_Update(SHA_CTX *ctx, void* data, int len);
void SHA1_Final(unsigned char digest[20], SHA_CTX *ctx);

// implementations
struct SHA_CTX {
	unsigned int state[5];
	unsigned int count[2];
	unsigned int buffer[80];
	int lenBuf;
};

void SHA1_Init(SHA_CTX *ctx) {
	int i;
	ctx->lenBuf = 0;
	ctx->count[0] = ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	for (i = 0; i < 80; i++) { ctx->buffer[i] = 0; }
}


void SHA1_Update(SHA_CTX *ctx, void *data, int len) {
	unsigned char *dataIn = (unsigned char*)data;
	int i;

	for (i = 0; i < len; i++) {
		ctx->buffer[ctx->lenBuf / 4] <<= 8;
		ctx->buffer[ctx->lenBuf / 4] |= (unsigned int)dataIn[i];
		if ((++ctx->lenBuf) % 64 == 0) {
			SHA1_Transform(ctx);
			ctx->lenBuf = 0;
		}
		ctx->count[1] += 8;
		ctx->count[0] += (ctx->count[1] < 8);
	}
}


void SHA1_Final(unsigned char digest[20], SHA_CTX *ctx) {
	unsigned char pad0x80 = 0x80;
	unsigned char pad0x00 = 0x00;
	unsigned char padlen[8];
	int i;

	padlen[0] = (unsigned char)((ctx->count[0] >> 24) & 255);
	padlen[1] = (unsigned char)((ctx->count[0] >> 16) & 255);
	padlen[2] = (unsigned char)((ctx->count[0] >> 8)  & 255);
	padlen[3] = (unsigned char)((ctx->count[0] >> 0)  & 255);
	padlen[4] = (unsigned char)((ctx->count[1] >> 24) & 255);
	padlen[5] = (unsigned char)((ctx->count[1] >> 16) & 255);
	padlen[6] = (unsigned char)((ctx->count[1] >> 8)  & 255);
	padlen[7] = (unsigned char)((ctx->count[1] >> 0)  & 255);

	SHA1_Update(ctx, &pad0x80, 1);
	while (ctx->lenBuf != 56) { SHA1_Update(ctx, &pad0x00, 1); }
	SHA1_Update(ctx, padlen, 8);
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)(ctx->state[i / 4] >> 24);
		ctx->state[i / 4] <<= 8;
	}
	SHA1_Init(ctx);
}

void SHA1_Transform(SHA_CTX *ctx) {
	int t;
	unsigned int A = ctx->state[0];
	unsigned int B = ctx->state[1];
	unsigned int C = ctx->state[2];
	unsigned int D = ctx->state[3];
	unsigned int E = ctx->state[4];
	unsigned int TEMP;

	const unsigned int k1 = 0x5a827999;
	const unsigned int k2 = 0x6ed9eba1;
	const unsigned int k3 = 0x8f1bbcdc;
	const unsigned int k4 = 0xca62c1d6;

	for (t = 16; t <= 79; t++)
		ctx->buffer[t] = SHA_ROTATE(ctx->buffer[t-3] ^ ctx->buffer[t-8] ^ ctx->buffer[t-14] ^ ctx->buffer[t-16], 1);

	for (t = 0; t <= 19; t++) {
		TEMP = SHA_ROTATE(A,5) + (((C^D)&B)^D) + E + ctx->buffer[t] + k1;
		E = D; 
		D = C; 
		C = SHA_ROTATE(B, 30); 
		B = A;
		A = TEMP;
	}
	for (t = 20; t <= 39; t++) {
		TEMP = SHA_ROTATE(A,5) + (B^C^D) + E + ctx->buffer[t] + k2;
		E = D; 
		D = C; 
		C = SHA_ROTATE(B, 30); 
		B = A; 
		A = TEMP;
	}
	for (t = 40; t <= 59; t++) {
		TEMP = SHA_ROTATE(A,5) + ((B&C)|(D&(B|C))) + E + ctx->buffer[t] + k3;
		E = D; 
		D = C; 
		C = SHA_ROTATE(B, 30); 
		B = A; 
		A = TEMP;
	}
	for (t = 60; t <= 79; t++) {
		TEMP = SHA_ROTATE(A,5) + (B^C^D) + E + ctx->buffer[t] + k4;
		E = D; 
		D = C; 
		C = SHA_ROTATE(B, 30); 
		B = A; 
		A = TEMP;
	}

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E; 
}


} // namespace sha
} // namespace Merak

#endif // MERAK_SHA_SHA1_H_