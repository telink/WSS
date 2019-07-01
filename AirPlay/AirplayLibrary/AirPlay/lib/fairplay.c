#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include "fairplay.h"
#include "mycrypt.h"

static void print_buf(unsigned char *data, int len)
{
	int i;
	for (i = 0; i < len; i++)
		fprintf(stderr, "%02x", data[i]);
	fprintf(stderr, "\n");
}

#define SERVER_PORT 8883

static int fairplay_sock_fd = 0;
static int get_fairplay_socket()
{
	struct sockaddr_in ser_addr;

	if (fairplay_sock_fd > 0) return fairplay_sock_fd;

	memset(&ser_addr, 0, sizeof(ser_addr));
	ser_addr.sin_family = AF_INET;

	//inet_aton("106.186.117.173", (struct in_addr *)&ser_addr.sin_addr);
	//inet_aton("127.0.0.1", (struct in_addr *)&ser_addr.sin_addr);
	ser_addr.sin_addr.s_addr = inet_addr("192.168.1.108");
	ser_addr.sin_port = htons(SERVER_PORT);
	fairplay_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fairplay_sock_fd <= 0)
	{
		fprintf(stderr, "%s:%d, create socket failed", __FILE__, __LINE__);
		return 0;
	}

	if (connect(fairplay_sock_fd, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0)
	{
		fprintf(stderr, "%s:%d, create socket failed", __FILE__, __LINE__);
		fairplay_sock_fd = 0;
		return 0;
	}

	return fairplay_sock_fd;
}

static void close_fairplay_socket()
{
	if (fairplay_sock_fd>0)
	{
		closesocket(fairplay_sock_fd);
		//close(fairplay_sock_fd);
	}
	fairplay_sock_fd = 0;
}

unsigned char * fairplay_query(int cmd, const unsigned char *data, int len, int *size_p)
{
	int sock_fd;
	unsigned char recvbuf[1024] = { 0 };
	unsigned char sendbuf[1024] = { 0 };
	int sendlen = 0;
	int retlen;
	unsigned char *buf;

	if (cmd < 1 || cmd > 3) return NULL;

	sock_fd = get_fairplay_socket();

	sendlen = len + 2;
	sendbuf[0] = cmd & 0xff;
	sendbuf[1] = sendlen & 0xff;
	memcpy(sendbuf + 2, data, len);

	retlen = send(sock_fd, sendbuf, sendlen, 0);
	if (retlen < 0) {
		close_fairplay_socket();
		return NULL;
	}

	retlen = recv(sock_fd, recvbuf, 1024, 0);

	if (retlen <= 0) {
		close_fairplay_socket();
		return NULL;
	}

	*size_p = retlen;
	buf = (unsigned char*)malloc(retlen);
	memcpy(buf, recvbuf, retlen);

	if (cmd == 3)
		close_fairplay_socket();

	return buf;
}


//int airplay_decrypt(AES_KEY *ctx, unsigned char *in, unsigned int len, unsigned char *out)
//{
//	unsigned char *pin, *pout;
//	unsigned int n;
//	unsigned char k;
//	int i, remain = 0;
//	int l = len, len1 = 0;
//
//	if (l == 0) return 0;
//
//	pin = in; pout = out;
//
//	fprintf(stderr, "remain=%d\n", ctx->remain_bytes);
//
//	if (ctx->remain_bytes) {
//		n = ctx->remain_bytes;
//		do {
//			*pout = *pin ^ ctx->out[n];
//			n = (n + 1) & 0xf;
//			ctx->remain_bytes = n;
//			l--;
//			pout++;
//			pin++;
//			if (l == 0) return 0;
//		} while (n != 0);
//	}
//
//	if (l <= 15) {
//		remain = l;
//		AES_ecb_encrypt(&ctx->in, &ctx->out, ctx, AES_ENCRYPT);
//	}
//	else {
//		len1 = l;
//		do {
//			AES_ecb_encrypt(&ctx->in, &ctx->out, ctx, AES_ENCRYPT);
//			i = 15;
//			do {
//				k = ctx->in[i] + 1;
//				ctx->in[i] = k;
//				if (k) break;
//				--i;
//			} while (i != -1);
//			for (i = 0; i<16; i++)
//			{
//				pout[i] = pin[i] ^ ctx->out[i];
//			}
//			pout += 16;
//			pin += 16;
//			l -= 16;
//		} while (l > 15);
//		if (l == 0) return 0;
//
//		/*
//		i = (len1 - 16) & 0xfffffff0 + 16;
//
//		pin = in + i;
//		pout = out + i;
//		*/
//		AES_ecb_encrypt(&ctx->in, &ctx->out, ctx, 1);
//		remain = l;
//	}
//
//	i = 15;
//	do {
//		k = ctx->in[i] + 1;
//		ctx->in[i] = k;
//		if (k) break;
//		--i;
//	} while (i != -1);
//
//	for (i = 0; i<remain; i++)
//	{
//		pout[i] = pin[i] ^ ctx->out[i];
//	}
//	if (ctx->remain_flags == 0)
//		ctx->remain_bytes += remain;
//
//	return 0;
//}
//

void sha512msg(const unsigned char *msg1, size_t msg1_len, const unsigned char *msg2, size_t msg2_len, unsigned char *out)
{
	sha512_context ctx;
	sha512_init(&ctx);
	sha512_update(&ctx, msg1, msg1_len);
	sha512_update(&ctx, msg2, msg2_len);
	sha512_final(&ctx, out);
}

void sha512msg2(const char *msg1, const char *msg2, const char *key, char *digest1, char *digest2)
{
	sha512_context ctx;

	sha512_init(&ctx);
	sha512_update(&ctx, (const unsigned char*)msg1, strlen(msg1));
	sha512_update(&ctx, (const unsigned char*)key, 16LL);
	sha512_final(&ctx, (unsigned char*)digest1);

	sha512_init(&ctx);
	sha512_update(&ctx, (const unsigned char*)msg2, strlen(msg2));
	sha512_update(&ctx, (const unsigned char*)key, 16LL);
	sha512_final(&ctx, (unsigned char*)digest2);

}