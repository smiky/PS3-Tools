#include "common.h"

void print_hash(u8 *ptr, u32 len, bool upper)
{
	while(len--)
		upper ? printf("%02X", *ptr++) : printf("%02x", *ptr++);
}

//old c type
//void *mmap_file(const char *path)
//{
//	int fd;
//	struct stat st;
//	void *ptr;
//
//	fd = open(path, O_RDONLY);
//	if (fd == -1)
//		fail("open %s", path);
//	if (fstat(fd, &st) != 0)
//		fail("fstat %s", path);
//
//	ptr = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
//	printf("result %s", ptr);
//	if (ptr == NULL)
//		fail("mmap");
//	close(fd);
//
//	return ptr;
//}

//new standard
void *plus_mmap_file(const wchar_t *wpath)
{
	int wfd;
	struct stat st;
	void *wptr;

	errno_t err_t = _wsopen_s(&wfd, wpath, _O_RDONLY, _SH_DENYWR, _S_IREAD | _S_IWRITE);

	if (wfd == -1)
		fail("open %s", wpath);
	if (fstat(wfd, &st) != 0)
		fail("fstat %s", wpath);

	wptr = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, wfd, 0);
	if (wptr == NULL)
		fail("mmap error");
	_close(wfd);

	return wptr;
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf_s(msg, sizeof(msg), a, va);
	fprintf(stderr, "%s\n", msg);
	perror("perror");

	exit(1);
}

void aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out)
{
	AES_KEY k;
	u32 i;
	u8 tmp[16];
	u8 iv[16];

	memcpy(iv, iv_in, 16);
	memset(&k, 0, sizeof k);
	AES_set_decrypt_key(key, 128, &k);

	while (len > 0)
	{
		memcpy(tmp, in, 16);
		AES_decrypt(in, out, &k);

		for (i = 0; i < 16; i++)
			out[i] ^= iv[i];

		memcpy(iv, tmp, 16);

		out += 16;
		in += 16;
		len -= 16;
	}
}

void aes128(u8 *key, const u8 *in, u8 *out)
{
    AES_KEY k;

    assert(!AES_set_decrypt_key(key, 128, &k));
    AES_decrypt(in, out, &k);
}

// FIXME: use a non-broken sha1.c *sigh*
static void sha1_fixup(struct SHA1Context *ctx, u8 *digest)
{
	u32 i;

	for(i = 0; i < 5; i++)
	{
		*digest++ = ctx->Message_Digest[i] >> 24 & 0xff;
		*digest++ = ctx->Message_Digest[i] >> 16 & 0xff;
		*digest++ = ctx->Message_Digest[i] >> 8 & 0xff;
		*digest++ = ctx->Message_Digest[i] & 0xff;
	}
}

void sha1(u8 *data, u32 len, u8 *digest)
{
	struct SHA1Context ctx;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, len);
	SHA1Result(&ctx);

	sha1_fixup(&ctx, digest);
}

void sha1_hmac(u8 *key, u8 *data, u32 len, u8 *digest)
{
	struct SHA1Context ctx;
	u32 i;
	u8 ipad[0x40];
	u8 tmp[0x40 + 0x14]; // opad + hash(ipad + message)

	SHA1Reset(&ctx);

	for (i = 0; i < sizeof ipad; i++)
	{
		tmp[i] = key[i] ^ 0x5c; // opad
		ipad[i] = key[i] ^ 0x36;
	}

	SHA1Input(&ctx, ipad, sizeof ipad);
	SHA1Input(&ctx, data, len);
	SHA1Result(&ctx);

	sha1_fixup(&ctx, tmp + 0x40);

	sha1(tmp, sizeof tmp, digest);
}

static int key_build_path(char *ptr)
{
	char *home = NULL;
	char *dir = NULL;
	size_t len;

	memset(ptr, 0, 256);

	_dupenv_s(&dir, &len, "PS3_KEYS");
	if (dir != NULL)
	{
		errno_t err_t = strncpy_s(ptr, 128, dir, 256);
		if(err_t == 0)
			return 0;
		else
			return err_t;
	}

#ifdef WIN32
	_dupenv_s(&home, &len, "USERPROFILE");	//in my PC value["C:\Users\SmikY"]
#else
	home = getenv("HOME");
#endif
	if (home == NULL)
		_snprintf_s(ptr, 128, 256, "ps3keys");
	else
#ifdef WIN32
		_snprintf_s(ptr, 128, 256, "%s\\ps3keys\\", home);
#else
		_snprintf(ptr, 256, "%s/.ps3/", home);
#endif

	return 0;
}

static int key_read(const char *path, u32 len, u8 *dst)
{
	FILE *fp = NULL;
	u32 read;
	int ret = -1;

	fopen_s(&fp, path, "rb");
	if (fp == NULL)
		goto fail;

	read = fread(dst, len, 1, fp);

	if (read != 1)
		goto fail;

	ret = 0;

fail:
	if (fp != NULL)
		fclose(fp);

	return ret;
}

int key_get_simple(const char *name, u8 *bfr, u32 len)
{
	char base[256];
	char path[256];

	if (key_build_path(base) < 0)
		return -1;

	_snprintf_s(path, sizeof(path), "%s/%s", base, name);
	if (key_read(path, len, bfr) < 0)
		return -1;

	return 0;
}