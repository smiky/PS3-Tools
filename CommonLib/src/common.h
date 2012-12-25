#ifndef __COMMON_H__
#define __COMMON_H__

#include <assert.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <wchar.h>
#include <sys/stat.h>

#include "mingw_mmap.h"
#include "types.h"
#include "aes.h"
#include "sha1.h"

void print_hash(u8 *ptr, u32 len, bool upper);
//void *mmap_file(const char *path);
void *plus_mmap_file(const wchar_t *wpath);
__declspec(noreturn) void fail(const char *fmt, ...);
void aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out);
void aes128(u8 *key, const u8 *in, u8 *out);
static void sha1_fixup(struct SHA1Context *ctx, u8 *digest);
void sha1(u8 *data, u32 len, u8 *digest);
void sha1_hmac(u8 *key, u8 *data, u32 len, u8 *digest);
static int key_build_path(char *ptr);
static int key_read(const char *path, u32 len, u8 *dst);
int key_get_simple(const char *name, u8 *bfr, u32 len);

#endif