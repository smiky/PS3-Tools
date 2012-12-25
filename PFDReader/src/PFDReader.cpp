// PFDReader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "common.h"

using namespace std;

static int dbg = 1;

static u8 *pfd = NULL;
static u32 pfd_n_params;
static u32 pfd_table_entry;

const char ii[] = { '"' };

void err_log(char *name, char *content)
{
	fstream f;
	f.open(name, ios::out);
	if (!f.fail())
	{
		printf("Writing LOG..\n");
		f << "<?xml version=" << ii << 1.0 << ii << " encoding=" << ii << "utf-8" << ii << " standalone=" << "yes" << ii << "?>" << endl;
		f << "<paramsfo add_hidden=" << ii << "false" << ii << ">" << endl;		
		f << "	<param key=" << ii << "File Certificate" << ii << " fmt=" << ii << "utf8"  << ii << " max_len=" << ii << "192" << ii << ">" << content << "</param>"  << endl;
		f << "</paramsfo>";
		f.close();
		printf("LOG Written Finish!\n");
	}
}

void read_pfd()
{
	printf("Reading PFD..\n");
	pfd_n_params = be32(pfd + 0x70) + be32(pfd + 0x74);
	pfd_table_entry = be32(pfd + 0x60) + be32(pfd + 0x64);
	unsigned int i, j;

	if (dbg) printf("[PFD HDR]	  0x%08x_0x%08x\n", (unsigned int)be32(pfd), (unsigned int)be32(pfd + 0x4));
	if (dbg) printf("[PFD Version]	  0x%08x_0x%08x\n", (unsigned int)be32(pfd + 0x8), (unsigned int)be32(pfd + 0xc));
	if (dbg) printf("[PFD HashKey]	  %08X%08X%08X%08X\n", be32(pfd + 0x10), be32(pfd + 0x14), be32(pfd + 0x18), be32(pfd + 0x1c));
	if (dbg) printf("[PFD SHA1-HMAC 1] %08X%08X%08X%08X%08X\n", be32(pfd + 0x20), be32(pfd + 0x24), be32(pfd + 0x28), be32(pfd + 0x2c), be32(pfd + 0x30));
	if (dbg) printf("[PFD SHA1-HMAC 2] %08X%08X%08X%08X%08X\n", be32(pfd + 0x34), be32(pfd + 0x38), be32(pfd + 0x3c), be32(pfd + 0x40), be32(pfd + 0x44));
	if (dbg) printf("[PFD SHA1-HMAC 3] %08X%08X%08X%08X%08X\n", be32(pfd + 0x48), be32(pfd + 0x4c), be32(pfd + 0x50), be32(pfd + 0x54), be32(pfd + 0x58));
	if (dbg) printf("[PFD Padding]	  0x%08x\n", be32(pfd + 0x5c));
	if (dbg) printf("[PFD N]		  %u Value(s)\n", pfd_n_params);
	if (dbg) printf("[PFD XY-Table Entry]	%u Value(s)\n", pfd_table_entry);
	if (dbg) printf("*[PFD Table Head]	0x%08x%08x | 0x%08x%08x\n", be32(pfd + 0x60), be32(pfd + 0x64), be32(pfd + 0x68), be32(pfd + 0x6c));
	if (dbg) printf("*[PFD X-Table]\n");

	for (i = 0x0; i < pfd_table_entry; i += 0x1)
	{
		if (be32(pfd + (0x78 + 0x4 + (i * 0x8))) != 0x72)		
			if (dbg) printf("[POS:%2i]		0x%x\n", i + 1, be32(pfd + (0x78 + 0x4 + (i * 0x8))));	
	}

	if (dbg) printf("*[PFD Protected Files Tables]\n");
	if (dbg) printf("*[Virtual Index ID]	0x%08x%08x\n", be32(pfd + 0x240), be32(pfd + 0x244));

	for (i = 0; i < pfd_n_params; i++)
	{
		u32 offset = 0x110 * i;
		if (dbg)
		{
			//param32 = be64(pfd + 0x240 + 0x8);
			char param[0x50];
			char param_fc[0x100];

			for (j = 0x0; j < 0x41; j += 0x1)
				param[j] = le8(pfd + 0x240 + 0x8 + offset + j);
			printf("*[File Name]		%s\n", param);
			for (j = 0x0; j < 0x7; j += 0x1)
				param[j] = le8(pfd + 0x248 + 0x41 + offset + j);
			printf("*[Random Garbage]	%s\n", param);
			for (int j = 0x0; j < 0xb8; j++)
				param_fc[j] = le8(pfd + 0x248 + 0x48 + offset + j);
			printf("*[File Certificate]	%s\n", param_fc);			
			printf("*[File Size]		%u Bytes\n", be32(pfd + 0x248 + 0x48 + 0xb8 + offset) + be32(pfd + 0x248 + 0x48 + 0xb8 + offset + 0x4));
			//err_log("FPD.LOG", param_fc);
		}
	}
	
	if (dbg) printf("*[PFD Y-Table]\n");
	for (i = 0x0; i < pfd_table_entry; i += 0x1)
	{
		if (dbg)
		{
			printf("*[%02u]		Hash: ", i + 1);
			print_hash(pfd + (0x7B60 + (i * 0x14)), 0x10, true);
			printf("\n");
			//if (dbg) printf("*[%02u]		Hash:%X%X%X%X%X\n", i + 1, be32(pfd + (0x7B60 + (i * 0x14))), be32(pfd + (0x7B64 + (i * 0x14))), be32(pfd + (0x7B68 + (i * 0x14))), be32(pfd + (0x7B6c + (i * 0x14))), be32(pfd + (0x7B70 + (i * 0x14))));	
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	u8 enc[0x14] = { 0x7C, 0x1F, 0x5C, 0x28, 0xA7, 0xEE, 0x4D, 0x39, 0x22, 0xAD, 0xC8, 0x28, 0xE6, 0xCD, 0x78, 0x88, 0x98, 0x0F, 0x33, 0xB6 }, des[0x14];
	u8 iv[0x10] = { 0x69, 0x15, 0x2C, 0x97, 0x81, 0x2B, 0x25, 0xC5, 0x2A, 0xD4, 0xFA, 0x18, 0xE4, 0xB8, 0x16, 0xA8 };	
	//key_get_simple("ht_iv_test", iv, 0x10);
	aes128(iv, enc, des);
	print_hash(des, 0x14, true);

	if (argc == 2)
	{
		pfd = (u8*)plus_mmap_file(argv[1]);
		if (dbg) printf("[PFD ADDRESS] 0x%08x\n", pfd);

		read_pfd();
	}
	else
		printf("Please input valid format! like [?.exe ?.SFO ?.???]");

	return 0;
}