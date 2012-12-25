// SFOReader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "common.h"

using namespace std;

//#define UNKN 0x0004 //UTF8
#define UTF8 0x0204
//#define INTG 0x0404

static int dbg = 1;
static int *content;    //1:int32 | 2:utf8
static string *SFO_VALUES;
static string *UTF8_params;

static u8 *sfo = NULL;
static u32 sfo_n_params;
static u32 *length;
static u64 *int32_params;

//u32 sfo_header = 0x46535000; //Big endian

const char ii[] = { '"' };

void read_sfo()
{
	printf("Reading SFO..\n");
	u32 sfo_vals = le32(sfo + 0x08), sfo_param = le32(sfo + 0x0c);
	u32 sfo_type, sfo_val_ptr, sfo_val_size, sfo_param_ptr, sfo_param_size;
	u64 param32;
	sfo_n_params = le32(sfo + 0x10);
	unsigned int i, k;

	SFO_VALUES = new string[sfo_n_params];
	content = new int[sfo_n_params];
	int32_params = new u64[sfo_n_params];
	UTF8_params = new string[sfo_n_params];
	length = new u32[sfo_n_params];

	if (dbg) printf("[SFO HDR]     0x%08x\n", (unsigned int)be32(sfo));
	if (dbg) printf("[SFO Version] 0x%08x\n", (unsigned int)le32(sfo + 0x4));
	if (dbg) printf("[SFO N]	      %u Value(s)\n", sfo_n_params);
	if (dbg) printf("[SFO Params Offsets]  0x%08x\n", sfo_param);
	if (dbg) printf("[ SFO ]\n");

	for (i = 0x0; i < sfo_n_params; i += 0x1)
	{
		char value[0x20];
		char param[0x500];

		if (i != sfo_n_params - 1)
			sfo_val_size = le8(sfo + (0x24 + (i * 0x10))) - le8(sfo + (0x14 + (i * 0x10)));
		else
			sfo_val_size = 0x8;

		sfo_val_ptr = (sfo_vals + le16(sfo + (0x14 + (i * 0x10))));
		sfo_param_size = le32(sfo + (0x1c + (i * 0x10)));
		sfo_param_ptr = le32(sfo + (0x20 + (i * 0x10))) + sfo_param;
		sfo_type = le16(sfo + (0x16 + (i * 0x10)));

		if (dbg) printf("[ Type: 0x%x | Size: 0x%x | Param_S: 0x%x]\n", sfo_type, sfo_param_size, sfo_param_ptr);

		for (k = 0; k < (unsigned int)(u32)sfo_val_size; k++)
			value[k] = be8(sfo + (sfo_val_ptr + k));
		if (dbg) printf("[ %3i ] %16s", i + 1, value);

		SFO_VALUES[i] = value;
		length[i] = sfo_param_size;

		if (sfo_param_size == 0x4)
		{
			if (sfo_type != UTF8)
			{
				param32 = le32(sfo + sfo_param_ptr);
			}
			else
			{
				for (k = 0x0; k < sfo_param_size; k += 0x1)
					param[k] = le8(sfo + sfo_param_ptr + k);
			}
		}
		else if (sfo_param_size > 0x4 && sfo_param_size <= 0x8)
		{
			if (sfo_type != UTF8)
			{
				param32 = be32(sfo + sfo_param_ptr);
			}
			else
			{
				for (k = 0x0; k < sfo_param_size; k += 0x1)
					param[k] = le8(sfo + sfo_param_ptr + k);
			}
		}
		else if (sfo_param_size > 0x8 && sfo_param_size <= 0x16)
		{
			if (sfo_type != UTF8)
			{
				param32 = be64(sfo + sfo_param_ptr);
			}
			else
			{
				for (k = 0x0; k < sfo_param_size; k += 0x1)
					param[k] = le8(sfo + sfo_param_ptr + k);
			}
		}
		else if (sfo_param_size > 0x16 && sfo_param_size <= 0x30)
		{
			if (sfo_type != UTF8)
			{
				param32 = be64(sfo + sfo_param_ptr);
			}
			else
			{
				for (k = 0x0; k < 0x30; k += 0x1)
					param[k] = le8(sfo + sfo_param_ptr + k);
			}
		}
		else if (sfo_param_size >= 0x32)
		{
			if (sfo_type != UTF8)
			{
				param32 = be64(sfo + sfo_param_ptr);
			}
			else
			{
				for (k = 0x0; k < sfo_param_size; k++)
				{
					param[k] = le8(sfo + sfo_param_ptr + k);
					//if (dbg) printf("<0x%08x>\n", sfo + sfo_param_ptr + k);
				}
			}
		}
		else {}

		if (sfo_type != UTF8)
		{
			content[i] = 1;
			int32_params[i] = param32;
			if (dbg) printf(" | Param: 0x%x\n", (unsigned int)param32);
		}
		else
		{
			content[i] = 2;
			UTF8_params[i] = param;
			if (dbg) printf(" | Param: %s\n", param);
		}
	}
}

void build_sfx(const char *sfx_path)
{
	printf("Writing SFX..\n");
	fstream f;
	f.open(sfx_path, ios::out);
	if (f.fail())
		fail("Failed on writing SFX [Path: %s]", sfx_path);

	else
	{
		f << "<?xml version=" << ii << 1.0 << ii << " encoding=" << ii << "utf-8" << ii << " standalone=" << "yes" << ii << "?>" << endl;
		f << "<paramsfo add_hidden=" << ii << "false" << ii << ">" << endl;

		for (unsigned int i = 0; i < sfo_n_params; i++)
		{
			if (content[i] != 2)
				f << "  <param key=" << ii << SFO_VALUES[i].c_str() << ii << " fmt=" << ii << "int32" << ii << " max_len=" << ii << length[i] << ii << ">" << int32_params[i] << "</param>"  << endl;
			else
			{
				while (UTF8_params[i].find("\n") != string::npos)
					UTF8_params[i].replace(UTF8_params[i].find("\n"), 1, " ");
				f << "  <param key=" << ii << SFO_VALUES[i].c_str() << ii << " fmt=" << ii << "utf8"  << ii << " max_len=" << ii << length[i] << ii << ">" << UTF8_params[i].c_str() << "</param>"  << endl;
			}
		}
		f << "</paramsfo>";
		f.close();
	}
	printf("SFX Written!\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc == 3)
	{
		size_t i;
		char argv_c[50];

		sfo = (u8*)plus_mmap_file(argv[1]);
		if (dbg) printf("[SFO ADDRESS] 0x%08x\n", sfo);

		read_sfo();

		wcstombs_s(&i, argv_c, sizeof(argv_c), argv[2], wcslen(argv[2]));
		build_sfx(argv_c);
	}
	else
		printf("Please input valid format! like [?.exe ?.SFO ?.???]");

	return 0;
}