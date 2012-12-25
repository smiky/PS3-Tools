#include "mingw_mmap.h"

extern int getpagesize()
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return static_cast<int>(si.dwPageSize);
}

void *mingw_mmap(void *pStart, size_t sLength, int nProt, int nFlags, int nFd, off_t oOffset)
{
	(void)nProt;
	HANDLE hHandle;

	//printf("%s, %d, %d, %d, %d, %d\n", pStart, sLength, nProt, nFlags, nFd, oOffset);

	if (pStart != NULL || !(nFlags & MAP_PRIVATE))
	{
		printf("Invalid usage of mingw_mmap");
		return NULL;
	}
	if (oOffset % getpagesize() != 0)
	{
		printf("Offset does not match the memory allocation granularity");
		return NULL;
	}

	hHandle = CreateFileMapping((HANDLE)_get_osfhandle(nFd), NULL, PAGE_WRITECOPY, 0, 0, NULL);
	if (hHandle != NULL)
	{
		pStart = MapViewOfFile(hHandle, FILE_MAP_COPY, 0, oOffset, sLength);
	}	
	return pStart;
}

int mingw_munmap(void *pStart, size_t sLength)
{
	(void)sLength;

	if (UnmapViewOfFile(pStart) != 0)
		return FALSE;

	return TRUE;
}