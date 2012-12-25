#pragma once

#include <io.h>
#include <stdio.h>
#include <windows.h>
#include <sys/types.h>

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 2
#define MAP_PRIVATE 3

extern int getpagesize();

void *mingw_mmap(void *pStart, size_t sLength, int nProt, int nFlags, int nFd, off_t oOffset);
#define mmap mingw_mmap

int mingw_munmap(void *pStart, size_t sLength);
#define munmap mingw_munmap