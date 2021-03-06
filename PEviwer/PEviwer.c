#define _CRT_SECURE_NO_WARNINGS 

#include <stdio.h>
#include "_PE.h"
#include <time.h>  


int main(int argc, char* argv[])
{
	IMAGE_DOS_HEADER _DOS_HEADER;
	IMAGE_NT_HEADER32  _NT_HEAER32;

	FILE *fp = fopen("putty.exe", "rb");

	//File open exception
	if (fp == NULL) {
		printf("File open failed\n");
	}

	//Read Datas to DOS_HEADER 
	fread(&_DOS_HEADER, sizeof(_DOS_HEADER), 1, fp);

	//Check PE file
	if (_DOS_HEADER.e_magic != 23117) {
		printf("해당 파일은 PE 파일이 아닙니다\n");
		exit(0);
	}

	//Print DOS_HEADER's main values
	printf("DOS_HEADER\n");
	printf("e_magic : %X\ne_lfanew : %X\n\n", _DOS_HEADER.e_magic, _DOS_HEADER.e_lfanew);

	//Find NT_HEADER's offset
	fseek(fp, _DOS_HEADER.e_lfanew, SEEK_SET);

	//Read Datas to NT_HEADER
	fread(&_NT_HEAER32, sizeof(&_NT_HEAER32), 1, fp);

	//Print NT_HEADER's main values
	printf("NT_HEADER\n");
 	if (  _NT_HEAER32.Signature  == 0x4550)
	 	printf("Signature : %0X\n", _NT_HEAER32.Signature);


	printf("%X", _NT_HEAER32.FileHeader.TimeDateStamp);
	  

	return 0;
}

