#ifndef PE_HEADER
#define PE_HEADER

typedef unsigned short WORD;
typedef long LONG;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef struct _IMAGE_OPTIONAL_HEADER;
typedef struct _IMAGE_DOS_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY;
typedef struct _NT_HEADERS;

#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;         // DOS signature : 4D5A ("MZ")
	WORD e_cblp;
	WORD e_cp;           
	WORD e_crlc;       
	WORD e_cparhdr;      
	WORD e_minalloc;      
	WORD e_maxalloc;      
	WORD e_ss;           
	WORD e_sp;           
	WORD e_csum;       
	WORD e_ip;           
	WORD e_cs;           
	WORD e_lfarlc;        
	WORD e_ovno;         
	WORD e_res[4];     
	WORD e_oemid;         
	WORD e_oeminfo;    
	WORD e_res2[10];    
	LONG   e_lfanew;       // NT header's offset
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
#pragma pack(pop)



#pragma pack(push, 1)
typedef struct _IMAGE_FILE_HEADER {

	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;

}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_OPTIONAL_HEADER {

	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
}IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
#pragma pack(pop)



#pragma pack(push, 1)
typedef struct _NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADER32, *PIMAGE_NT_HEADER32;
#pragma pack(pop)
#endif 

