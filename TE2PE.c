// Converts Terse Executable (TE) image to PE32(+) image
// Author: Nikolaj Schlej aka CodeRush
// License: WTFPL2 (http://wtfpl2.com/)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)

// Basic types
#define UINT8  uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN  unsigned int
#define VOID   void

#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_ARM64    0xAA64

#define EFI_IMAGE_DOS_SIGNATURE     0x5A4D     // MZ
#define EFI_IMAGE_PE_SIGNATURE      0x00004550 // PE
#define EFI_IMAGE_TE_SIGNATURE      0x5A56     // VZ

// DOS header
typedef struct _EFI_IMAGE_DOS_HEADER {
    UINT16  e_magic;    // Magic number
    UINT16  e_cblp;     // Bytes on last page of file
    UINT16  e_cp;       // Pages in file
    UINT16  e_crlc;     // Relocations
    UINT16  e_cparhdr;  // Size of header in paragraphs
    UINT16  e_minalloc; // Minimum extra paragraphs needed
    UINT16  e_maxalloc; // Maximum extra paragraphs needed
    UINT16  e_ss;       // Initial (relative) SS value
    UINT16  e_sp;       // Initial SP value
    UINT16  e_csum;     // Checksum
    UINT16  e_ip;       // Initial IP value
    UINT16  e_cs;       // Initial (relative) CS value
    UINT16  e_lfarlc;   // File address of relocation table
    UINT16  e_ovno;     // Overlay number
    UINT16  e_res[4];   // Reserved words
    UINT16  e_oemid;    // OEM identifier (for e_oeminfo)
    UINT16  e_oeminfo;  // OEM information; e_oemid specific
    UINT16  e_res2[10]; // Reserved words
    UINT32  e_lfanew;   // File address of new header
} EFI_IMAGE_DOS_HEADER;

// COFF file header (object and image)
typedef struct _EFI_IMAGE_FILE_HEADER {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} EFI_IMAGE_FILE_HEADER;

// Characteristics
#define EFI_IMAGE_FILE_RELOCS_STRIPPED      0x0001  // Relocation info stripped from file
#define EFI_IMAGE_FILE_EXECUTABLE_IMAGE     0x0002  // File is executable  (i.e. no unresolved external references)
#define EFI_IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004  // Line numbers stripped from file
#define EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008  // Local symbols stripped from file
#define EFI_IMAGE_FILE_BYTES_REVERSED_LO    0x0080  // Bytes of machine word are reversed
#define EFI_IMAGE_FILE_32BIT_MACHINE        0x0100  // 32 bit word machine
#define EFI_IMAGE_FILE_DEBUG_STRIPPED       0x0200  // Debugging info stripped from file in .DBG file
#define EFI_IMAGE_FILE_SYSTEM               0x1000  // System File
#define EFI_IMAGE_FILE_DLL                  0x2000  // File is a DLL
#define EFI_IMAGE_FILE_BYTES_REVERSED_HI    0x8000  // Bytes of machine word are reversed

// Header Data Directories.
typedef struct _EFI_IMAGE_DATA_DIRECTORY {
    UINT32  VirtualAddress;
    UINT32  Size;
} EFI_IMAGE_DATA_DIRECTORY;

// Directory Entries
#define EFI_IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define EFI_IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define EFI_IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define EFI_IMAGE_DIRECTORY_ENTRY_DEBUG       6
#define EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT   7
#define EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR   8
#define EFI_IMAGE_DIRECTORY_ENTRY_TLS         9
#define EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10

#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16

// PE32 Optional Header
#define EFI_IMAGE_PE_OPTIONAL_HDR32_MAGIC 0x10b

// Optional Header Standard Fields for PE32
typedef struct _EFI_IMAGE_OPTIONAL_HEADER32{
    // Standard fields
    UINT16                    Magic;
    UINT8                     MajorLinkerVersion;
    UINT8                     MinorLinkerVersion;
    UINT32                    SizeOfCode;
    UINT32                    SizeOfInitializedData;
    UINT32                    SizeOfUninitializedData;
    UINT32                    AddressOfEntryPoint;
    UINT32                    BaseOfCode;
    UINT32                    BaseOfData;  // PE32 contains this additional field, which is absent in PE32+

    // Optional Header Windows-Specific Fields
    UINT32                    ImageBase;
    UINT32                    SectionAlignment;
    UINT32                    FileAlignment;
    UINT16                    MajorOperatingSystemVersion;
    UINT16                    MinorOperatingSystemVersion;
    UINT16                    MajorImageVersion;
    UINT16                    MinorImageVersion;
    UINT16                    MajorSubsystemVersion;
    UINT16                    MinorSubsystemVersion;
    UINT32                    Win32VersionValue;
    UINT32                    SizeOfImage;
    UINT32                    SizeOfHeaders;
    UINT32                    CheckSum;
    UINT16                    Subsystem;
    UINT16                    DllCharacteristics;
    UINT32                    SizeOfStackReserve;
    UINT32                    SizeOfStackCommit;
    UINT32                    SizeOfHeapReserve;
    UINT32                    SizeOfHeapCommit;
    UINT32                    LoaderFlags;
    UINT32                    NumberOfRvaAndSizes;
    EFI_IMAGE_DATA_DIRECTORY  DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER32;

// PE32 image header
typedef struct _EFI_IMAGE_NT_HEADERS32 {
    UINT32 Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} EFI_IMAGE_NT_HEADERS32;

#define EFI_IMAGE_PE_OPTIONAL_HDR64_MAGIC 0x20b

typedef struct {
  //
  // Standard fields.
  //
  UINT16                    Magic;
  UINT8                     MajorLinkerVersion;
  UINT8                     MinorLinkerVersion;
  UINT32                    SizeOfCode;
  UINT32                    SizeOfInitializedData;
  UINT32                    SizeOfUninitializedData;
  UINT32                    AddressOfEntryPoint;
  UINT32                    BaseOfCode;
  //
  // NT additional fields.
  //
  UINT64                    ImageBase;
  UINT32                    SectionAlignment;
  UINT32                    FileAlignment;
  UINT16                    MajorOperatingSystemVersion;
  UINT16                    MinorOperatingSystemVersion;
  UINT16                    MajorImageVersion;
  UINT16                    MinorImageVersion;
  UINT16                    MajorSubsystemVersion;
  UINT16                    MinorSubsystemVersion;
  UINT32                    Win32VersionValue;
  UINT32                    SizeOfImage;
  UINT32                    SizeOfHeaders;
  UINT32                    CheckSum;
  UINT16                    Subsystem;
  UINT16                    DllCharacteristics;
  UINT64                    SizeOfStackReserve;
  UINT64                    SizeOfStackCommit;
  UINT64                    SizeOfHeapReserve;
  UINT64                    SizeOfHeapCommit;
  UINT32                    LoaderFlags;
  UINT32                    NumberOfRvaAndSizes;
  EFI_IMAGE_DATA_DIRECTORY  DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER64;

//PE32+ image header
typedef struct {
  UINT32                      Signature;
  EFI_IMAGE_FILE_HEADER       FileHeader;
  EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} EFI_IMAGE_NT_HEADERS64;


// Section Table. This table immediately follows the optional header.
typedef struct _EFI_IMAGE_SECTION_HEADER {
    UINT8 Name[8];
    union {
        UINT32  PhysicalAddress;
        UINT32  VirtualSize;
    } Misc;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} EFI_IMAGE_SECTION_HEADER;

// Header format for TE images, defined in the PI Specification 1.0.
typedef struct {
    UINT16                    Signature;            // The signature for TE format = "VZ"
    UINT16                    Machine;              // From original file header
    UINT8                     NumberOfSections;     // From original file header
    UINT8                     Subsystem;            // From original optional header
    UINT16                    StrippedSize;         // Number of bytes we removed from header
    UINT32                    AddressOfEntryPoint;  // Offset to entry point -- from original optional header
    UINT32                    BaseOfCode;           // From original image -- required for ITP debug
    UINT64                    ImageBase;            // From original file header (ORLY?)
    EFI_IMAGE_DATA_DIRECTORY  DataDirectory[2];     // Only base relocation and debug directories
} EFI_IMAGE_TE_HEADER;

// Data directory indexes in TE image header
#define EFI_IMAGE_TE_DIRECTORY_ENTRY_BASERELOC  0
#define EFI_IMAGE_TE_DIRECTORY_ENTRY_DEBUG      1

// Return values
#define ERR_SUCCESS 0
#define ERR_OUT_OF_MEMORY 1
#define ERR_INVALID_PARAMETER 2
#define ERR_INVALID_IMAGE 3
#define ERR_FILE_OPEN 4
#define ERR_FILE_READ 5
#define ERR_FILE_CREATE 6
#define ERR_FILE_WRITE 7

#pragma pack(pop)

// DOS header
static EFI_IMAGE_DOS_HEADER DosHeader = { 0 };

// PE header
static EFI_IMAGE_NT_HEADERS32 PeHeader = { 0 };

// PE32+ header
static EFI_IMAGE_NT_HEADERS64 PePlusHeader = { 0 };

//32bit convert
UINT8 convert32(UINT8* te, UINTN teSize, UINT8** peOut, UINTN* peOutSize)
{
    UINTN  i;
    UINT8* pe;
    UINTN  peSize;
    EFI_IMAGE_TE_HEADER* teHeader;
    EFI_IMAGE_SECTION_HEADER* sectionHeader;
    int is64 = 0;

    // Check arguments for sanity
    if (!te || teSize <= sizeof(EFI_IMAGE_TE_HEADER) || !peOut || !peOutSize) {
        printf("convert: called with invalid parameter\n");
        return ERR_INVALID_PARAMETER;
    }
    
    // Check TE header to be valid and remove it from the input
    teHeader = (EFI_IMAGE_TE_HEADER*) te;
    te += sizeof(EFI_IMAGE_TE_HEADER);
    teSize -= sizeof(EFI_IMAGE_TE_HEADER);

    if (teHeader->Signature != EFI_IMAGE_TE_SIGNATURE) {
        printf("convert: TE signature not found. Not a TE image, maybe?\n");
        return ERR_INVALID_IMAGE;
    }

    // Calculate PE image size
    peSize = teHeader->StrippedSize + teSize;

    // Start filling DosHeader and PeHeader based on current TE header
    DosHeader.e_magic = EFI_IMAGE_DOS_SIGNATURE;
    PeHeader.Signature = EFI_IMAGE_PE_SIGNATURE;
    PeHeader.FileHeader.Machine = teHeader->Machine;
    PeHeader.FileHeader.NumberOfSections = teHeader->NumberOfSections;
    PeHeader.FileHeader.SizeOfOptionalHeader = sizeof(EFI_IMAGE_OPTIONAL_HEADER32);
    PeHeader.FileHeader.Characteristics = 0x210E;
    PeHeader.OptionalHeader.Magic = EFI_IMAGE_PE_OPTIONAL_HDR32_MAGIC;
    PeHeader.OptionalHeader.AddressOfEntryPoint = teHeader->AddressOfEntryPoint;
    PeHeader.OptionalHeader.BaseOfCode = teHeader->BaseOfCode;
    PeHeader.OptionalHeader.ImageBase = (UINT32)teHeader->ImageBase - teHeader->StrippedSize + sizeof(EFI_IMAGE_TE_HEADER);
    PeHeader.OptionalHeader.SectionAlignment = 0x10;
    PeHeader.OptionalHeader.FileAlignment = 0x10;
    PeHeader.OptionalHeader.SizeOfImage = peSize;
    PeHeader.OptionalHeader.Subsystem = teHeader->Subsystem;
    PeHeader.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
    PeHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = teHeader->DataDirectory[0].VirtualAddress;
    PeHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = teHeader->DataDirectory[0].Size;
    PeHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = teHeader->DataDirectory[1].VirtualAddress;
    PeHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size = teHeader->DataDirectory[1].Size;
    // Not filled are e_lfanew, SizeOfHeaders, SizeOfCode, SizeOfInitData, SizeOfUninitData, BaseOfData

    // Parse sections to determine unfilled elements
    sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(teHeader + 1);
    // Fill size of headers based on the first section offset
    PeHeader.OptionalHeader.SizeOfHeaders = sectionHeader->PointerToRawData;

    for (i = 0; i < teHeader->NumberOfSections; i++, sectionHeader++) {
        // Try code section
        if (!strncmp(sectionHeader->Name, ".text", sizeof(sectionHeader->Name))) {
            // Check code section sanity
            if (sectionHeader->PointerToRawData != teHeader->BaseOfCode) {
                printf("convert: .text->PointerToRawData (%08Xh) != BaseOfCode (%08Xh). Invalid TE image?\n", sectionHeader->PointerToRawData, teHeader->BaseOfCode);
                return ERR_INVALID_IMAGE;
            }

            PeHeader.OptionalHeader.SizeOfCode = sectionHeader->SizeOfRawData;
        }
        // Try initialized data section
        else if (!strncmp(sectionHeader->Name, ".data", sizeof(sectionHeader->Name))) {
            PeHeader.OptionalHeader.BaseOfData = sectionHeader->PointerToRawData;
            PeHeader.OptionalHeader.SizeOfInitializedData = sectionHeader->SizeOfRawData;
        }
        // Try uninitialized data section
        else if (!strncmp(sectionHeader->Name, ".rdata", sizeof(sectionHeader->Name))) {
            PeHeader.OptionalHeader.SizeOfUninitializedData = sectionHeader->SizeOfRawData;
        }
        // Try relocation section
        else if (!strncmp(sectionHeader->Name, ".reloc", sizeof(sectionHeader->Name))) {
            //TODO: add more sanity checks in case of incorrect images
        }
        else {
            UINT8 name[sizeof(sectionHeader->Name) + 1];
            name[sizeof(sectionHeader->Name)] = 0; // Ensure trailing zero
            memcpy(name, sectionHeader->Name, sizeof(sectionHeader->Name));
            printf("convert: unknown section \"%s\" found in TE image\n", name);
        }
    }

    // Calculate e_lfanew
    DosHeader.e_lfanew = teHeader->StrippedSize - sizeof(EFI_IMAGE_NT_HEADERS32);

    // Allocate buffer for PE image
    pe = (UINT8*)malloc(peSize);
    if (!pe) {
        printf("convert: failed to allocate enough memory for PE image\n");
        return ERR_OUT_OF_MEMORY;
    }
    // Zero allocated memory
    memset(pe, 0, peSize);

    // Copy filled data into newly allocated buffer
    memcpy(pe, &DosHeader, sizeof(EFI_IMAGE_DOS_HEADER));
    memcpy(pe + DosHeader.e_lfanew, &PeHeader, sizeof(EFI_IMAGE_NT_HEADERS32));
    memcpy(pe + teHeader->StrippedSize, te, teSize);

    // Fill output parameters
    *peOut = pe;
    *peOutSize = peSize;

    return ERR_SUCCESS;
}

//64bit convert
UINT8 convert64(UINT8* te, UINTN teSize, UINT8** peOut, UINTN* peOutSize)
{
    UINTN  i;
    UINT8* pe;
    UINTN  peSize;
    EFI_IMAGE_TE_HEADER* teHeader;
    EFI_IMAGE_SECTION_HEADER* sectionHeader;

    // Check arguments for sanity
    if (!te || teSize <= sizeof(EFI_IMAGE_TE_HEADER) || !peOut || !peOutSize) {
        printf("convert64: called with invalid parameter\n");
        return ERR_INVALID_PARAMETER;
    }
    
    // Check TE header to be valid and remove it from the input
    teHeader = (EFI_IMAGE_TE_HEADER*) te;
    te += sizeof(EFI_IMAGE_TE_HEADER);
    teSize -= sizeof(EFI_IMAGE_TE_HEADER);

    if (teHeader->Signature != EFI_IMAGE_TE_SIGNATURE) {
        printf("convert64: TE signature not found. Not a TE image, maybe?\n");
        return ERR_INVALID_IMAGE;
    }

    // Calculate PE image size
    peSize = teHeader->StrippedSize + teSize;

    // Start filling DosHeader and PeHeader based on current TE header
    DosHeader.e_magic = EFI_IMAGE_DOS_SIGNATURE;
    PePlusHeader.Signature = EFI_IMAGE_PE_SIGNATURE;
    PePlusHeader.FileHeader.Machine = teHeader->Machine;
    PePlusHeader.FileHeader.NumberOfSections = teHeader->NumberOfSections;
    PePlusHeader.FileHeader.SizeOfOptionalHeader = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
    PePlusHeader.FileHeader.Characteristics = 0x002E;
    PePlusHeader.OptionalHeader.Magic = EFI_IMAGE_PE_OPTIONAL_HDR64_MAGIC;
    PePlusHeader.OptionalHeader.AddressOfEntryPoint = teHeader->AddressOfEntryPoint;
    PePlusHeader.OptionalHeader.BaseOfCode = teHeader->BaseOfCode;
    PePlusHeader.OptionalHeader.ImageBase = teHeader->ImageBase;
    PePlusHeader.OptionalHeader.SectionAlignment = 0x1000;
    PePlusHeader.OptionalHeader.FileAlignment = 0x1000;
    PePlusHeader.OptionalHeader.SizeOfImage = peSize;
    PePlusHeader.OptionalHeader.Subsystem = teHeader->Subsystem;
    PePlusHeader.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
    PePlusHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = teHeader->DataDirectory[0].VirtualAddress;
    PePlusHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = teHeader->DataDirectory[0].Size;
    PePlusHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = teHeader->DataDirectory[1].VirtualAddress;
    PePlusHeader.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size = teHeader->DataDirectory[1].Size;
    // Not filled are e_lfanew, SizeOfHeaders, SizeOfCode, SizeOfInitData, SizeOfUninitData

    // Parse sections to determine unfilled elements
    sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(teHeader + 1);
    // Fill size of headers based on the first section offset
    PePlusHeader.OptionalHeader.SizeOfHeaders = sectionHeader->PointerToRawData;

    for (i = 0; i < teHeader->NumberOfSections; i++, sectionHeader++) {
        // Try code section
        if (!strncmp(sectionHeader->Name, ".text", sizeof(sectionHeader->Name))) {
            // Check code section sanity
            if (sectionHeader->PointerToRawData != teHeader->BaseOfCode) {
                printf("convert64: .text->PointerToRawData (%08Xh) != BaseOfCode (%08Xh). Invalid TE image?\n", sectionHeader->PointerToRawData, teHeader->BaseOfCode);
                return ERR_INVALID_IMAGE;
            }

            PePlusHeader.OptionalHeader.SizeOfCode = sectionHeader->SizeOfRawData;
        }
        // Try initialized data section
        else if (!strncmp(sectionHeader->Name, ".data", sizeof(sectionHeader->Name))) {
            PePlusHeader.OptionalHeader.SizeOfInitializedData = sectionHeader->SizeOfRawData;
        }
        // Try uninitialized data section
        else if (!strncmp(sectionHeader->Name, ".rdata", sizeof(sectionHeader->Name))) {
            PePlusHeader.OptionalHeader.SizeOfUninitializedData = sectionHeader->SizeOfRawData;
        }
        // Try relocation section
        else if (!strncmp(sectionHeader->Name, ".reloc", sizeof(sectionHeader->Name))) {
            //TODO: add more sanity checks in case of incorrect images
        }
        else {
            UINT8 name[sizeof(sectionHeader->Name) + 1];
            name[sizeof(sectionHeader->Name)] = 0; // Ensure trailing zero
            memcpy(name, sectionHeader->Name, sizeof(sectionHeader->Name));
            printf("convert64: unknown section \"%s\" found in TE image\n", name);
        }
    }

    // Calculate e_lfanew
    DosHeader.e_lfanew = teHeader->StrippedSize - sizeof(EFI_IMAGE_NT_HEADERS64);

    // Allocate buffer for PE image
    pe = (UINT8*)malloc(peSize);
    if (!pe) {
        printf("convert64: failed to allocate enough memory for PE image\n");
        return ERR_OUT_OF_MEMORY;
    }
    // Zero allocated memory
    memset(pe, 0, peSize);

    // Copy filled data into newly allocated buffer
    memcpy(pe, &DosHeader, sizeof(EFI_IMAGE_DOS_HEADER));
    memcpy(pe + DosHeader.e_lfanew, &PePlusHeader, sizeof(EFI_IMAGE_NT_HEADERS64));
    memcpy(pe + teHeader->StrippedSize, te, teSize);

    // Fill output parameters
    *peOut = pe;
    *peOutSize = peSize;

    return ERR_SUCCESS;
}

// Convert function
UINT8 convert(UINT8* te, UINTN teSize, UINT8** peOut, UINTN* peOutSize)
{
    EFI_IMAGE_TE_HEADER* teHeader;

    // Check arguments for sanity
    if (!te || teSize <= sizeof(EFI_IMAGE_TE_HEADER) || !peOut || !peOutSize) {
        printf("convert: called with invalid parameter\n");
        return ERR_INVALID_PARAMETER;
    }
    
    // Check TE header to be valid and remove it from the input
    teHeader = (EFI_IMAGE_TE_HEADER*) te;

    if (teHeader->Signature != EFI_IMAGE_TE_SIGNATURE) {
        printf("convert: TE signature not found. Not a TE image, maybe?\n");
        return ERR_INVALID_IMAGE;
    }

    switch(teHeader->Machine)
    {
        case IMAGE_FILE_MACHINE_I386:
        //add more 32-bit machines here
            return convert32(te, teSize, peOut, peOutSize);
        case IMAGE_FILE_MACHINE_ARM64:
        //add more 64-bit machines here
            return convert64(te, teSize, peOut, peOutSize);
        default:
            printf("convert: unsupported Machine %04X\n", teHeader->Machine);
            return ERR_INVALID_IMAGE;
    }
}

// Main
int main(int argc, char* argv[])
{
    FILE*  file;
    UINT8* buffer;
    UINT8* image;
    UINTN  filesize;
    UINTN  imagesize;
    UINTN  read;
    UINT8  status;

    // Check arguments count
    if (argc != 3) {
        // Print usage and exit
        printf("TE2PE v0.1.2 - converts Terse Executable image into PE32(+) image\n\n"
               "Usage: TE2PE te.bin pe.bin\n");
        return ERR_INVALID_PARAMETER;
    }

    // Read input file
    file = fopen(argv[1], "rb");
    if (!file) {
        printf("Can't open input file\n");
        return ERR_FILE_OPEN;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    buffer = (UINT8*)malloc(filesize);
    if (!buffer) {
        printf("Can't allocate memory for input file\n");
        return ERR_OUT_OF_MEMORY;
    }

    // Read the whole file into buffer
    read = fread((VOID*)buffer, 1, filesize, file);
    if (read != filesize) {
        printf("Can't read input file\n");
        return ERR_FILE_READ;
    }
    
    // Close input file
    fclose(file);

    // Call conversion routine
    status = convert(buffer, filesize, &image, &imagesize);
    if (status)
        return status;
    
    // Create output file
    file = fopen(argv[2], "wb");
    if (!file) {
        printf("Can't create output file\n");
        return ERR_FILE_CREATE;
    }
    
    // Write converted image
    if (fwrite(image, 1, imagesize, file) != imagesize)
    {
        printf("Can't write to output file\n");
        return ERR_FILE_WRITE;
    }

    // Close output file 
    fclose(file);

    return ERR_SUCCESS;
}
