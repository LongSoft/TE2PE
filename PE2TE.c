// Converts Terse Executable (TE) image to PE32 image
// Author: Nikolaj Schlej aka CodeRush
// License: WTFPL2 (http://wtfpl2.com/)

// I don't know any machine with 64-bit PEI, so only 32-bit images are supported right now
// If you've found 64-bit TE file, please open the issue on project's GitHub repo

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

// Only I386 images are supported now
#define IMAGE_FILE_MACHINE_UNKNOWN   0
#define IMAGE_FILE_MACHINE_I386      0x014c
#define IMAGE_FILE_MACHINE_IA64      0x0200
#define IMAGE_FILE_MACHINE_AMD64     0x8664
#define IMAGE_FILE_MACHINE_ARM       0x01c0
#define IMAGE_FILE_MACHINE_THUMB     0x01c2
#define IMAGE_FILE_MACHINE_ARMV7     0x01c4
#define IMAGE_FILE_MACHINE_ARM64     0xAA64
#define IMAGE_FILE_MACHINE_POWERPC   0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1

#define EFI_IMAGE_DOS_SIGNATURE     0x5A4D     // MZ
#define EFI_IMAGE_PE_SIGNATURE      0x00004550 // PE
#define EFI_IMAGE_TE_SIGNATURE      0x5A56     // VZ

#define EFI_IMAGE_PE_OPTIONAL_HDR32_MAGIC 0x10b
#define EFI_IMAGE_PE_OPTIONAL_HDR64_MAGIC 0x20b

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

#ifndef SWAP32
#define SWAP32(V) ((((UINT32)(V) & 0xff) << 24) | (((UINT32)(V) & 0xff00) << 8) | (((UINT32)(V) & 0xff0000) >> 8) |  (((UINT32)(V) & 0xff000000) >> 24))
#endif /* SWAP32 */

// Optional Header Standard Fields for PE32+
typedef struct _EFI_IMAGE_OPTIONAL_HEADER64 {
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
    // Optional Header Windows-Specific Fields.
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
typedef struct _EFI_IMAGE_PE_HEADER {
    UINT32 Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} EFI_IMAGE_PE_HEADER;

typedef struct _EFI_IMAGE_PEPLUS_HEADER {
    UINT32 Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} EFI_IMAGE_PEPLUS_HEADER;

typedef union _EFI_IMAGE_PE_HEADERS {
    EFI_IMAGE_PE_HEADER Header32;
    EFI_IMAGE_PEPLUS_HEADER Header64;
} EFI_IMAGE_PE_HEADERS;

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

uint64_t
rnd(
    uint64_t v,
    uint64_t r)
{
    r--;
    v += r;
    v &= ~(int64_t)r;
    return(v);
}

// TE header
static EFI_IMAGE_TE_HEADER TeHeader = { 0 };

// Convert function
UINT8 convert(UINT8* pe, UINTN peSize, UINT8** teOut, UINTN* teOutSize)
{
    UINTN  i;
    UINT8* te;
    UINTN  teSize;
    EFI_IMAGE_DOS_HEADER* peDosHeader;
    EFI_IMAGE_PE_HEADERS* PeHeader;
    EFI_IMAGE_SECTION_HEADER* sectionHeader;
    UINT8* pe_start=pe;
    UINTN  pe_startSize = peSize;
    UINT8 Is64Bit = 0;

    // Check arguments for sanity
    if (!pe || peSize <= (sizeof(EFI_IMAGE_DOS_HEADER) + sizeof(EFI_IMAGE_PE_HEADER)) || !teOut || !teOutSize) {
        printf("convert: called with invalid parameter\n");
        return ERR_INVALID_PARAMETER;
    }
    
    // Check TE header to be valid and remove it from the input
    peDosHeader = (EFI_IMAGE_DOS_HEADER*) pe;
    pe += peDosHeader->e_lfanew;
    peSize -= peDosHeader->e_lfanew;
    PeHeader = (EFI_IMAGE_PE_HEADERS*) pe;
    if (PeHeader->Header32.Signature != EFI_IMAGE_PE_SIGNATURE) {
        printf("convert: PE signature not found. Not a PE image, maybe?\n");
        return ERR_INVALID_IMAGE;
    }

    if (PeHeader->Header32.OptionalHeader.Magic == EFI_IMAGE_PE_OPTIONAL_HDR32_MAGIC)
    {
        Is64Bit = 0;
        pe += sizeof(EFI_IMAGE_PE_HEADER);
        peSize -= sizeof(EFI_IMAGE_PE_HEADER);

        TeHeader.StrippedSize = sizeof(EFI_IMAGE_TE_HEADER);
    } else if (PeHeader->Header64.OptionalHeader.Magic == EFI_IMAGE_PE_OPTIONAL_HDR64_MAGIC) {
        Is64Bit = 1;
        pe += sizeof(EFI_IMAGE_PEPLUS_HEADER);
        peSize -= sizeof(EFI_IMAGE_PEPLUS_HEADER);

        TeHeader.StrippedSize = sizeof(EFI_IMAGE_TE_HEADER);
    } else {
        printf("convert: PE optional header magic 0x%x invalid.\n", PeHeader->Header32.OptionalHeader.Magic);
        return ERR_INVALID_IMAGE;
    }

    // Calculate TE image size
    teSize = peSize;

    // Start filling DosHeader and PeHeader based on current TE header
    TeHeader.Signature = EFI_IMAGE_TE_SIGNATURE;
    TeHeader.Machine = PeHeader->Header32.FileHeader.Machine;
    TeHeader.NumberOfSections = (uint8_t)PeHeader->Header32.FileHeader.NumberOfSections;

    if (Is64Bit)
    {
        TeHeader.AddressOfEntryPoint = PeHeader->Header64.OptionalHeader.AddressOfEntryPoint;
        TeHeader.BaseOfCode = PeHeader->Header64.OptionalHeader.BaseOfCode;
        TeHeader.ImageBase = PeHeader->Header64.OptionalHeader.ImageBase;
        TeHeader.Subsystem = PeHeader->Header64.OptionalHeader.Subsystem;
        TeHeader.DataDirectory[0].VirtualAddress = PeHeader->Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        TeHeader.DataDirectory[0].Size = PeHeader->Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        TeHeader.DataDirectory[1].VirtualAddress = PeHeader->Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        TeHeader.DataDirectory[1].Size = PeHeader->Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        TeHeader.AddressOfEntryPoint = PeHeader->Header64.OptionalHeader.AddressOfEntryPoint;
    } else {
        TeHeader.AddressOfEntryPoint = PeHeader->Header32.OptionalHeader.AddressOfEntryPoint;
        TeHeader.BaseOfCode = PeHeader->Header32.OptionalHeader.BaseOfCode;
        TeHeader.ImageBase = PeHeader->Header32.OptionalHeader.ImageBase;
        TeHeader.Subsystem = PeHeader->Header32.OptionalHeader.Subsystem;
        TeHeader.DataDirectory[0].VirtualAddress = PeHeader->Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        TeHeader.DataDirectory[0].Size = PeHeader->Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        TeHeader.DataDirectory[1].VirtualAddress = PeHeader->Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        TeHeader.DataDirectory[1].Size = PeHeader->Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        TeHeader.AddressOfEntryPoint = PeHeader->Header32.OptionalHeader.AddressOfEntryPoint;
    }

    // Not filled are e_lfanew, SizeOfHeaders, SizeOfCode, SizeOfInitData, SizeOfUninitData, BaseOfData

    // Parse sections to determine unfilled elements
    if (Is64Bit)
    {
        sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(pe);
    } else {
        sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(pe);
    }

    for (i = 0; i < PeHeader->Header32.FileHeader.NumberOfSections; i++, sectionHeader++) {
        // Try code section
        if (!strncmp((char *)sectionHeader->Name, ".text", sizeof(sectionHeader->Name))) {
            // Check code section sanity
            if (Is64Bit)
            {
                if (sectionHeader->PointerToRawData != PeHeader->Header64.OptionalHeader.BaseOfCode) {
                    printf("convert: .text->PointerToRawData (%08Xh) != BaseOfCode (%08Xh). Invalid PE image?\n", sectionHeader->PointerToRawData, PeHeader->Header64.OptionalHeader.BaseOfCode);
                    return ERR_INVALID_IMAGE;
                }
            } else {
                if (sectionHeader->PointerToRawData != PeHeader->Header32.OptionalHeader.BaseOfCode) {
                    printf("convert: .text->PointerToRawData (%08Xh) != BaseOfCode (%08Xh). Invalid PE image?\n", sectionHeader->PointerToRawData, PeHeader->Header32.OptionalHeader.BaseOfCode);
                    return ERR_INVALID_IMAGE;
                }
            }

            TeHeader.BaseOfCode = sectionHeader->PointerToRawData;
        }
        // Try initialized data section
        else if (!strncmp((char *)sectionHeader->Name, ".data", sizeof(sectionHeader->Name))) {
            if (Is64Bit == 0)
            {
                if (sectionHeader->PointerToRawData != PeHeader->Header32.OptionalHeader.BaseOfData) {
                    printf("convert: .data->PointerToRawData (%08Xh) != BaseOfData (%08Xh). Invalid PE image?\n", sectionHeader->PointerToRawData, PeHeader->Header32.OptionalHeader.BaseOfData);
                    return ERR_INVALID_IMAGE;
                }
            }
        }
        // Try uninitialized data section
        else if (!strncmp((char *)sectionHeader->Name, ".rdata", sizeof(sectionHeader->Name))) {
        }
        // Try relocation section
        else if (!strncmp((char *)sectionHeader->Name, ".reloc", sizeof(sectionHeader->Name))) {
        }
        // Try relocation section
        else if (!strncmp((char *)sectionHeader->Name, ".debug", sizeof(sectionHeader->Name))) {
        }
        else {
            UINT8 name[sizeof(sectionHeader->Name) + 1];
            name[sizeof(sectionHeader->Name)] = 0; // Ensure trailing zero
            memcpy(name, sectionHeader->Name, sizeof(sectionHeader->Name));
            printf("convert: unknown section \"%s\" found in PE image\n", name);
        }
    }

    // Allocate buffer for PE image
    te = (UINT8*)malloc(pe_startSize);
    if (!te) {
        printf("convert: failed to allocate enough memory for PE image\n");
        return ERR_OUT_OF_MEMORY;
    }
    // Zero allocated memory
    memset(te, 0, pe_startSize);

    // Copy filled data into newly allocated buffer
    memcpy(te, &TeHeader, sizeof(EFI_IMAGE_TE_HEADER));

    // Parse sections to determine unfilled elements
    if (Is64Bit)
    {
        sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(pe);
    } else {
        sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(pe);
    }

    for (i = 0; i < PeHeader->Header32.FileHeader.NumberOfSections; i++, sectionHeader++) {
        memcpy(te + sizeof(EFI_IMAGE_TE_HEADER) + (i * sizeof(EFI_IMAGE_SECTION_HEADER)), sectionHeader, sizeof(EFI_IMAGE_SECTION_HEADER));
    }

    if (Is64Bit)
    {
        memcpy(te + PeHeader->Header64.OptionalHeader.SizeOfHeaders, pe_start + PeHeader->Header64.OptionalHeader.SizeOfHeaders, (pe_startSize - PeHeader->Header64.OptionalHeader.SizeOfHeaders));
    } else {
        memcpy(te + PeHeader->Header32.OptionalHeader.SizeOfHeaders, pe_start + PeHeader->Header32.OptionalHeader.SizeOfHeaders, (pe_startSize - PeHeader->Header32.OptionalHeader.SizeOfHeaders));
    }

    // Fill output parameters
    *teOut = te;
    *teOutSize = pe_startSize;

    return ERR_SUCCESS;
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
        printf("PE2TE v0.1.1 - converts PE32 image into Terse Executable image\n\n"
               "Usage: PE2TE pe.bin te.bin\n");
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
