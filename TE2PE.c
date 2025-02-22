/*
Copyright 2025 Nikolaj Schlej

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#define UINTN  unsigned long
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

// PE32 image header
typedef struct _EFI_IMAGE_PE_HEADER {
    UINT32 Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} EFI_IMAGE_PE_HEADER;

// PE32 image header
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

// DOS header
static EFI_IMAGE_DOS_HEADER DosHeader = { 0 };

// PE header
static EFI_IMAGE_PE_HEADERS PeHeader = { 0 };

// Convert function
UINT8 convert(UINT8* te, UINTN teSize, UINT8** peOut, UINTN* peOutSize, char apply_fixup)
{
    UINTN  i;
    UINT8* pe;
    UINTN  peSize;
    EFI_IMAGE_TE_HEADER* teHeader;
    EFI_IMAGE_SECTION_HEADER* sectionHeader;
    UINT32 SectionsCount = 0;
    UINT32 ConvSize = 0;
    unsigned char Is64Bit = 0;

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
    switch (teHeader->Machine) {
        case IMAGE_FILE_MACHINE_ARM:
        case IMAGE_FILE_MACHINE_THUMB:
        case IMAGE_FILE_MACHINE_ARMV7:
        case IMAGE_FILE_MACHINE_I386:
            Is64Bit = 0;

            PeHeader.Header32.Signature = EFI_IMAGE_PE_SIGNATURE;
            PeHeader.Header32.FileHeader.Machine = teHeader->Machine;
            PeHeader.Header32.FileHeader.NumberOfSections = teHeader->NumberOfSections;
            PeHeader.Header32.FileHeader.SizeOfOptionalHeader = sizeof(EFI_IMAGE_OPTIONAL_HEADER32);
            PeHeader.Header32.FileHeader.Characteristics = 0x210E;
            PeHeader.Header32.OptionalHeader.Magic = EFI_IMAGE_PE_OPTIONAL_HDR32_MAGIC;
            PeHeader.Header32.OptionalHeader.AddressOfEntryPoint = teHeader->AddressOfEntryPoint;
            PeHeader.Header32.OptionalHeader.BaseOfCode = teHeader->BaseOfCode;
            if (apply_fixup) PeHeader.Header32.OptionalHeader.ImageBase = (UINT32)(teHeader->ImageBase - teHeader->StrippedSize + sizeof(EFI_IMAGE_TE_HEADER));
            else             PeHeader.Header32.OptionalHeader.ImageBase = (UINT32)(teHeader->ImageBase);
            PeHeader.Header32.OptionalHeader.SectionAlignment = 0x10;
            PeHeader.Header32.OptionalHeader.FileAlignment = 0x10;
            PeHeader.Header32.OptionalHeader.SizeOfImage = (UINT32)peSize;
            PeHeader.Header32.OptionalHeader.Subsystem = teHeader->Subsystem;
            PeHeader.Header32.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
            PeHeader.Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = teHeader->DataDirectory[0].VirtualAddress;
            PeHeader.Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = teHeader->DataDirectory[0].Size;
            PeHeader.Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = teHeader->DataDirectory[1].VirtualAddress;
            PeHeader.Header32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size = teHeader->DataDirectory[1].Size;
            break;

        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_IA64:
        case IMAGE_FILE_MACHINE_ARM64:
            Is64Bit = 1;

            PeHeader.Header64.Signature = EFI_IMAGE_PE_SIGNATURE;
            PeHeader.Header64.FileHeader.Machine = teHeader->Machine;
            PeHeader.Header64.FileHeader.NumberOfSections = teHeader->NumberOfSections;
            PeHeader.Header64.FileHeader.SizeOfOptionalHeader = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
            PeHeader.Header64.FileHeader.Characteristics = 0x210E;
            PeHeader.Header64.OptionalHeader.Magic = EFI_IMAGE_PE_OPTIONAL_HDR64_MAGIC;
            PeHeader.Header64.OptionalHeader.AddressOfEntryPoint = teHeader->AddressOfEntryPoint;
            PeHeader.Header64.OptionalHeader.BaseOfCode = teHeader->BaseOfCode;
            if (apply_fixup) PeHeader.Header64.OptionalHeader.ImageBase = teHeader->ImageBase - teHeader->StrippedSize + sizeof(EFI_IMAGE_TE_HEADER);
            else             PeHeader.Header64.OptionalHeader.ImageBase = teHeader->ImageBase;
            PeHeader.Header64.OptionalHeader.SectionAlignment = 0x10;
            PeHeader.Header64.OptionalHeader.FileAlignment = 0x10;
            PeHeader.Header64.OptionalHeader.SizeOfImage = (UINT32)peSize;
            PeHeader.Header64.OptionalHeader.Subsystem = teHeader->Subsystem;
            PeHeader.Header64.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
            PeHeader.Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = teHeader->DataDirectory[0].VirtualAddress;
            PeHeader.Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = teHeader->DataDirectory[0].Size;
            PeHeader.Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = teHeader->DataDirectory[1].VirtualAddress;
            PeHeader.Header64.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size = teHeader->DataDirectory[1].Size;
            break;

        default:
            printf("ERROR: Invalid or unknown PE Optional Header Magic\n");
            return ERR_INVALID_IMAGE;
    }
    
    // Not filled are e_lfanew, SizeOfHeaders, SizeOfCode, SizeOfInitData, SizeOfUninitData, BaseOfData

    // Parse sections to determine unfilled elements
    sectionHeader = (EFI_IMAGE_SECTION_HEADER*)(teHeader + 1);
    // Fill size of headers based on the first section offset
    if (Is64Bit) {
        PeHeader.Header64.OptionalHeader.SizeOfHeaders = sectionHeader->PointerToRawData;
    } else {
        PeHeader.Header32.OptionalHeader.SizeOfHeaders = sectionHeader->PointerToRawData;
    }

    SectionsCount = teHeader->NumberOfSections;
    for (i = 0; i < SectionsCount; i++, sectionHeader++)
    {
        // Try code section
        if (!strncmp((char *)sectionHeader->Name, ".text", sizeof(sectionHeader->Name))) {
            // Check code section sanity
            if (sectionHeader->PointerToRawData != teHeader->BaseOfCode) {
                printf("convert: .text->PointerToRawData (%08Xh) != BaseOfCode (%08Xh). Invalid TE image?\n", sectionHeader->PointerToRawData, teHeader->BaseOfCode);
                return ERR_INVALID_IMAGE;
            }

            if (Is64Bit) {
                PeHeader.Header64.OptionalHeader.SizeOfCode = sectionHeader->SizeOfRawData;
            } else {
                PeHeader.Header32.OptionalHeader.SizeOfCode = sectionHeader->SizeOfRawData;
            }
        }
        // Try initialized data section
        else if (!strncmp((char *)sectionHeader->Name, ".data", sizeof(sectionHeader->Name))) {
            if (Is64Bit == 0) {
                PeHeader.Header32.OptionalHeader.BaseOfData = sectionHeader->PointerToRawData;
                PeHeader.Header32.OptionalHeader.SizeOfInitializedData = sectionHeader->SizeOfRawData;
            } else {
                PeHeader.Header64.OptionalHeader.SizeOfInitializedData = sectionHeader->SizeOfRawData;
            }
        }
        // Try uninitialized data section
        else if (!strncmp((char *)sectionHeader->Name, ".rdata", sizeof(sectionHeader->Name))) {
            if (Is64Bit) {
                PeHeader.Header64.OptionalHeader.SizeOfUninitializedData = sectionHeader->SizeOfRawData;
            } else {
                PeHeader.Header32.OptionalHeader.SizeOfUninitializedData = sectionHeader->SizeOfRawData;
            }
        }
        // Try relocation section
        else if (!strncmp((char *)sectionHeader->Name, ".reloc", sizeof(sectionHeader->Name))) {
            //TODO: add more sanity checks in case of incorrect images
        }
        // Try relocation section
        else if (!strncmp((char *)sectionHeader->Name, ".debug", sizeof(sectionHeader->Name))) {
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
    if (Is64Bit) {
        DosHeader.e_lfanew = teHeader->StrippedSize - sizeof(EFI_IMAGE_PEPLUS_HEADER);
    } else {
        DosHeader.e_lfanew = teHeader->StrippedSize - sizeof(EFI_IMAGE_PE_HEADER);
    }

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

    if (Is64Bit) {
        memcpy(pe + DosHeader.e_lfanew, &PeHeader, sizeof(EFI_IMAGE_PEPLUS_HEADER));
    } else {
        memcpy(pe + DosHeader.e_lfanew, &PeHeader, sizeof(EFI_IMAGE_PE_HEADER));
    }

    memcpy(pe + teHeader->StrippedSize, te, teSize);

    // Fill output parameters
    *peOut = pe;
    *peOutSize = peSize;

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
    char   opt_fixup = 0;
    const char* infile = NULL;
    const char* outfile = NULL;

    // Check options
    if (argc >= 2 && (memcmp(argv[1], "-f", 3) == 0 || memcmp(argv[1], "-fixup", 7) == 0)) {
        opt_fixup = 1;
    }
    
    // Check arguments count
    if ((opt_fixup && argc !=4) || (!opt_fixup && argc !=3)) {
        // Print usage and exit
        printf("TE2PE v0.1.4 - converts Terse Executable image file into PE32 image file\n\n"
               "Usage: TE2PE [-f] te_file.bin pe_file.bin\n"
               "Options: -f, --fixup    Apply TE image base fix-up for PE image entry point\n"
               "                        The fixup is required for certain TE images\n"
               "                        extracted from AMI AptioV-based UEFI binaries\n"
               "                        Try this option if the resulting PE image\n"
               "                        appears to have incorrect entry point offset\n");
        return ERR_INVALID_PARAMETER;
    }

    // Set infile and outfile
    if (opt_fixup) {
        infile = argv[2];
        outfile = argv[3];
    }
    else {
        infile = argv[1];
        outfile = argv[2];
    }
    
    // Read input file
    file = fopen(infile, "rb");
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
    status = convert(buffer, filesize, &image, &imagesize, opt_fixup);
    if (status)
        return status;
    
    // Create output file
    file = fopen(outfile, "wb");
    if (!file) {
        printf("Can't create output file\n");
        return ERR_FILE_CREATE;
    }
    
    // Write converted image
    if (fwrite(image, 1, imagesize, file) != imagesize) {
        printf("Can't write to output file\n");
        return ERR_FILE_WRITE;
    }

    // Close output file 
    fclose(file);

    return ERR_SUCCESS;
}
