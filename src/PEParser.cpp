#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <strsafe.h>

HANDLE GetFileContent(const char* lpFilePath) {
    const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] An error occurred while opening the file: %d", GetLastError());
        CloseHandle(hFile);
        return nullptr;
    }
    const DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if (dwFileSize == INVALID_FILE_SIZE) {
        printf("[-] An error occurred while getting the file size: %d", GetLastError());
        CloseHandle(hFile);
        return nullptr;
    }

    const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
    if (hFileContent == INVALID_HANDLE_VALUE) {
        printf("[-] An error occurred while allocating memory for the file content: %d", GetLastError());
        CloseHandle(hFile);
        if (hFileContent != nullptr) {
            HeapFree(GetProcessHeap(), 0, hFileContent);
            CloseHandle(hFileContent);
        }
        return nullptr;
    }

    const BOOL bReadFile = ReadFile(hFile, hFileContent, dwFileSize, nullptr, nullptr);
    if (!bReadFile) {
        printf("[-] An error occurred while reading the file: %d", GetLastError());
        CloseHandle(hFile);
        if (hFileContent != nullptr) {
            HeapFree(GetProcessHeap(), 0, hFileContent);
            CloseHandle(hFileContent);
        }
        return nullptr;
    }
    CloseHandle(hFile);
    return hFileContent;
}

PIMAGE_SECTION_HEADER GetSections(const PIMAGE_SECTION_HEADER pImageSectionHeader, const int numOfSections, const DWORD dImportAddress) {
    PIMAGE_SECTION_HEADER pImportSectionHeader = nullptr;
    printf("\n\n[+] Section Header:");
    for (int i = 0; i < numOfSections; i++) {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        printf("\n\nSection index: %d of %d", i + 1, numOfSections);
        printf("\n----------------------");
        printf("\n\tSection name: %s", pCurrentSectionHeader->Name);
        printf("\n\tRaw address: 0x%X", (uintptr_t)pCurrentSectionHeader->PointerToRawData);
        printf("\n\tRaw size: 0x%X", (uintptr_t)pCurrentSectionHeader->SizeOfRawData);
        printf("\n\tirtual address: 0x%X", (uintptr_t)pCurrentSectionHeader->VirtualAddress);
        printf("\n\tVirtual Size: 0x%X", (uintptr_t)pCurrentSectionHeader->Misc.VirtualSize);
        printf("\n\tCharacteristics: ");
        if (pCurrentSectionHeader->Characteristics & 0x00000008) {
            printf("The section should not be padded to the next boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00000020) {
            printf("Section contains executable code, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00000040) {
            printf("Section contains initialized data, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00000080) {
            printf("Section contains uninitialized data, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00000200) {
            printf("Section contains comments or other information, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00000800) {
            printf("Section will not become part of the image, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00001000) {
            printf("Section contains COMDAT data, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00004000) {
            printf("Reset speculative exceptions handling bits in the TLB entries for this section, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00008000) {
            printf("Section contains data referenced through the global pointer, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00100000) {
            printf("Align data on a 1-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00200000) {
            printf("Align data on a 2-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00300000) {
            printf("Align data on a 4-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00400000) {
            printf("Align data on an 8-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00500000) {
            printf("Align data on a 16-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00600000) {
            printf("Align data on a 32-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00700000) {
            printf("Align data on a 64-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00800000) {
            printf("Align data on a 128-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00900000) {
            printf("Align data on a 256-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00A00000) {
            printf("Align data on a 512-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00B00000) {
            printf("Align data on a 1024-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00C00000) {
            printf("Align data on a 2048-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00D00000) {
            printf("Align data on a 4096-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x00E00000) {
            printf("Align data on an 8192-byte boundary, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x01000000) {
            printf("Section contains extended relocations, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x02000000) {
            printf("Section can be discarded, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x04000000) {
            printf("Section cannot be cached, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x08000000) {
            printf("Section is not pageable, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x10000000) {
            printf("Section can be shared in memory, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x20000000) {
            printf("Section can be executed as code, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x40000000) {
            printf("Section can be read, ");
        }
        if (pCurrentSectionHeader->Characteristics & 0x80000000) {
            printf("Section can be written to, ");
        }
        if (dImportAddress >= pCurrentSectionHeader->VirtualAddress && dImportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize) {
            pImportSectionHeader = pCurrentSectionHeader;
        }
    }
    return pImportSectionHeader;
}

void GetImport32(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, const DWORD dRawOffset, const PIMAGE_SECTION_HEADER pImportSection) {
    printf("\n\n[+] IMPORTED DLL\n");

    while (pImportDescriptor->Name != 0) {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImportDescriptor->Name - pImportSection->VirtualAddress)));

        if (pImportDescriptor->OriginalFirstThunk == 0) {
            continue;
        }
        
        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA32)(dRawOffset + (pImportDescriptor->OriginalFirstThunk - pImportSection->VirtualAddress));

        printf("\n\tImported Functions: \n\n");
        
        while (pOriginalFirstThunk->u1.AddressOfData != 0) {
            if (pOriginalFirstThunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32) {
                ++pOriginalFirstThunk;
                continue;
            }

            const auto pImportByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThunk->u1.AddressOfData;
            if (pImportByName == nullptr) {
                continue;
            }
            
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                printf("\t0x%X (Ordinal) : %s\n", (uintptr_t)pOriginalFirstThunk->u1.AddressOfData, dRawOffset + (pImportByName->Name - pImportSection->VirtualAddress));
            }
            else {
                printf("\t\t%s\n", dRawOffset + (pImportByName->Name - pImportSection->VirtualAddress));
            }
            ++pOriginalFirstThunk;
        }
        ++pImportDescriptor;
    }
}

void GetImport64(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, const DWORD dRawOffset, const PIMAGE_SECTION_HEADER pImportSection) {
    printf("\n\n[+] IMPORTED DLL\n");

    while (pImportDescriptor->Name != 0) {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImportDescriptor->Name - pImportSection->VirtualAddress)));

        if (pImportDescriptor->OriginalFirstThunk == 0) {
            continue;
        }

        auto pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(dRawOffset + (pImportDescriptor->OriginalFirstThunk - pImportSection->VirtualAddress));

        printf("\n\tImported Functions: \n\n");

        while (pOriginalFirstThunk->u1.AddressOfData != 0) {
            if (pOriginalFirstThunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64) {
                ++pOriginalFirstThunk;
                continue;
            }

            const auto pImportByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThunk->u1.AddressOfData;
            if (pImportByName == nullptr) {
                continue;
            }

            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                printf("\t0x%X (Ordinal) : %s\n", (uintptr_t)pOriginalFirstThunk->u1.AddressOfData, dRawOffset + (pImportByName->Name - pImportSection->VirtualAddress));
            }
            else {
                printf("\t\t%s\n", dRawOffset + (pImportByName->Name - pImportSection->VirtualAddress));
            }
            ++pOriginalFirstThunk;
        }
        ++pImportDescriptor;
    }
}

PIMAGE_SECTION_HEADER GetExportSection(const PIMAGE_SECTION_HEADER pSectionHeader, const int numOfSections, const DWORD dExportAddress) {
    PIMAGE_SECTION_HEADER pExportHeader = nullptr;

    for (int i = 0; i < numOfSections; i++) {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (dExportAddress >= pCurrentSectionHeader->VirtualAddress && dExportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize) {
            pExportHeader = pCurrentSectionHeader;
        }
    }

    return pExportHeader;
}

void GetExports(const PIMAGE_EXPORT_DIRECTORY pExportDirectory, const DWORD dRawOffset, const PIMAGE_SECTION_HEADER pExportSection) {
    printf("\n[+] EXPORTED FUNCTION\n\n");

    const DWORD dNumberOfNames = pExportDirectory->NumberOfNames;
    const auto pArrayOfFunctionNames = (DWORD*)(dRawOffset + (pExportDirectory->AddressOfNames - pExportSection->VirtualAddress));
    for (int i = 0; i < (int) dNumberOfNames; i++) {
        printf("\t%s\n", (char*)dRawOffset + (pArrayOfFunctionNames[i] - pExportSection->VirtualAddress));
    }
}

int ParseImage32(const PIMAGE_DOS_HEADER pDosHeader) {
    const auto pNtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    if (pNtHeaders32 == nullptr) {
        return -1;
    }
    const IMAGE_FILE_HEADER fileHeader = pNtHeaders32->FileHeader;
    const IMAGE_OPTIONAL_HEADER32 optionalHeader = pNtHeaders32->OptionalHeader;
    const auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders32 + sizeof(IMAGE_NT_HEADERS32));
    if (pSectionHeader == nullptr) {
        return -1;
    }

    printf("[+] PE IMAGE INFORMATION \n");
    printf("\n[+] Architecture x86 \n");

    printf("\n[+] Optional Header: \n");
    printf("\n[+] Pointer to the entry point: 0x%08X", optionalHeader.AddressOfEntryPoint);
    printf("\n[+] Checksum: 0x%08X", optionalHeader.CheckSum);
    printf("\n[+] Image base: 0x%08X", optionalHeader.ImageBase);
    printf("\n[+] File alignment: 0x%08X", optionalHeader.FileAlignment);
    printf("\n[+] Size of image: 0x%08X", optionalHeader.SizeOfImage);

    const PIMAGE_SECTION_HEADER pImportSectionHeader = GetSections(pSectionHeader, fileHeader.NumberOfSections, optionalHeader.DataDirectory[1].VirtualAddress);
    if (pImportSectionHeader == nullptr) {
        printf("\n[-] An error when trying to retrieve PE imports !\n");
        return -1;
    }

    DWORD dRawOffset = (DWORD)pDosHeader + pImportSectionHeader->PointerToRawData;
    const auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (optionalHeader.DataDirectory[1].VirtualAddress) - pImportSectionHeader->VirtualAddress);
    if (pImportDescriptor == nullptr) {
        printf("\n[-] An error occured when trying to retrieve PE imports descriptor !\n");
        return -1;
    }
    GetImport32(pImportDescriptor, dRawOffset, pImportSectionHeader);

    const PIMAGE_SECTION_HEADER pExportSection = GetExportSection(pSectionHeader, fileHeader.NumberOfSections, optionalHeader.DataDirectory[0].VirtualAddress);
    if (pExportSection != nullptr) {
        dRawOffset = (DWORD)pDosHeader + pExportSection->PointerToRawData;
        const auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (optionalHeader.DataDirectory[0].VirtualAddress - pExportSection->VirtualAddress));
        GetExports(pExportDirectory, dRawOffset, pExportSection);
    }
    return 0;
}

int ParseImage64(const PIMAGE_DOS_HEADER pDosHeader) {
    const auto pNtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    if (pNtHeaders64 == nullptr) {
        return -1;
    }
    const IMAGE_FILE_HEADER fileHeader = pNtHeaders64->FileHeader;
    const IMAGE_OPTIONAL_HEADER64 optionalHeader = pNtHeaders64->OptionalHeader;
    const auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders64 + sizeof(IMAGE_NT_HEADERS64));
    if (pSectionHeader == nullptr) {
        return -1;
    }

    printf("[+] PE IMAGE INFORMATION \n");
    printf("\n[+] Architecture x64 \n");

    printf("\n[+] Optional Header: \n");
    printf("\n[+] Pointer to the entry point: 0x%08X", optionalHeader.AddressOfEntryPoint);
    printf("\n[+] Checksum: 0x%08X", optionalHeader.CheckSum);
    printf("\n[+] Image base: 0x%08X", optionalHeader.ImageBase);
    printf("\n[+] File alignment: 0x%08X", optionalHeader.FileAlignment);
    printf("\n[+] Size of image: 0x%08X", optionalHeader.SizeOfImage);

    const PIMAGE_SECTION_HEADER pImportSectionHeader = GetSections(pSectionHeader, fileHeader.NumberOfSections, optionalHeader.DataDirectory[1].VirtualAddress);
    if (pImportSectionHeader == nullptr) {
        printf("\n[-] An error when trying to retrieve PE imports !\n");
        return -1;
    }

    DWORD dRawOffset = (DWORD)pDosHeader + pImportSectionHeader->PointerToRawData;
    const auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (optionalHeader.DataDirectory[1].VirtualAddress) - pImportSectionHeader->VirtualAddress);
    if (pImportDescriptor == nullptr) {
        printf("\n[-] An error occured when trying to retrieve PE imports descriptor !\n");
        return -1;
    }
    GetImport64(pImportDescriptor, dRawOffset, pImportSectionHeader);

    const PIMAGE_SECTION_HEADER pExportSection = GetExportSection(pSectionHeader, fileHeader.NumberOfSections, optionalHeader.DataDirectory[0].VirtualAddress);
    if (pExportSection != nullptr) {
        dRawOffset = (DWORD)pDosHeader + pExportSection->PointerToRawData;
        const auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (optionalHeader.DataDirectory[0].VirtualAddress - pExportSection->VirtualAddress));
        GetExports(pExportDirectory, dRawOffset, pExportSection);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    char* lpFilePath;
    if (argc == 2) {
        lpFilePath = argv[1];
    }
    else {
        printf("[-] Invalid arguments. Usage: PEParser.exe <FilePath>");
        return 1;
    }

    const HANDLE hFileContent = GetFileContent(lpFilePath);
    if (hFileContent == INVALID_HANDLE_VALUE) {
        if (hFileContent != nullptr) {
            CloseHandle(hFileContent);
        }
        return -1;
    }

    const auto pDosHeader = (PIMAGE_DOS_HEADER)hFileContent;
    if (pDosHeader == nullptr) {
        if (hFileContent != nullptr) {
            HeapFree(hFileContent, 0, nullptr);
            CloseHandle(hFileContent);
        }
        return -1;
    }

    const auto pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hFileContent + pDosHeader->e_lfanew);
    if (pNtHeaders == nullptr) {
        if (hFileContent != nullptr) {
            HeapFree(hFileContent, 0, nullptr);
            CloseHandle(hFileContent);
        }
        return -1;
    }

    // Identify x86 or x64
    int ParseResult = 0;
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        ParseResult = ParseImage32(pDosHeader);
    }
    else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ParseResult = ParseImage64(pDosHeader);
    }
    if (hFileContent != nullptr) {
        HeapFree(hFileContent, 0, nullptr);
    }
    return ParseResult;
}