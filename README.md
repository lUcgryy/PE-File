<div align='center'>

# **PE Parser**
 
</div>

## **Language:** C++

## **Requirement:** A C++ Compiler (g++)

## **Description:**

This program retrive some information of a file. It can parse x86 and x64 file. Execute run.bat to get the PEParser.exe

1.  **Optional Header:**

    -   Pointer to Entry Point
    -   Checksum
    -   Image Base
    -   File Alignment
    -   Size of Image

2.  **Information about all sections of the file:**

    -   Name
    -   Characteristics
    -   Raw Address
    -   Raw Size
    -   Virtual Address
    -   Virtula Size

3.  **Every DLL imported with imported functions.**
4.  **Every exported functions (if the DataDirectory exists).**

## **Usage:** PEParser.exe <PE_file>