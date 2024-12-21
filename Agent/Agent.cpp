#include <iostream>
#include <Windows.h>


// IOCTL defines
#define DEVICE_TYPE1 0x8000
#define IOCTL_CHECK_PROCESS CTL_CODE(DEVICE_TYPE1, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_RESULT  CTL_CODE(DEVICE_TYPE1, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process item
typedef struct _USER_PROCESS_ITEM {
    ULONG ProcessId;
    WCHAR ImageFileName[260];
    BOOLEAN AllowProcess;
} USER_PROCESS_ITEM, * PUSER_PROCESS_ITEM;

// Device path for create file
#define DEVICE_PATH L"\\\\.\\ProcessMonitor"

int main()
{
    printf("Agent starting ...\n");

    printf("Opening device ...\n");
    HANDLE hDevice = CreateFileW(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("Failed opening device. Error: 0x%x\n", error);
        return 1;
    }

    USER_PROCESS_ITEM Item = { 0 };
    DWORD BytesReturned;

    printf("Device opened successfully, pulling processes tasks to process.\n");
    while (TRUE)
    {
        BOOL Result = DeviceIoControl(
            hDevice,
            IOCTL_CHECK_PROCESS,
            NULL,
            0,
            &Item,
            sizeof(Item),
            &BytesReturned,
            NULL
        );

        if (!Result || BytesReturned == 0)
        {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                printf("DeviceIoControl failed: 0x%x\n", GetLastError());
            }
            Sleep(100);
            continue;
        }

        // Get the executable name from the full path
        const WCHAR* execName = Item.ImageFileName;
        const WCHAR* lastBackslash = wcsrchr(Item.ImageFileName, L'\\');
        if (lastBackslash != nullptr) {
            execName = lastBackslash + 1;  // Skip the backslash
        }

        wprintf(L"Analyzing process: %ws [PID: %lu]\n", execName, Item.ProcessId);
        
        // Simulate the static analysis
        Item.AllowProcess = (wcscmp(execName, L"Malware.exe") != 0);


        wprintf(L"Sending results for process: %ws [PID: %lu]\n Verdict: %ws\n",
            Item.ImageFileName,
            Item.ProcessId,
            Item.AllowProcess ? L"Allowed" : L"Blocked");

        Result = DeviceIoControl(
            hDevice,
            IOCTL_SEND_RESULT,
            &Item,
            sizeof(Item),
            NULL,
            0,
            &BytesReturned,
            NULL
        );

        if (!Result) {
            printf("Failed to send result: 0x%x\n", GetLastError());
        }
    }

    CloseHandle(hDevice);
    return 0;
}