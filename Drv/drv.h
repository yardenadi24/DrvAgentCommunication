#pragma once

#include "commons.h"
#include "ntstrsafe.h"

#define DEVICE_NAME L"\\Device\\ProcessMonitor"
#define SYMLINK_NAME L"\\??\\ProcessMonitor"

enum PROCESS_STATE {
	PROCESS_PENDING = 0,
	PROCESS_IN_PROGRESS = 1,
	PROCESS_PROCESSED = 2
};

typedef struct _PROCCESS_ITEM {
	LIST_ENTRY ListEntry;
	ULONG ProcessId;
	WCHAR ImageFileName[260];
	KEVENT Event;
	BOOLEAN AllowProcess;
	PROCESS_STATE ProcessState;
}PROCESS_ITEM, *PPROCESS_ITEM;

// Globals
PDEVICE_OBJECT g_pDeviceObject;
LIST_ENTRY g_ProcessQueue;
FAST_MUTEX g_QueueLock;
BOOLEAN g_Monitor;
ULONG g_AgentPID;

// Process notification callback
VOID ProcessNotifyCallback(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS DispatchDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
);

extern "C"
NTSTATUS DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
);

VOID DriverUnload(
	PDRIVER_OBJECT pDriverObject
);

NTSTATUS
DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);