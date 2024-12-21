#include "drv.h"


extern "C"
NTSTATUS NTAPI DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);

	// Initialize queue head and mutex
	InitializeListHead(&g_ProcessQueue);
	ExInitializeFastMutex(&g_QueueLock);
	g_Monitor = FALSE;
	g_AgentPID = 0;

	do {

		// Create device
		Status = IoCreateDevice(
			pDriverObject,
			0,
			&DeviceName,
			DEVICE_TYPE1,
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&g_pDeviceObject
		);

		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed creating device 0x%u\n", Status);
			break;
		}

		g_pDeviceObject->Flags |= DO_BUFFERED_IO;

		// Create the symbolic link
		Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
		if (!NT_SUCCESS(Status))
		{
			IoDeleteDevice(g_pDeviceObject);
			DbgPrint("Failed creating symbolic link 0x%u\n", Status);
			break;
		}

		// Set mj funcntions
		pDriverObject->DriverUnload = DriverUnload;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
		pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;

		// Register for process creation
		Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
		if (!NT_SUCCESS(Status))
		{
			IoDeleteDevice(g_pDeviceObject);
			IoDeleteSymbolicLink(&SymLinkName);
			DbgPrint("Failed register for process creation 0x%u\n", Status);
			break;
		}


	} while (false);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Failed loading driver 0x%u\n", Status);
		return Status;
	}

	DbgPrint("Driver loaded successfully\n");

	return Status;
}

VOID DriverUnload(
	PDRIVER_OBJECT pDriverObject
)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	ExAcquireFastMutex(&g_QueueLock);
	while(!IsListEmpty(&g_ProcessQueue))
	{
		PLIST_ENTRY pEntry = RemoveHeadList(&g_ProcessQueue);
		PPROCESS_ITEM pItem = CONTAINING_RECORD(pEntry, PROCESS_ITEM, ListEntry);
		ExFreePool(pItem);

	}
	ExReleaseFastMutex(&g_QueueLock);

	DbgPrint("Driver unloaded\n");
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Process notification callback
VOID ProcessNotifyCallback(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);


	if (!CreateInfo) {
		DbgPrint("Process terminated : % lu\n", HandleToULong(ProcessId));
		if (g_Monitor && HandleToULong(ProcessId) == g_AgentPID)
		{
			g_Monitor = FALSE;
			g_AgentPID = 0;
		}
		return;
	}

	// Skip the agent process
	UNICODE_STRING AgentName = RTL_CONSTANT_STRING(L"Agent.exe");

	BOOLEAN IsAget = RtlSuffixUnicodeString(&AgentName, CreateInfo->ImageFileName, TRUE);

	if (IsAget)
	{
		DbgPrint("Identified the agent process, start monitoring\n");
		g_Monitor = TRUE;
		g_AgentPID = HandleToULong(ProcessId);
		return;
	}

	if (!g_Monitor)
	{
		return;
	}

	DbgPrint("New process creation: %wZ, PID: %lu\n",
		CreateInfo->ImageFileName,
		HandleToULong(ProcessId));

	PPROCESS_ITEM pItem = (PPROCESS_ITEM)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_ITEM),'METI');
	if (!pItem) {
		DbgPrint("Failed to allocate process item\n");
		return;
	}
	RtlZeroMemory(pItem, sizeof(PROCESS_ITEM));

	// Copy relevant info
	pItem->ProcessId = HandleToULong(ProcessId);
	RtlStringCbCopyW(pItem->ImageFileName, sizeof(pItem->ImageFileName), CreateInfo->ImageFileName->Buffer);
	pItem->ProcessState = PROCESS_PENDING;

	// Initialize syncronization event
	KeInitializeEvent(&pItem->Event, NotificationEvent, FALSE);

	// Insert process item to the queue
	ExAcquireFastMutex(&g_QueueLock);
	DbgPrint("Inserting process to queue: %ws \n[PID: %lu]\n",
		pItem->ImageFileName,
		pItem->ProcessId);
	InsertTailList(&g_ProcessQueue, &pItem->ListEntry);
	ExReleaseFastMutex(&g_QueueLock);

	// Wait for agent verdict
	LARGE_INTEGER timeout;
	timeout.QuadPart = -50000000LL;
	NTSTATUS Status = KeWaitForSingleObject(
		&pItem->Event,
		Executive,
		KernelMode,
		FALSE,
		&timeout
	);

	// Check if we reached time out
	if (Status == STATUS_TIMEOUT) {
		DbgPrint("Wait timed out after 5 seconds for process: %ws [PID: %lu]\n",
			pItem->ImageFileName,
			pItem->ProcessId);
		pItem->AllowProcess = TRUE;
	}
	else if (!NT_SUCCESS(Status)) {
		DbgPrint("Failed to wait for processed event\n");
	}
	else if (pItem->ProcessState != PROCESS_PROCESSED)
	{
		DbgPrint("the event did not get processed\n");
	}

	// Check verdict
	if (!pItem->AllowProcess)
	{
		DbgPrint("Blocking process: %ws \n[PID: %lu]\n",
			pItem->ImageFileName,
			pItem->ProcessId);
		CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
	}
	else {
		DbgPrint("Allowing process: %ws \n[PID: %lu]\n",
			pItem->ImageFileName,
			pItem->ProcessId);
	}

	// Remove from list before freeing
	ExAcquireFastMutex(&g_QueueLock);
	RemoveEntryList(&pItem->ListEntry);
	ExReleaseFastMutex(&g_QueueLock);

	ExFreePool(pItem);
}

NTSTATUS DispatchDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	NTSTATUS Status = STATUS_SUCCESS;

	ULONG IoCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	switch (IoCode)
	{
		// IOCTL from the agent askingn for process to "scan"
		case IOCTL_CHECK_PROCESS:
		{
			PUSER_PROCESS_ITEM pUserItem = (PUSER_PROCESS_ITEM)pIrp->AssociatedIrp.SystemBuffer;

			ExAcquireFastMutex(&g_QueueLock);

			PPROCESS_ITEM pItem = NULL;

			// Search for the first item that is not in progress
			if (!IsListEmpty(&g_ProcessQueue))
			{
				PLIST_ENTRY pEntry = g_ProcessQueue.Flink;
				PPROCESS_ITEM pTempItem = NULL;
				while (pEntry != &g_ProcessQueue)
				{
					pTempItem = CONTAINING_RECORD(pEntry, PROCESS_ITEM, ListEntry);
					if (pTempItem->ProcessState == PROCESS_PENDING)
					{
						pItem = pTempItem;
						pItem->ProcessState = PROCESS_IN_PROGRESS;
						DbgPrint("Sending to the agent process: %ws \n[PID: %lu]\n",
						pItem->ImageFileName,
						pItem->ProcessId);
						break;
					}
					pEntry = pEntry->Flink;
				}
			}

			ExReleaseFastMutex(&g_QueueLock);

			if (pItem)
			{
				pUserItem->ProcessId = pItem->ProcessId;
				RtlCopyMemory(pUserItem->ImageFileName,pItem->ImageFileName,sizeof(pItem->ImageFileName));
				pIrp->IoStatus.Information = sizeof(USER_PROCESS_ITEM);
				Status = STATUS_SUCCESS;
			}
			else {
				Status = STATUS_NO_MORE_ENTRIES;
			}
			break;

		}
		// IOCTL from the agent with update regarding verdicts
		case IOCTL_SEND_RESULT:
		{
			PUSER_PROCESS_ITEM pUserItem = (PUSER_PROCESS_ITEM)pIrp->AssociatedIrp.SystemBuffer;
			
			DbgPrint("Got process from agent: %ws \n[PID: %lu]\n",
				pUserItem->ImageFileName,
				pUserItem->ProcessId);

			ExAcquireFastMutex(&g_QueueLock);
			PLIST_ENTRY Entry = g_ProcessQueue.Flink;
			BOOLEAN Found = FALSE;

			while (Entry != &g_ProcessQueue)
			{
				PPROCESS_ITEM pItem = CONTAINING_RECORD(Entry, PROCESS_ITEM, ListEntry);
				if (pItem->ProcessId == pUserItem->ProcessId && pItem->ProcessState == PROCESS_IN_PROGRESS)
				{
					pItem->AllowProcess = pUserItem->AllowProcess;
					pItem->ProcessState = PROCESS_PROCESSED;
					KeSetEvent(&pItem->Event, IO_NO_INCREMENT, FALSE);
					Found = TRUE;
					break;
				}
				Entry = Entry->Flink;
				if (Entry == &g_ProcessQueue || Found) 
					break;
			}

			ExReleaseFastMutex(&g_QueueLock);
			Status = STATUS_SUCCESS;
			break;
		}

		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return Status;
}
