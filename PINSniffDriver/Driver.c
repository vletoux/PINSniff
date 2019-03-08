/*++  
  
Copyright (c) Microsoft Corporation.  All rights reserved.  
  
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY  
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE  
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR  
    PURPOSE.  
  
Module Name:  
  
    filter.c  
  
Abstract:  
  
    This module shows how to a write a generic filter driver.  
  
Environment:  
  
    Kernel mode  
  
Revision History:  
  
    Fixed bugs - March 15, 2001  
  
    Added Ioctl interface - Aug 16, 2001  
      
    Updated to use IoCreateDeviceSecure function - Sep 17, 2002  
  
    Updated to use RemLocks - Oct 29, 2002  
      
--*/   
   
//#define IOCTL_INTERFACE 1

#include "driver.h"   
#include "driver.tmh"
//#include "Eventsevents.h"

#ifdef ALLOC_PRAGMA   
#pragma alloc_text (INIT, DriverEntry)   
#pragma alloc_text (PAGE, FilterAddDevice)   
#pragma alloc_text (PAGE, FilterDispatchPnp)   
#pragma alloc_text (PAGE, FilterUnload)   
#pragma alloc_text (PAGE, FilterDispatchIo)   
#pragma alloc_text (PAGE, FilterTransmitIO)   
#endif   
   
NTSTATUS   
DriverEntry(   
    __in PDRIVER_OBJECT  DriverObject,   
    __in PUNICODE_STRING RegistryPath   
    )   
/*++  
  
Routine Description:  
  
    Installable driver initialization entry point.  
    This entry point is called directly by the I/O system.  
  
Arguments:  
  
    DriverObject - pointer to the driver object  
  
    RegistryPath - pointer to a unicode string representing the path,  
                   to driver-specific key in the registry.  
  
Return Value:  
  
    STATUS_SUCCESS if successful,  
    STATUS_UNSUCCESSFUL otherwise.  
  
--*/   
{   
    NTSTATUS            status = STATUS_SUCCESS;   
    ULONG               ulIndex;   
    PDRIVER_DISPATCH  * dispatch;   

    UNREFERENCED_PARAMETER (RegistryPath);   
    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING( DriverObject, RegistryPath );

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");
    //   
    // Create dispatch points   
    //   
    for (ulIndex = 0, dispatch = DriverObject->MajorFunction;   
         ulIndex <= IRP_MJ_MAXIMUM_FUNCTION;   
         ulIndex++, dispatch++) {   
   
        *dispatch = FilterPass;   
    }   
   
    DriverObject->MajorFunction[IRP_MJ_PNP]            = FilterDispatchPnp;   
    DriverObject->MajorFunction[IRP_MJ_POWER]          = FilterDispatchPower;   
    DriverObject->DriverExtension->AddDevice           = FilterAddDevice;   
    DriverObject->DriverUnload                         = FilterUnload;   
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FilterDispatchIo;
   
    return status;   
}   
   
   
NTSTATUS   
FilterAddDevice(   
    __in PDRIVER_OBJECT DriverObject,   
    __in PDEVICE_OBJECT PhysicalDeviceObject   
    )   
/*++  
  
Routine Description:  
  
    The Plug & Play subsystem is handing us a brand new PDO, for which we  
    (by means of INF registration) have been asked to provide a driver.  
  
    We need to determine if we need to be in the driver stack for the device.  
    Create a function device object to attach to the stack  
    Initialize that device object  
    Return status success.  
  
    Remember: We can NOT actually send ANY non pnp IRPS to the given driver  
    stack, UNTIL we have received an IRP_MN_START_DEVICE.  
  
Arguments:  
  
    DeviceObject - pointer to a device object.  
  
    PhysicalDeviceObject -  pointer to a device object created by the  
                            underlying bus driver.  
  
Return Value:  
  
    NT status code.  
  
--*/   
{   
    NTSTATUS                status = STATUS_SUCCESS;   
    PDEVICE_OBJECT          deviceObject = NULL;   
    PDEVICE_EXTENSION       deviceExtension;   
    ULONG                   deviceType = FILE_DEVICE_UNKNOWN;   
   
    PAGED_CODE();   
   
   
    //   
    // IoIsWdmVersionAvailable(1, 0x20) returns TRUE on os after Windows 2000.   
    //   
    if (!IoIsWdmVersionAvailable(1, 0x20)) {   
        //   
        // Win2K system bugchecks if the filter attached to a storage device   
        // doesn't specify the same DeviceType as the device it's attaching   
        // to. This bugcheck happens in the filesystem when you disable   
        // the devicestack whose top level deviceobject doesn't have a VPB.   
        // To workaround we will get the toplevel object's DeviceType and   
        // specify that in IoCreateDevice.   
        //   
        deviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);   
        deviceType = deviceObject->DeviceType;   
        ObDereferenceObject(deviceObject);   
    }   
   
    //   
    // Create a filter device object.   
    //   
   
    status = IoCreateDevice (DriverObject,   
                             sizeof (DEVICE_EXTENSION),   
                             NULL,  // No Name   
                             deviceType,   
                             FILE_DEVICE_SECURE_OPEN,   
                             FALSE,   
                             &deviceObject);   
   
   
    if (!NT_SUCCESS (status)) {   
        //   
        // Returning failure here prevents the entire stack from functioning,   
        // but most likely the rest of the stack will not be able to create   
        // device objects either, so it is still OK.   
        //   
        return status;   
    }   
   
    deviceExtension = (PDEVICE_EXTENSION) deviceObject->DeviceExtension;   
   
    deviceExtension->DeviceData.Type = DEVICE_TYPE_FIDO;   
   
    deviceExtension->NextLowerDriver = IoAttachDeviceToDeviceStack (   
                                       deviceObject,   
                                       PhysicalDeviceObject);   
    //   
    // Failure for attachment is an indication of a broken plug & play system.   
    //   
   
    if (NULL == deviceExtension->NextLowerDriver) {   
   
        IoDeleteDevice(deviceObject);   
        return STATUS_UNSUCCESSFUL;   
    }   
   
    deviceObject->Flags |= deviceExtension->NextLowerDriver->Flags &   
                            (DO_BUFFERED_IO | DO_DIRECT_IO |   
                            DO_POWER_PAGABLE );   
   
   
    deviceObject->DeviceType = deviceExtension->NextLowerDriver->DeviceType;   
   
    deviceObject->Characteristics =   
                          deviceExtension->NextLowerDriver->Characteristics;   
   
    deviceExtension->Self = deviceObject;   
   
    //   
    // Let us use remove lock to keep count of IRPs so that we don't    
    // deteach and delete our deviceobject until all pending I/Os in our   
    // devstack are completed. Remlock is required to protect us from   
    // various race conditions where our driver can get unloaded while we   
    // are still running dispatch or completion code.   
    //   
       
    IoInitializeRemoveLock (&deviceExtension->RemoveLock ,    
                            POOL_TAG,   
                            1, // MaxLockedMinutes    
                            100); // HighWatermark, this parameter is    
                                // used only on checked build. Specifies    
                                // the maximum number of outstanding    
                                // acquisitions allowed on the lock   
                                   
   
    //   
    // Set the initial state of the Filter DO   
    //   
   
    INITIALIZE_PNP_STATE(deviceExtension);   
 
   
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;   
   
    return STATUS_SUCCESS;   
   
}   
   
   
NTSTATUS   
FilterPass (   
    __in PDEVICE_OBJECT DeviceObject,   
    __in PIRP Irp   
    )   
/*++  
  
Routine Description:  
  
    The default dispatch routine.  If this driver does not recognize the  
    IRP, then it should send it down, unmodified.  
    If the device holds iris, this IRP must be queued in the device extension  
    No completion routine is required.  
  
    For demonstrative purposes only, we will pass all the (non-PnP) Irps down  
    on the stack (as we are a filter driver). A real driver might choose to  
    service some of these Irps.  
  
    As we have NO idea which function we are happily passing on, we can make  
    NO assumptions about whether or not it will be called at raised IRQL.  
    For this reason, this function must be in put into non-paged pool  
    (aka the default location).  
  
Arguments:  
  
   DeviceObject - pointer to a device object.  
  
   Irp - pointer to an I/O Request Packet.  
  
Return Value:  
  
      NT status code  
  
--*/   
{   
    PDEVICE_EXTENSION           deviceExtension;   
    NTSTATUS    status;   
       
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
    status = IoAcquireRemoveLock (&deviceExtension->RemoveLock, Irp);   
    if (!NT_SUCCESS (status)) {   
        Irp->IoStatus.Status = status;   
        IoCompleteRequest (Irp, IO_NO_INCREMENT);   
        return status;   
    }   
   
   IoSkipCurrentIrpStackLocation (Irp);   
   status = IoCallDriver (deviceExtension->NextLowerDriver, Irp);   
   IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);    
   return status;   
}   
   

   
   
   
NTSTATUS   
FilterDispatchPnp (   
    __in PDEVICE_OBJECT DeviceObject,   
    __in PIRP Irp   
    )   
/*++  
  
Routine Description:  
  
    The plug and play dispatch routines.  
  
    Most of these the driver will completely ignore.  
    In all cases it must pass on the IRP to the lower driver.  
  
Arguments:  
  
   DeviceObject - pointer to a device object.  
  
   Irp - pointer to an I/O Request Packet.  
  
Return Value:  
  
      NT status code  
  
--*/   
{   
    PDEVICE_EXTENSION           deviceExtension;   
    PIO_STACK_LOCATION         irpStack;   
    NTSTATUS                            status;   
    KEVENT                               event;   
   
    PAGED_CODE();   
   
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
    irpStack = IoGetCurrentIrpStackLocation(Irp);   
   
   status = IoAcquireRemoveLock (&deviceExtension->RemoveLock, Irp);   
    if (!NT_SUCCESS (status)) {   
        Irp->IoStatus.Status = status;   
        IoCompleteRequest (Irp, IO_NO_INCREMENT);   
        return status;   
    }   
       
   
    switch (irpStack->MinorFunction) {   
    case IRP_MN_START_DEVICE:   
   
        //   
        // The device is starting.   
        // We cannot touch the device (send it any non pnp irps) until a   
        // start device has been passed down to the lower drivers.   
        //   
        KeInitializeEvent(&event, NotificationEvent, FALSE);   
        IoCopyCurrentIrpStackLocationToNext(Irp);   
        status = IoSetCompletionRoutineEx(deviceExtension->NextLowerDriver, Irp,   
                               (PIO_COMPLETION_ROUTINE) FilterStartCompletionRoutine,   
                               &event,   
                               TRUE,   
                               TRUE,   
                               TRUE);   
   
        status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);   
           
        //   
        // Wait for lower drivers to be done with the Irp. Important thing to   
        // note here is when you allocate memory for an event in the stack     
        // you must do a KernelMode wait instead of UserMode to prevent    
        // the stack from getting paged out.   
        //   
        if (status == STATUS_PENDING) {   
   
           KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);             
           status = Irp->IoStatus.Status;   
        }   
   
        if (NT_SUCCESS (status)) {   
   
            //   
            // As we are successfully now back, we will   
            // first set our state to Started.   
            //   
   
            SET_NEW_PNP_STATE(deviceExtension, Started);   
   
            //   
            // On the way up inherit FILE_REMOVABLE_MEDIA during Start.   
            // This characteristic is available only after the driver stack is started!.   
            //   
            if (deviceExtension->NextLowerDriver->Characteristics & FILE_REMOVABLE_MEDIA) {   
   
                DeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;   
            }   
   
        }   
           
        Irp->IoStatus.Status = status;   
        IoCompleteRequest (Irp, IO_NO_INCREMENT);   
        IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);    
        return status;   
   
    case IRP_MN_REMOVE_DEVICE:   
   
        //   
        // Wait for all outstanding requests to complete   
        //   
        IoReleaseRemoveLockAndWait(&deviceExtension->RemoveLock, Irp);   
   
        IoSkipCurrentIrpStackLocation(Irp);   
   
        status = IoCallDriver(deviceExtension->NextLowerDriver, Irp);   
   
        SET_NEW_PNP_STATE(deviceExtension, Deleted);   
           
        IoDetachDevice(deviceExtension->NextLowerDriver);   
        IoDeleteDevice(DeviceObject);   
        return status;   
   
   
    case IRP_MN_QUERY_STOP_DEVICE:   
        SET_NEW_PNP_STATE(deviceExtension, StopPending);   
        status = STATUS_SUCCESS;   
        break;   
   
    case IRP_MN_CANCEL_STOP_DEVICE:   
   
        //   
        // Check to see whether you have received cancel-stop   
        // without first receiving a query-stop. This could happen if someone   
        // above us fails a query-stop and passes down the subsequent   
        // cancel-stop.   
        //   
   
        if (StopPending == deviceExtension->DevicePnPState)   
        {   
            //   
            // We did receive a query-stop, so restore.   
            //   
            RESTORE_PREVIOUS_PNP_STATE(deviceExtension);   
        }   
        status = STATUS_SUCCESS; // We must not fail this IRP.   
        break;   
   
    case IRP_MN_STOP_DEVICE:   
        SET_NEW_PNP_STATE(deviceExtension, Stopped);   
        status = STATUS_SUCCESS;   
        break;   
   
    case IRP_MN_QUERY_REMOVE_DEVICE:   
   
        SET_NEW_PNP_STATE(deviceExtension, RemovePending);   
        status = STATUS_SUCCESS;   
        break;   
   
    case IRP_MN_SURPRISE_REMOVAL:   
   
        SET_NEW_PNP_STATE(deviceExtension, SurpriseRemovePending);   
        status = STATUS_SUCCESS;   
        break;   
   
    case IRP_MN_CANCEL_REMOVE_DEVICE:   
   
        //   
        // Check to see whether you have received cancel-remove   
        // without first receiving a query-remove. This could happen if   
        // someone above us fails a query-remove and passes down the   
        // subsequent cancel-remove.   
        //   
   
        if (RemovePending == deviceExtension->DevicePnPState)   
        {   
            //   
            // We did receive a query-remove, so restore.   
            //   
            RESTORE_PREVIOUS_PNP_STATE(deviceExtension);   
        }   
   
        status = STATUS_SUCCESS; // We must not fail this IRP.   
        break;   
   
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:   
   
        //   
        // On the way down, pagable might become set. Mimic the driver   
        // above us. If no one is above us, just set pagable.   
        //   
        if ((DeviceObject->AttachedDevice == NULL) ||   
            (DeviceObject->AttachedDevice->Flags & DO_POWER_PAGABLE)) {   
   
            DeviceObject->Flags |= DO_POWER_PAGABLE;   
        }   
   
        IoCopyCurrentIrpStackLocationToNext(Irp);   
   
        IoSetCompletionRoutineEx(   
			deviceExtension->NextLowerDriver,
            Irp,   
            FilterDeviceUsageNotificationCompletionRoutine,   
            NULL,   
            TRUE,   
            TRUE,   
            TRUE   
            );   
   
        return IoCallDriver(deviceExtension->NextLowerDriver, Irp);   
   
    default:   
        //   
        // If you don't handle any IRP you must leave the   
        // status as is.   
        //   
        status = Irp->IoStatus.Status;   
   
        break;   
    }   
   
    //   
    // Pass the IRP down and forget it.   
    //   
    Irp->IoStatus.Status = status;   
    IoSkipCurrentIrpStackLocation (Irp);   
    status = IoCallDriver (deviceExtension->NextLowerDriver, Irp);   
    IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);    
    return status;   
}   
   
NTSTATUS   
FilterStartCompletionRoutine(   
    __in PDEVICE_OBJECT   DeviceObject,   
    __in PIRP             Irp,   
    __in PVOID            Context   
    )   
/*++  
Routine Description:  
    A completion routine for use when calling the lower device objects to  
    which our filter deviceobject is attached.  
  
Arguments:  
  
    DeviceObject - Pointer to deviceobject  
    Irp          - Pointer to a PnP Irp.  
    Context      - NULL  
Return Value:  
  
    NT Status is returned.  
  
--*/   
   
{   
    PKEVENT             event = (PKEVENT)Context;   
   
    UNREFERENCED_PARAMETER (DeviceObject);   
   
    //   
    // If the lower driver didn't return STATUS_PENDING, we don't need to    
    // set the event because we won't be waiting on it.    
    // This optimization avoids grabbing the dispatcher lock, and improves perf.   
    //   
    if (Irp->PendingReturned == TRUE) {   
        KeSetEvent (event, IO_NO_INCREMENT, FALSE);   
    }   
   
    //   
    // The dispatch routine will have to call IoCompleteRequest   
    //   
   
    return STATUS_MORE_PROCESSING_REQUIRED;   
   
}   
   
NTSTATUS   
FilterDeviceUsageNotificationCompletionRoutine(   
    __in PDEVICE_OBJECT   DeviceObject,   
    __in PIRP             Irp,   
    __in PVOID            Context   
    )   
/*++  
Routine Description:  
    A completion routine for use when calling the lower device objects to  
    which our filter deviceobject is attached.  
  
Arguments:  
  
    DeviceObject - Pointer to deviceobject  
    Irp          - Pointer to a PnP Irp.  
    Context      - NULL  
Return Value:  
  
    NT Status is returned.  
  
--*/   
   
{   
    PDEVICE_EXTENSION       deviceExtension;   
   
    UNREFERENCED_PARAMETER(Context);   
   
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
   
   
    if (Irp->PendingReturned) {   
   
        IoMarkIrpPending(Irp);   
    }   
   
    //   
    // On the way up, pagable might become clear. Mimic the driver below us.   
    //   
    if (!(deviceExtension->NextLowerDriver->Flags & DO_POWER_PAGABLE)) {   
   
        DeviceObject->Flags &= ~DO_POWER_PAGABLE;   
    }   
   
    IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);    
   
    return STATUS_CONTINUE_COMPLETION;   
   
}   
   
NTSTATUS   
FilterDispatchPower(   
    __in PDEVICE_OBJECT    DeviceObject,   
    __in PIRP              Irp   
    )   
/*++  
  
Routine Description:  
  
    This routine is the dispatch routine for power irps.  
  
Arguments:  
  
    DeviceObject - Pointer to the device object.  
  
    Irp - Pointer to the request packet.  
  
Return Value:  
  
    NT Status code  
--*/   
{   
    PDEVICE_EXTENSION   deviceExtension;   
    NTSTATUS    status;   
       
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
    status = IoAcquireRemoveLock (&deviceExtension->RemoveLock, Irp);   
    if (!NT_SUCCESS (status)) { // may be device is being removed.   
        Irp->IoStatus.Status = status;   
        PoStartNextPowerIrp(Irp);   
        IoCompleteRequest (Irp, IO_NO_INCREMENT);   
        return status;   
    }   
   
    PoStartNextPowerIrp(Irp);   
    IoSkipCurrentIrpStackLocation(Irp);   
    status = PoCallDriver(deviceExtension->NextLowerDriver, Irp);   
    IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);    
    return status;   
}   
   
   
   
VOID   
FilterUnload(   
    __in PDRIVER_OBJECT DriverObject   
    )   
/*++  
  
Routine Description:  
  
    Free all the allocated resources in DriverEntry, etc.  
  
Arguments:  
  
    DriverObject - pointer to a driver object.  
  
Return Value:  
  
    VOID.  
  
--*/   
{   
    PAGED_CODE();   
   UNREFERENCED_PARAMETER(DriverObject);
    //   
    // The device object(s) should be NULL now   
    // (since we unload, all the devices objects associated with this   
    // driver must be deleted.   
    //   
    ASSERT(DriverObject->DeviceObject == NULL);   
   
    //   
    // We should not be unloaded until all the devices we control   
    // have been removed from our queue.   
    //   
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Unload");
	WPP_CLEANUP(DriverObject);
   
    return;   
}   

VOID DumpAPDU(PIRP Irp, ULONG dwDataIn)
{
    PSCARD_T1_REQUEST pInputBuffer = (PSCARD_T1_REQUEST) Irp->AssociatedIrp.SystemBuffer;
	BYTE* pbData = NULL;
	DWORD dwSize = 0;
	DWORD i;
	CHAR* buffer = NULL;

	if (sizeof(SCARD_T1_REQUEST)> dwDataIn) {
		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Data to small");
		return;
	}
	if (pInputBuffer->ioRequest.cbPciLength > dwDataIn || pInputBuffer->ioRequest.cbPciLength < sizeof(SCARD_T1_REQUEST)) {
		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Data to small");
		return;
	}
	if (pInputBuffer->ioRequest.dwProtocol != SCARD_PROTOCOL_T1 && pInputBuffer->ioRequest.dwProtocol != SCARD_PROTOCOL_T0) {
		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Unknown protocol");
		return;
	}
	pbData = (BYTE*)(pInputBuffer) + pInputBuffer->ioRequest.cbPciLength;
	dwSize = dwDataIn - pInputBuffer->ioRequest.cbPciLength;

	buffer = (CHAR*) ExAllocatePoolWithTag(NonPagedPool, 5 + 3 * dwSize + 1, 'APDU');
	if (!buffer) 
	{
		return;
	}
	buffer[0] = 'A';
	buffer[1] = 'P';
	buffer[2] = 'D';
	buffer[3] = 'U';
	buffer[4] = ':';
	for(i = 0; i < dwSize; i++) {
		BYTE data = pbData[i];
		buffer[5+3*i] = '0';
		buffer[5+3*i+1] = '0';
		buffer[5+3*i+2] = ' ';
		if ((data & 0x0F) >= 0xA) 
			buffer[5+3*i+1] = 'A' + ((data&0x0F) - 0x0A);
		else
			buffer[5+3*i+1] += (data & 0x0F);
		if ((data & 0xF0) >= 0xA0) 
			buffer[5+3*i] = 'A' + ((data&0xF0) >> 4) - 0x0A;
		else
			buffer[5+3*i] += ((data & 0xF0) >> 4);
		
	}
	buffer[5+i*3] = 0;

	TraceEvents(TRACE_LEVEL_ERROR, TRACE_APDU, "%s", buffer);

	ExFreePool(buffer);
}

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
NTSTATUS TransmitIoCompletion( IN PDEVICE_OBJECT  pDevObj, IN PIRP  pIrp, IN PVOID  Context )
{
	
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation( pIrp );
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(Context);
	
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "IOCTL_SMARTCARD_TRANSMIT Output");

	if (pIrp->PendingReturned) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "IoStatus PendingReturned");
		IoMarkIrpPending( pIrp );
	}
	if(NT_SUCCESS(pIrp->IoStatus.Status)){
		
		DumpAPDU(pIrp, MIN(pIrpStack->Parameters.DeviceIoControl.OutputBufferLength, (ULONG) pIrp->IoStatus.Information));
	} else if (pIrp->IoStatus.Status == STATUS_CANCELLED) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "IoStatus cancelled");   
	} else {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "IoStatus other error");
	}

	return STATUS_SUCCESS;
}

NTSTATUS   
FilterTransmitIO (   
    __in PDEVICE_OBJECT DeviceObject,   
    __in PIRP pIrp,
	__in PIO_STACK_LOCATION  pIrpStack
    )   
/*++  
  
Routine Description:  
  
    The default dispatch routine.  If this driver does not recognize the  
    IRP, then it should send it down, unmodified.  
    If the device holds iris, this IRP must be queued in the device extension  
    No completion routine is required.  
  
    For demonstrative purposes only, we will pass all the (non-PnP) Irps down  
    on the stack (as we are a filter driver). A real driver might choose to  
    service some of these Irps.  
  
    As we have NO idea which function we are happily passing on, we can make  
    NO assumptions about whether or not it will be called at raised IRQL.  
    For this reason, this function must be in put into non-paged pool  
    (aka the default location).  
  
Arguments:  
  
   DeviceObject - pointer to a device object.  
  
   Irp - pointer to an I/O Request Packet.  
  
Return Value:  
  
      NT status code  
  
--*/   
{   
    PDEVICE_EXTENSION           deviceExtension;   
    NTSTATUS    status;   
    
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "IOCTL_SMARTCARD_TRANSMIT Input");

	deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
	status = IoAcquireRemoveLock (&deviceExtension->RemoveLock, pIrp);   
	if (!NT_SUCCESS (status)) {   
        pIrp->IoStatus.Status = status;   
        IoCompleteRequest (pIrp, IO_NO_INCREMENT);   
        return status;   
    }

	DumpAPDU(pIrp, pIrpStack->Parameters.DeviceIoControl.InputBufferLength);

	IoCopyCurrentIrpStackLocationToNext(pIrp);

	IoSetCompletionRoutineEx(deviceExtension->NextLowerDriver,
							pIrp,
							TransmitIoCompletion,
							NULL,
							TRUE,//InvokeOnSuccess
							TRUE, // InvokeOnError
							TRUE // InvokeOnCancel
							);
	status = IoCallDriver(deviceExtension->NextLowerDriver, pIrp);
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, pIrp);    
	return status;   

}   

VOID   
DumpPowerControl (   
     __in PDEVICE_OBJECT DeviceObject,   
	 __in PIRP pIrp,
	__in PIO_STACK_LOCATION  pIrpStack
    )   
{
	PDEVICE_EXTENSION           deviceExtension;   
    NTSTATUS    status;   
	
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "IOCTL_SMARTCARD_POWER");

	deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;   
	status = IoAcquireRemoveLock (&deviceExtension->RemoveLock, pIrp);   
	if (!NT_SUCCESS (status)) {   
        return;   
    }
	if (pIrpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(DWORD)) {
		DWORD code = *((DWORD*) pIrp->AssociatedIrp.SystemBuffer);
		if (code == SCARD_WARM_RESET || code == SCARD_COLD_RESET) {
			TraceEvents(TRACE_LEVEL_ERROR, TRACE_CARD_RESET, "%s", "APDU:Reset");
		}
	}

	IoReleaseRemoveLock(&deviceExtension->RemoveLock, pIrp);    
}

NTSTATUS   
FilterDispatchIo(   
    __in PDEVICE_OBJECT    DeviceObject,   
    __in PIRP              Irp   
    )   
/*++  
  
Routine Description:  
  
    This routine is the dispatch routine for non passthru irps.  
    We will check the input device object to see if the request  
    is meant for the control device object. If it is, we will  
    handle and complete the IRP, if not, we will pass it down to   
    the lower driver.  
      
Arguments:  
  
    DeviceObject - Pointer to the device object.  
  
    Irp - Pointer to the request packet.  
  
Return Value:  
  
    NT Status code  
--*/   
{   
    PIO_STACK_LOCATION  irpStack;   
    PCOMMON_DEVICE_DATA commonData;   
   
    PAGED_CODE();   
   
   commonData = (PCOMMON_DEVICE_DATA)DeviceObject->DeviceExtension;   
   
   
    //   
    // Please note that this is a common dispatch point for controlobject and   
    // filter deviceobject attached to the pnp stack.    
    //   
    if (commonData->Type == DEVICE_TYPE_FIDO) {   
        //   
        // We will just  the request down as we are not interested in handling   
        // requests that come on the PnP stack.   
        //   
		irpStack = IoGetCurrentIrpStackLocation (Irp);
		if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL && irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SMARTCARD_TRANSMIT) {
			return FilterTransmitIO(DeviceObject, Irp, irpStack);
		}
		if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL && irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SMARTCARD_POWER) {
			DumpPowerControl(DeviceObject, Irp, irpStack);
		}

        return FilterPass(DeviceObject, Irp);       
    }   
	return STATUS_SUCCESS;
}
