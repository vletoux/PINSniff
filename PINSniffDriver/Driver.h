/*++ 
 
Copyright (c) Microsoft Corporation.  All rights reserved. 
 
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY 
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR 
    PURPOSE. 
 
Module Name: 
 
    filter.h 
 
Abstract: 
 
    Contains structure definitions and function prototypes for filter driver. 
 
Environment: 
 
    Kernel mode 
 
Revision History: 
--*/ 

#include <ntddk.h> 

#include <wdmsec.h> // for IoCreateDeviceSecure 
#include <initguid.h> 
#include <dontuse.h> 
#pragma warning(disable: 4201)
#include <winsmcrd.h>
#include "Trace.h"


//#include "wmimof.h"

// {41966169-3FD7-4392-AFE4-E6A9D0A92C72}  - generated using guidgen.exe 
DEFINE_GUID (GUID_SD_FILTER_CONTROL_OBJECT, 
        0x41966169, 0x3fd7, 0x4392, 0xaf, 0xe4, 0xe6, 0xa9, 0xd0, 0xa9, 0x2c, 0x72); 
 
// 
// GUID definition are required to be outside of header inclusion pragma to avoid 
// error during precompiled headers. 
// 


 
#ifndef  STATUS_CONTINUE_COMPLETION //required to build driver in Win2K and XP build environment 
// 
// This value should be returned from completion routines to continue 
// completing the IRP upwards. Otherwise, STATUS_MORE_PROCESSING_REQUIRED 
// should be returned. 
// 
#define STATUS_CONTINUE_COMPLETION      STATUS_SUCCESS 
 
#endif 
 
#define POOL_TAG   'liFT' 
 
// 
// These are the states Filter transition to upon 
// receiving a specific PnP Irp. Refer to the PnP Device States 
// diagram in DDK documentation for better understanding. 
// 
 
typedef enum _DEVICE_PNP_STATE { 
 
    NotStarted = 0,         // Not started yet 
    Started,                // Device has received the START_DEVICE IRP 
    StopPending,            // Device has received the QUERY_STOP IRP 
    Stopped,                // Device has received the STOP_DEVICE IRP 
    RemovePending,          // Device has received the QUERY_REMOVE IRP 
    SurpriseRemovePending,  // Device has received the SURPRISE_REMOVE IRP 
    Deleted                 // Device has received the REMOVE_DEVICE IRP 
 
} DEVICE_PNP_STATE; 
 
#define INITIALIZE_PNP_STATE(_Data_)    \
        (_Data_)->DevicePnPState =  NotStarted;\
        (_Data_)->PreviousPnPState = NotStarted;
 
#define SET_NEW_PNP_STATE(_Data_, _state_) \
        (_Data_)->PreviousPnPState =  (_Data_)->DevicePnPState;\
        (_Data_)->DevicePnPState = (_state_);
 
#define RESTORE_PREVIOUS_PNP_STATE(_Data_)   \
        (_Data_)->DevicePnPState =   (_Data_)->PreviousPnPState;\
 
typedef enum _DEVICE_TYPE { 
 
    DEVICE_TYPE_INVALID = 0,         // Invalid Type; 
    DEVICE_TYPE_FIDO,                // Device is a filter device. 
    DEVICE_TYPE_CDO,                 // Device is a control device. 
 
} DEVICE_TYPE_VALUE; 
 
// 
// A common header for the device extensions of the Filter and control 
// device objects 
// 
 
typedef struct _COMMON_DEVICE_DATA 
{ 
 
    DEVICE_TYPE Type; 
 
} COMMON_DEVICE_DATA, *PCOMMON_DEVICE_DATA; 
 
 
typedef struct _DEVICE_EXTENSION 
{ 
    COMMON_DEVICE_DATA DeviceData; 
 
    // 
    // A back pointer to the device object. 
    // 
 
    PDEVICE_OBJECT  Self; 
 
    // 
    // The top of the stack before this filter was added. 
    // 
 
    PDEVICE_OBJECT  NextLowerDriver; 
 
    // 
    // current PnP state of the device 
    // 
 
    DEVICE_PNP_STATE  DevicePnPState; 
 
    // 
    // Remembers the previous pnp state 
    // 
 
    DEVICE_PNP_STATE    PreviousPnPState; 
 
    // 
    // Removelock to track IRPs so that device can be removed and 
    // the driver can be unloaded safely. 
    // 
    IO_REMOVE_LOCK RemoveLock; 
 
} DEVICE_EXTENSION, *PDEVICE_EXTENSION; 
 
 
 
DRIVER_INITIALIZE DriverEntry; 
 
DRIVER_ADD_DEVICE FilterAddDevice; 
 
__drv_dispatchType(IRP_MJ_PNP) 
DRIVER_DISPATCH FilterDispatchPnp; 
 
__drv_dispatchType(IRP_MJ_POWER) 
DRIVER_DISPATCH FilterDispatchPower; 
 
__drv_dispatchType_other 
DRIVER_DISPATCH FilterPass; 
 
DRIVER_UNLOAD FilterUnload; 
 
IO_COMPLETION_ROUTINE FilterDeviceUsageNotificationCompletionRoutine; 
 
NTSTATUS 
FilterStartCompletionRoutine( 
    __in PDEVICE_OBJECT   DeviceObject, 
    __in PIRP             Irp, 
    __in PVOID            Context 
    ); 
 
 
PCHAR 
PnPMinorFunctionString ( 
    UCHAR MinorFunction 
); 
 

DRIVER_DISPATCH FilterDispatchIo; 

NTSTATUS   
FilterTransmitIO (   
    __in PDEVICE_OBJECT DeviceObject,   
    __in PIRP pIrp,
	__in PIO_STACK_LOCATION  pIrpStack
    )   ;
