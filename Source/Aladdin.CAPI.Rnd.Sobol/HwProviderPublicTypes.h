//---------------------------------------------------------------------------------------------------
// Copyright: (c) 1998-2001 Информзащита, Россия
//---------------------------------------------------------------------------------------------------
// $Archive: /Common/Include/HwProviderPublicTypes.h $	
// $Revision: 54 $
// $Date: 29.05.02 10:55 $
// Unit:        
// Author:      
// Responsible: Евгений Ломовский
//---------------------------------------------------------------------------------------------------
// Description: Константы, структуры данных и прототипы функций для работы
//				с драйверами устройств АП
//---------------------------------------------------------------------------------------------------
/*
// $History: HwProviderPublicTypes.h $
 * 
 * *****************  Version 54  *****************
 * User: Eugenel      Date: 29.05.02   Time: 10:55
 * Updated in $/Common/Include
 * 
 * *****************  Version 11  *****************
 * User: Eugenel      Date: 30.11.01   Time: 18:12
 * Updated in $/Common/Include
 * 
 * *****************  Version 9  *****************
 * User: Eugenel      Date: 24.10.01   Time: 18:59
 * Updated in $/Common/Include
 * 
 * *****************  Version 8  *****************
 * User: Szaitsev     Date: 20.03.01   Time: 18:23
 * Updated in $/Common/Include
 * 
 * *****************  Version 7  *****************
 * User: Szaitsev     Date: 6.03.01    Time: 16:35
 * Updated in $/Common/Include
 */

#ifndef __PUBLICTYPES_H__
#define __PUBLICTYPES_H__

#pragma pack(push,8)
// Это определение нужно чтобы в CPP правильно распозновались
// функции
#ifdef __cplusplus
extern "C" {
#endif

typedef LONG SNCODE;

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SNET_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SNET_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef SNET_EXPORTS
#define SNET_API __declspec(dllexport)
#else
#define SNET_API __declspec(dllimport)
#endif

//
// Generic test for success on any status value (non-negative numbers
// indicate success).
//

#define IF_SUCCESS(Status) ((SNCODE)(Status) >= 0)

//
// Generic test for information on any status value.
//

#define IF_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)

//
// Generic test for warning on any status value.
//

#define IF_WARNING(Status) ((ULONG)(Status) >> 30 == 2)

//
// Generic test for error on any status value.
//

#define IF_ERROR(Status) ((ULONG)(Status) >> 30 == 3)

#define SECRETNET_ERROR(Status) ((ULONG)Status & 0xFFFF)

// 
#define APPLICATION_ERROR_MASK       0x20000000
#define ERROR_SEVERITY_SUCCESS       0x00000000
#define ERROR_SEVERITY_INFORMATIONAL 0x40000000
#define ERROR_SEVERITY_WARNING       0x80000000
#define ERROR_SEVERITY_ERROR         0xC0000000
//

#if !defined(_TYPE_TM_)

typedef enum _TYPE_TM{
	ExternalTm,
	InternalTm,
	Memory0,
	Memory1
} TYPE_TM, *PTYPE_TM;
#define _TYPE_TM_

#endif // !defined(TYPE_TM)

// Структура для хранения кодов вызова для драйвера
typedef struct _DEVICE_CONTROL_IOCTL{
	ULONG	Size;
	ULONG	DeviceQueryInformation;
	ULONG	DeviceSetInformation;
	ULONG	DeviceRead;
	ULONG	DeviceWrite;
	ULONG	DeviceControl;
} DEVICE_CONTROL_IOCTL, *PDEVICE_CONTROL_IOCTL;

typedef enum _DEVICE_FUNCTION{
	IoctlQueryInformationFunction = 1,
	IoctlSetInformationFunction,
	IoctlReadFunction,
	IoctlWriteFunction,
	IoctlControlFunction
} DEVICE_FUNCTION, *PDEVICE_FUNCTION;

// Размер структуры 
#define DEFAULT_DEVICE_CONTROL_SIZE sizeof(DEVICE_CONTROL_IOCTL)

// Типы запрашиваемой информации у драйвера
typedef enum _QUERY_INFORMATION_CLASS{
	DeviceHardwareInformation = 1,
	DeviceIdInformation,
	DeviceIdTypeInformation,
	DeviceIdentificatorPresentInformation,
	DeviceRegistryPathInformation
} QUERY_INFORMATION_CLASS, *PQUERY_INFORMATION_CLASS;

// Типы запрашиваемой информации у драйвера
typedef enum _DEVICE_CONTROL_CLASS{
	DeviceBeginWaitPresent = 1,
	DeviceEndWaitPresent
} DEVICE_CONTROL_CLASS, *PDEVICE_CONTROL_CLASS;

typedef struct _DEVICE_PRESENT_INFORMATION{
	HANDLE	DeviceHandle;
	USHORT	DeviceId;
	ULONG	DeviceParam;
	ULONG	IDType;
	ULONG	IDMemSize;
} DEVICE_PRESENT_INFORMATION, *PDEVICE_PRESENT_INFORMATION;

#pragma warning( disable : 4200 )

typedef struct _DEVICE_CONTROL_TYPE{
	ULONG	Size;
	ULONG	IoctlFunction;
	CHAR	Buffer[0];
} DEVICE_CONTROL_TYPE, *PDEVICE_CONTROL_TYPE;

#pragma warning( once : 4200 )

typedef struct _QUERY_DEVICE_TYPE{
	QUERY_INFORMATION_CLASS QueryInformationClass;
	ULONG	Length;
	LONG	Status;
	CHAR	Buffer[1];
} QUERY_DEVICE_TYPE, *PQUERY_DEVICE_TYPE;

typedef struct _READ_WRITE_DEVICE_TYPE{
	ULONG	Length;
	TYPE_TM	TypeTm;
	LONG	Status;
	ULONG	Offset;
	CHAR	Buffer[1];
} READ_WRITE_DEVICE_TYPE, *PREAD_WRITE_DEVICE_TYPE;

typedef struct _QUERY_PRESENT_INFORMATION{
	BOOLEAN	Present;
}QUERY_PRESENT_INFORMATION, *PQUERY_PRESENT_INFORMATION;

typedef struct _QUERY_HARDWARE_INFORMATION{
	USHORT	DeviceId;
	ULONG	DeviceParam;
	ULONG	DeviceEnglishNameOffset;
	ULONG	DeviceRussianNameOffset;
} QUERY_HARDWARE_INFORMATION, *PQUERY_HARDWARE_INFORMATION;

typedef struct _QUERY_ID_TYPE_INFORMATION{
	ULONG	IDType;
	ULONG	IDMemSize;
	ULONG	IDTypeNameOffset;
	ULONG	IDNameOffset;
	ULONG	IDSize;
	ULONG	IDOffset;
} QUERY_ID_TYPE_INFORMATION, *PQUERY_ID_TYPE_INFORMATION;

typedef struct _QUERY_REGISTRY_INFORMATION {
	ULONG	NameSize;
	USHORT	Name[1];
} QUERY_REGISTRY_INFORMATION, *PQUERY_REGISTRY_INFORMATION;

/////////////////////////////////////////////////////////////
// Заголовки функций экспортируемых из DLL
/////////////////////////////////////////////////////////////

//   Функция возвращает список дескрипторов и количество 
// установленных в системе устройств аппаратной поддержки.
//
// Параметры:
//	phDevice
//		указатель на буфер - массив двойных слов, в который 
//		будет записан список дескрипторов установленных в системе 
//		устройств. Если передано значение указателя - NULL, 
//		функция просто возвращает количество устройств, 
//		установленных в системе;
//	pwDeviceNum
//		указатель на слово, в котором передается количество 
//		элементов в буфере phDevice и возвращается количество 
//		установленных в системе устройств. Если переданный указатель 
//		на буфер phDevice равен NULL или буфер слишком мал, 
//		чтобы вместить весь список дескрипторов, будет возвращен 
//		код ошибки SNAPI_ERROR_NOT_ENOUGH_MEMORY, а в это слово 
//		будет записано количество элементов в списке;
//
//	Примечания:
//		все параметры являются необязательными, т.е. 
//		вместо любого из параметров можно передать NULL

SNET_API SNCODE __stdcall SnAPI_GetDeviceHandles(
	OUT PHANDLE phDevice, 
	IN OUT PUSHORT pwDeviceNum);

SNET_API SNCODE __stdcall SnAPI_GetDeviceInfo(
	IN HANDLE hDevice,
	OUT PUSHORT pwDeviceID,
	OUT char* pszDeviceName,
	OUT char* pszDeviceNameRus,
	OUT PULONG pdwParams);

SNET_API SNCODE __stdcall SnAPI_BeginSession(
	IN HANDLE hDevice,
	OUT PHANDLE phSession);

SNET_API SNCODE __stdcall SnAPI_EndSession(
	IN HANDLE hDevice,
	IN HANDLE hSession);

SNET_API SNCODE __stdcall SnAPI_PIDCheckPresence(
	IN HANDLE hDevice);

SNET_API SNCODE __stdcall SnAPI_PIDReadID(
	IN HANDLE hDevice,
	OUT PUCHAR pbyID,
	IN OUT PULONG pdwIDSize);

SNET_API SNCODE __stdcall SnAPI_PIDGetInfo(
	IN HANDLE hDevice,
	OUT PULONG pdwPIDType,
	OUT PUCHAR pbyID,
	IN OUT PULONG pdwIDSize,
	OUT PCHAR pszPIDText,
	IN OUT PULONG pdwPIDTextSize,
	OUT PCHAR pszPIDTypeName,
	IN OUT PULONG pdwPIDTypeNameSize,
	OUT PULONG pdwMemSize);

SNET_API SNCODE __stdcall SnAPI_PIDReadMem(
	IN HANDLE hDevice,
	OUT PUCHAR pbyData,
	IN ULONG dwOffset,
	IN OUT PULONG pdwSize);

SNET_API SNCODE __stdcall SnAPI_PIDWriteMem(
	IN HANDLE hDevice,
	IN PUCHAR pbyData,
	IN ULONG dwOffset,
	IN OUT PULONG pdwSize);

SNET_API SNCODE __stdcall SnAPI_DeviceSpecificFunction(
	IN HANDLE hDevice,
	IN OUT PVOID pFuncInfo);

SNET_API SNCODE __stdcall SnAPI_SpecificFunction( 
	IN OUT PVOID pFuncInfo );

SNET_API SNCODE __stdcall SnAPI_ReleaseDeviceHandles(
	IN PHANDLE phDevice, 
	IN USHORT wDeviceNum );

// установка драйвера устройства
SNET_API SNCODE __stdcall SnAPI_InstallDeviceDriver(
	IN ULONG dwDeviceType,
	IN ULONG dwParam);

// удаление драйвера устройства
SNET_API SNCODE __stdcall SnAPI_RemoveDeviceDriver(
	IN ULONG dwDeviceType);

// получение списка типов устройств, драйвера которых присутствуют в системе
SNET_API SNCODE __stdcall SnAPI_GetAvailableDrivers(
	OUT LPSTR sMultiSzStr,
	IN  ULONG dwBufferSize);

// получить информацию о драйвере устройства
SNET_API SNCODE __stdcall SnAPI_GetDeviceDriverInfo(
	IN ULONG dwDeviceType);

// подготовить драйвера во время установки Secret Net
SNET_API SNCODE __stdcall SnAPI_InstallSecretNet();

// удалить записи из системы о драйверах во время удаления Secret Net
SNET_API SNCODE __stdcall SnAPI_RemoveSecretNet();

/////////////////////////////////////////////////////////////
// Типы указателей на функций экспортируемых из DLL
/////////////////////////////////////////////////////////////

typedef
SNCODE (__stdcall *PSnAPI_GetDeviceHandles)(
	OUT PHANDLE phDevice, 
	IN OUT PUSHORT pwDeviceNum);

typedef
SNCODE (__stdcall *PSnAPI_ReleaseDeviceHandles)(
	IN PHANDLE phDevice, 
	IN USHORT wDeviceNum);

typedef
SNCODE (__stdcall *PSnAPI_GetDeviceInfo)(
	IN HANDLE hDevice,
	OUT PUSHORT pwDeviceID,
	OUT PCHAR pszDeviceName,
	OUT PCHAR pszDeviceNameRus,
	OUT PULONG pdwParams);

typedef
SNCODE (__stdcall *PSnAPI_BeginSession)(
	IN HANDLE hDevice,
	OUT PHANDLE phSession);

typedef
SNCODE (__stdcall *PSnAPI_EndSession)(
	IN HANDLE hDevice,
	IN HANDLE hSession);

typedef
SNCODE (__stdcall *PSnAPI_PIDCheckPresence)(
	IN HANDLE hDevice);

typedef
SNCODE (__stdcall *PSnAPI_PIDReadID)(
	IN HANDLE hDevice,
	OUT PUCHAR pbyID,
	IN OUT PULONG pdwIDSize);

typedef
SNCODE (__stdcall *PSnAPI_PIDGetInfo)(
	IN HANDLE hDevice,
	OUT PULONG pdwPIDType,
	OUT PUCHAR pbyID,
	IN OUT PULONG pdwIDSize,
	OUT PCHAR pszPIDText,
	IN OUT PULONG pdwPIDTextSize,
	OUT PCHAR pszPIDTypeName,
	IN OUT PULONG pdwPIDTypeNameSize,
	OUT PULONG pdwMemSize);

typedef
SNCODE (__stdcall *PSnAPI_PIDReadMem)(
	IN HANDLE hDevice,
	OUT PUCHAR pbyData,
	IN ULONG dwOffset,
	IN OUT PULONG pdwSize);

typedef
SNCODE (__stdcall *PSnAPI_PIDWriteMem)(
	IN HANDLE hDevice,
	IN PUCHAR pbyData,
	IN ULONG dwOffset,
	IN OUT PULONG pdwSize);

typedef
SNCODE (__stdcall *PSnAPI_DeviceSpecificFunction)(
	IN HANDLE hDevice,
	IN OUT PVOID pFuncInfo);

typedef
SNCODE (__stdcall *PSnAPI_SpecificFunction)( 
	IN OUT PVOID pFuncInfo );

typedef
SNCODE (__stdcall *PSnAPI_InstallDeviceDriver)(
	IN ULONG dwDeviceType,
	IN ULONG dwParam);

typedef
SNCODE (__stdcall *PSnAPI_RemoveDeviceDriver)(
	IN ULONG dwDeviceType);

typedef
SNCODE (__stdcall *PSnAPI_GetAvailableDrivers)(
	OUT LPSTR sMultiSzStr,
	IN  ULONG dwBufferSize);

typedef
SNCODE (__stdcall *PSnAPI_GetDeviceDriverInfo)(
	IN ULONG dwDeviceType);

typedef
SNCODE (__stdcall *PSnAPI_InstallSecretNet)();

typedef
SNCODE (__stdcall *PSnAPI_RemoveSecretNet)();

#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif // __PUBLICTYPES_H__