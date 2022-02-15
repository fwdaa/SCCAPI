//---------------------------------------------------------------------------------------------------
// Copyright: (c) 1998-2001 Информзащита, Россия
//---------------------------------------------------------------------------------------------------
// $Archive: /Common/Include/snellock.H $	
// $Revision: 35 $
// $Date: 28.11.03 16:24 $
// Unit:        
// Author:      Денис Иванов, Сергей Зайцев
// Responsible: Дмитрий Борисов
//---------------------------------------------------------------------------------------------------
// Description: Описания и константы для работы с Snellock.dll
//---------------------------------------------------------------------------------------------------
// Modification History: 
//
// 01.02.2001 * В файл добавлен стандартный заголовок
//---------------------------------------------------------------------------------------------------

#ifndef __SNELZAM_H__
#define __SNELZAM_H__

#include "HwProviderPublicConst.h"
#include "HwProviderPublicTypes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef SNELLOCK_EXPORTS
#define DLLAPI __declspec(dllexport)
#else
#define DLLAPI __declspec(dllimport)
#endif

/***************************************************************
	SNCODE and TYPE_TM defined in HwProviderPublicTypes.h

#if !defined(SNCODE)
typedef long SNCODE;
#endif // !defined(SNCODE)

#if !defined(_TYPE_TM_)

typedef enum _TYPE_TM{
	ExternalTm,
	InternalTm,
	Memory0,
	Memory1
} TYPE_TM, *PTYPE_TM;
#define _TYPE_TM_

#endif // !defined(TYPE_TM)

****************************************************************/

#ifndef __SNLOCKIOCTL_H__
#define __SNLOCKIOCTL_H__

typedef unsigned char  UCHAR;
typedef unsigned short USHORT;
typedef unsigned long  ULONG;
typedef UCHAR  BYTE;
typedef USHORT WORD;
typedef ULONG  DWORD;

//	Это тип устройства

#define ELLOCK 40001		// Device ID for PCISable

//	Коды команд, исполняемых драйвером PCISable

#define IOCTL_CHECK_ADMIN       CTL_CODE(ELLOCK, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define IOCTL_CHECK_CARD        CTL_CODE(ELLOCK, 0x901, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define IOCTL_GET_PATH          CTL_CODE(ELLOCK, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define IOCTL_SET_PATH          CTL_CODE(ELLOCK, 0x903, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define IOCTL_LOCK_MEMORY       CTL_CODE(ELLOCK, 0x904, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define IOCTL_READ_MEM          CTL_CODE(ELLOCK, 0x001, METHOD_BUFFERED, FILE_READ_ACCESS )
#define IOCTL_WRITE_MEM         CTL_CODE(ELLOCK, 0x002, METHOD_BUFFERED, FILE_WRITE_ACCESS | FILE_READ_ACCESS )
#define IOCTL_QUERY_INFORMATION CTL_CODE(ELLOCK, 0x003, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SET_INFORMATION   CTL_CODE(ELLOCK, 0x004, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_DEVICE_CONTROL    CTL_CODE(ELLOCK, 0x005, METHOD_BUFFERED, FILE_WRITE_ACCESS | FILE_READ_ACCESS )
#define IOCTL_GET_RAND          CTL_CODE(ELLOCK, 0x006, METHOD_BUFFERED, FILE_READ_ACCESS )
#define IOCTL_VDD_REQUEST       CTL_CODE(ELLOCK, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define VDDREQ_SEEPSELECT         1			// Select NVRAM bank for further operations
#define VDDREQ_SEEPREAD           2			// Read data from selected NVRAM bank
#define VDDREQ_SEEPWRITE          3			// Write data to selected NVRAM bank
#define VDDREQ_TMREADID           0x10		// Read token ID
#define VDDREQ_TMREAD             0x11		// Read token data
#define VDDREQ_TMWRITE            0x12		// Write data to token
#define VDDREQ_TMSELECT           0x13		// Select token reader (internal/external)
#define VDDREQ_TMRESET            0x14		// Send reset pulse to token
#define VDDREQ_GETRNDBYTE         0x20		// Get one byte from random number generator
#define VDDREQ_GETRNDBYTES        0x21		// Generate array of random number bytes
#define VDDREQ_READJUMPER         0x30		// Read jumper state
#define VDDREQ_SHORTSWITCHES      0x31		// Short all switches on board
#define VDDREQ_OPENSWITCHES       0x32		// Open all switches on board
#define VDDREQ_GETRELAYINITSTATE  0x33		// Get initial state of onboard relays
#define VDDREQ_SETRELAYINITSTATE  0x34		// Set initial state of onboard relays
#define VDDREQ_STARTWATCHDOG      0x40		// Start watchdog
#define VDDREQ_STOPWATCHDOG       0x41		// Stop watchdog
#define VDDREQ_GETWATCHDOGTIMEOUT 0x42		// Get watchdog timeout
#define VDDREQ_SETWATCHDOGTIMEOUT 0x43		// Set watchdog timeout
#define VDDREQ_LOCKBOARD          0x50		// Lock board
#define VDDREQ_READLOCK           0x51		// Read board lock state

typedef struct _VDDREQ_DATA
{
	UCHAR  Command;
	int    Param1;				// Custom parameters (type and meaning may vary depending on request command)
	int    Param2;
	int    Param3;
	int    Param4;
	UCHAR  Buffer[0];			// Input/output data buffer for bulk operations
} VDDREQ_DATA, *PVDDREQ_DATA;

#endif // __SNLOCKIOCTL_H__

typedef struct _TYPE_INFO_DEVICE{
	short          Type;
	unsigned short Size;
	unsigned long  Port;
	unsigned short NameLength;
	char           Name[1];
} TYPE_INFO_DEVICE, *PTYPE_INFO_DEVICE;

#pragma pack(push,1)
typedef struct _VERSION_INFO
{
	BYTE  Major;
	BYTE  Minor;
	WORD  Build;
} VERSION_INFO, *PVERSION_INFO;
#pragma pack(pop)

#ifndef SN_OK
#define SN_OK           0	//Операция выполнена неуспешно
#endif

#define SNHW_ERROR      1	//Нет драйвера поддержки (только для NT)
#define SNHW_NOCARD     2	//Отсутствует плата ЭЗ в компьютере
#define SNHW_BADUSER    3	//Текущий пользователь не является администратором
#define SNHW_BADINPUT   4	//Неправильные входные параметры 
#define SNHW_BADSIZE    5	//Неправильный размер передаваемых данных
#define SNHW_CARDERROR  6	//Ошибка аппаратуры
#define SNHW_BADOP      7	//Ошибка выполнения команды
#define SNHW_NOTM       8	//ТМ не прижата

#define PARAM_OFFSET 1024
/*
	Назначение	Позволяет проверить наличие платы ЭЗ в компьютере
	Синтаксис	SNCODE sbisCard (void)
	Вход:	 Нет
	Выход:	Код завершения
	· Если код ошибки == SN_OK, то плата ЭЗ установлена на компьютере
	· Иначе - плата не установлена
*/
DLLAPI SNCODE __stdcall sbisCard(void);

/*
	Назначение	Позволяет проверить тип пользователя 
	Синтаксис	SNCODE  sbisAdmin(void)
	Вход	Нет
	Выход	Код завершения
	· Если код ошибки == SN_OK, то в систему вошел администратор
	· Иначе - в систему вошел обычный пользователь
*/
DLLAPI SNCODE __stdcall sbisAdmin(void);

/*
	Назначение	Позволяет получить путь к файлам, хранимый в электронном замке
	Синтаксис	SNCODE sbReadPathName (LPTSTR PathName, ULONG * uSize)
	Вход	(OUT) PathName - адрес буфера для чтения пути к файлам (ANSI)
	(IN/OUT) uSize - указатель на переменную, содержащую размер буфера
	Выход	Код завершения
	· Если код ошибки == SN_OK, то путь к файлам успешно считан. 
	· Если код ошибки == SN_BADSIZE, то в переменной uSize находится размер буфера, необходимый для успешного чтения 
	· Иначе - путь к файлам не считан в буфер
*/
DLLAPI SNCODE __stdcall sbReadPathName ( char* PathName, unsigned long *uSize );

/*
	Назначение	Позволяет сохранить путь к файлам, хранимый в электронном замке
	Синтаксис	SNCODE sbSavePathName (LPTSTR  PathName)
	Вход	(IN) PathName - адрес буфера с путем к файлам (ANSI)  
	Выход	Код завершения
	· Если код ошибки == SN_OK, путь успешно записан во внутреннюю память электронного замка
	· Иначе - путь к файлам не записан
*/
DLLAPI SNCODE __stdcall sbSavePathName(char* PathName);
DLLAPI SNCODE __stdcall sbReadMem(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize, unsigned long Offset, unsigned long* ReadLength);
DLLAPI SNCODE __stdcall sbWriteMem(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize, unsigned long Offset, unsigned long* WriteLength);
DLLAPI SNCODE __stdcall sbReadID(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize);
DLLAPI SNCODE __stdcall sbReadConfiguration(PTYPE_INFO_DEVICE Buffer, unsigned long BufferSize);
DLLAPI SNCODE __stdcall sbLockMem();
DLLAPI SNCODE __stdcall sbGetRand(void * Buffer, unsigned long BufferSize);
DLLAPI SNCODE __stdcall sbGetVersion(PVERSION_INFO pVerInfo);

/*
	Типы для экспорта функций из DLL
*/
typedef SNCODE ( __stdcall *psbisCard)(void);
typedef SNCODE ( __stdcall *psbisAdmin)(void);
typedef SNCODE ( __stdcall *psbReadPathName)(char* PathName, unsigned long *uSize);
typedef SNCODE ( __stdcall *psbSavePathName)(char*  PathName);
typedef SNCODE ( __stdcall *psbReadMem)(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize, unsigned long Offset, unsigned long* ReadLength);
typedef SNCODE ( __stdcall *psbWriteMem)(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize, unsigned long Offset, unsigned long* WriteLength);
typedef SNCODE ( __stdcall *psbReadID)(TYPE_TM TypeTm, void* Buffer, unsigned long BufferSize);
typedef SNCODE ( __stdcall *psbReadConfiguration)(PTYPE_INFO_DEVICE Buffer, unsigned long BufferSize);
typedef SNCODE ( __stdcall *psbLockMem)();
typedef SNCODE ( __stdcall *psbGetRand)(void * Buffer, unsigned long BufferSize);
typedef SNCODE ( __stdcall *psbGetVersion)(PVERSION_INFO pVerInfo);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif __SNELZAM_H__
