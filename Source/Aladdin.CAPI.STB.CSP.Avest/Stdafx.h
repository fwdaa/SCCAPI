// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0501
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1

#define  ATRACE_COMPONENT_ID  ATRACE_SCCAPI_DLL_COMPONENT_ID
#include <atrace_comps.h>
#include <atracer.h>
#include <except.h>
#include <avcspdef.h>

using namespace System; 

///////////////////////////////////////////////////////////////////////////////
// Структура импорта ключа шифрования
///////////////////////////////////////////////////////////////////////////////
#pragma pack(push, 1)
typedef struct _AVEST_SIMPLE_BLOB
{
	BLOBHEADER	header;		// стандартный заголовок
	ALG_ID		algID;		// идентификатор алгоритма обмена
	BYTE		key[32];	// значение ключа
	BYTE		mac[ 4];	// значение имитовставки
	BYTE		encrypt;	// признак зашифрования
	DWORD		bitsNonce;	// размер нонки в битах
}
AVEST_SIMPLE_BLOB, *PAVEST_SIMPLE_BLOB;
#pragma pack(pop)

