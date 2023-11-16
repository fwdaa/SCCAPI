// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0501
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <windows.h>
#include <vcclr.h>

///////////////////////////////////////////////////////////////////////////////
// Определение ключевых слов C++11 (отсутствовал до Visual Studio 2012)
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER <= 1600
#define noexcept    
#endif

///////////////////////////////////////////////////////////////////////////////
// Определения SAL (для сборки SDK 7)
///////////////////////////////////////////////////////////////////////////////
#if !defined _Field_size_bytes_
#define _Field_size_bytes_(size)
#endif 
#if !defined _In_reads_bytes_
#define _In_reads_bytes_(Length)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определения трассировки
///////////////////////////////////////////////////////////////////////////////
#define WPP_CONTROL_NAME CAPI
#define WPP_CONTROL_GUID (9FBE1F94, 4203, 4A56, 862C, 755504BCA37C)
#include "Trace.h"
#include "TraceWindows.h"

///////////////////////////////////////////////////////////////////////////////
// Используемые пространства имен
///////////////////////////////////////////////////////////////////////////////
using namespace System; 
using namespace System::Text; 
using namespace System::IO; 
using namespace System::Collections::Generic; 
using namespace System::ComponentModel; 
using namespace System::Reflection;
using namespace System::Security::Permissions;
using namespace System::Runtime::InteropServices; 
using namespace System::Runtime::CompilerServices;
using namespace System::Windows::Forms;

///////////////////////////////////////////////////////////////////////////////////////////////////
// Проверить версию Windows
///////////////////////////////////////////////////////////////////////////////////////////////////
inline BOOL IsWindows(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	// указать проверяемые условия
	DWORD dwMask = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR; DWORDLONG dwlCondition = 0; 

	// указать проверяемые условия
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MAJORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MINORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL); 

	// указать значения версий
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 
		wMajorVersion, wMinorVersion, 0, 0, {0}, wServicePackMajor, 0 
	};
	// выполнить проверку версий
    return ::VerifyVersionInfoW(&osvi, dwMask, dwlCondition);
}

#if (NTDDI_VERSION <= NTDDI_WINXPSP2)
#define CALG_SHA_256	(ALG_CLASS_HASH | ALG_TYPE_ANY | 12)
#define CALG_SHA_384	(ALG_CLASS_HASH | ALG_TYPE_ANY | 13)
#define CALG_SHA_512	(ALG_CLASS_HASH | ALG_TYPE_ANY | 14)
#endif 

