// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0501
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <windows.h>

///////////////////////////////////////////////////////////////////////////////
// ќпределени€ SAL (дл€ сборки SDK 7)
///////////////////////////////////////////////////////////////////////////////
#if !defined _Field_size_bytes_
#define _Field_size_bytes_(size)
#endif 
#if !defined _In_reads_bytes_
#define _In_reads_bytes_(Length)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ќпределение VTableProvStruc
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WINXP)
typedef struct _VTableProvStruc {
    DWORD   Version;
    FARPROC FuncVerifyImage;
    FARPROC FuncReturnhWnd;
    DWORD   dwProvType;
    BYTE*	pbContextInfo;
    DWORD   cbContextInfo;
    LPSTR   pszProvName;
} VTableProvStruc, *PVTableProvStruc;
#endif

///////////////////////////////////////////////////////////////////////////////
// ќпределени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#define WPP_CONTROL_NAME CAPI
#define WPP_CONTROL_GUID (9FBE1F94, 4203, 4A56, 862C, 755504BCA37C)
#include "Trace.h"
#include "TraceWindows.h"

///////////////////////////////////////////////////////////////////////////////
// »спользуемые пространства имен
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

#include "cptumar.h"

///////////////////////////////////////////////////////////////////////////////////////////////////
// ѕроверить версию Windows
///////////////////////////////////////////////////////////////////////////////////////////////////
inline BOOL IsWindows(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	// указать провер€емые услови€
	DWORD dwMask = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR; DWORDLONG dwlCondition = 0; 

	// указать провер€емые услови€
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MAJORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MINORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL); 

	// указать значени€ версий
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 
		wMajorVersion, wMinorVersion, 0, 0, {0}, wServicePackMajor, 0 
	};
	// выполнить проверку версий
    return ::VerifyVersionInfoW(&osvi, dwMask, dwlCondition);
}
