// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0600
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <windows.h>
#include <vcclr.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ���� C++11 (������������ �� Visual Studio 2012)
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER <= 1600
#define override    
#define noexcept    
#endif

///////////////////////////////////////////////////////////////////////////////
// ����������� SAL (��� ������ SDK 7)
///////////////////////////////////////////////////////////////////////////////
#if !defined _Field_size_bytes_
#define _Field_size_bytes_(size)
#endif 
#if !defined _In_reads_bytes_
#define _In_reads_bytes_(Length)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#define WPP_CONTROL_NAME CAPI
#define WPP_CONTROL_GUID (9FBE1F94, 4203, 4A56, 862C, 755504BCA37C)
#include "Trace.h"
#include "TraceWindows.h"

#include <bcrypt.h>
#include <ncrypt.h>

///////////////////////////////////////////////////////////////////////////////
// ������������ ������������ ����
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
// ��������� ������ Windows
///////////////////////////////////////////////////////////////////////////////////////////////////
inline BOOL IsWindows(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	// ������� ����������� �������
	DWORD dwMask = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR; DWORDLONG dwlCondition = 0; 

	// ������� ����������� �������
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MAJORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_MINORVERSION    , VER_GREATER_EQUAL); 
	dwlCondition = VerSetConditionMask(dwlCondition, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL); 

	// ������� �������� ������
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 
		wMajorVersion, wMinorVersion, 0, 0, {0}, wServicePackMajor, 0 
	};
	// ��������� �������� ������
    return ::VerifyVersionInfoW(&osvi, dwMask, dwlCondition);
}
