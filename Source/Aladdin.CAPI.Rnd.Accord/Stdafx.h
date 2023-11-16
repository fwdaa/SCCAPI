// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0500
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <windows.h>

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

///////////////////////////////////////////////////////////////////////////////
// ������������ ������������ ����
///////////////////////////////////////////////////////////////////////////////
using namespace System; 
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;

