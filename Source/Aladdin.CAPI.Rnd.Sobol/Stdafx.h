// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0501
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <windows.h>

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
#pragma warning (push)
#pragma warning (disable:28193) // 'pControlParameters' holds a value that must be examined
#define WPP_CONTROL_NAME CAPI
#define WPP_CONTROL_GUID (9FBE1F94, 4203, 4A56, 862C, 755504BCA37C)
#include "Trace.h"
#pragma warning (pop)

///////////////////////////////////////////////////////////////////////////////
// Используемые пространства имен
///////////////////////////////////////////////////////////////////////////////
using namespace System; 
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;

///////////////////////////////////////////////////////////////////////////////
// Используемые заголовочные файлы
///////////////////////////////////////////////////////////////////////////////
#include "HwProviderPublicConst.h"
#include "HwProviderPublicTypes.h"

#pragma warning(push)
#pragma warning(disable: 4200)
#include "snellock.h"
#pragma warning(pop)
