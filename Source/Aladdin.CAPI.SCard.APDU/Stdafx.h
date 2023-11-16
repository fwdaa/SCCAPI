// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _WIN32_WINNT  0x0501
#define _BIND_TO_CURRENT_VCLIBS_VERSION 1
#include <winscard.h>
#include <vcclr.h>
#pragma comment (lib, "winscard.lib")

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
using namespace System::Reflection;
using namespace System::Security::Permissions;
using namespace System::Security::Authentication;
using namespace System::Runtime::InteropServices; 
using namespace System::Runtime::CompilerServices;

#define WINDOWS
#include <libapdu.h>
#include <libapdu.helper.h>
#include <..\token\libapdu.internal.h>
#include <..\utils\bertlv.h>
#include <..\crypto\crypto.h>

