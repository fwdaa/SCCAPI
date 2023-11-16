#pragma once 
#define _CRT_SECURE_NO_WARNINGS

///////////////////////////////////////////////////////////////////////////////
// ����������� nullptr (������������ �� Visual Studio 2010)
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1600
#if !defined _MANAGED || _MANAGED == 0
#define nullptr 0
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ ������������ �������
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#define _WIN32_WINNT 0x0501
#include <windows.h>
#elif defined __linux__
#include <unistd.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#define WPP_CONTROL_NAME CAPI
#if defined _WIN32
#define WPP_CONTROL_GUID (3B61FCBE, EB57, 47FB, 8DBC, E2A9E8EC8F5C)
#endif 
#include "Trace.h"
#include "TraceOpenSSL.h"

