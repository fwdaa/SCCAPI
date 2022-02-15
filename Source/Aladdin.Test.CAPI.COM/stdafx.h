#pragma once
#define _WIN32_WINNT 0x0501
#include <SDKDDKVer.h>

#define _ATL_XP_TARGETING // support for Windows XP
#include <atlbase.h>
#include <atlstr.h>
#include <atlpath.h>
#include <atlenc.h>

///////////////////////////////////////////////////////////////////////////////
// Используемые интерфейсы и библиотеки 
///////////////////////////////////////////////////////////////////////////////
#include "Aladdin.CAPI.COM.h"
#pragma comment(lib, "Aladdin.CAPI.COM.lib")

