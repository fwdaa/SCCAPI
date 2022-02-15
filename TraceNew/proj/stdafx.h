#pragma once

#ifdef _KERNEL_MODE
#include <ntifs.h>
#elif defined _WIN32
#include <windows.h>
#else
#endif 

#define WPP_CONTROL_NAME Trace
#if defined _WIN32
#define WPP_CONTROL_GUID (00000000, 0000, 0000, 0000, 000000000000)
#endif
#include "../Trace.h"
