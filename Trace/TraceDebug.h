#pragma once

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ��������� 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline const char* GetDebugPrefix() 
{ 
	// ������ �������������� ��������
	return "[%9!d!]%8!04X!.%3!04X!::%4!016I64X! [%1!s!] %2!s! "; 
}
#else 
inline const char* GetDebugPrefix() 
{
	// �������� ��������� ����������
	if (const ControlParameters* pControlParameters = GetControlParameters())
	{
		// �������� ������ �������������� ��������
		if (const char* szPrefix = pControlParameters->DebugPrefix()) 
		{
			// ���������� ��������� �������
			szPrefix = szPrefix + strspn(szPrefix, " "); 

			// ��������� �������� ��������
			if (strcmp(szPrefix, "%0") != 0) return szPrefix; 

			// ������� �������� �������� �� ���������
			return "[%9!d!]%8!04X!.%3!04X!::%4!s! [%1!s!] %2!s! "; 
		}
	}
	return nullptr; 
}
#endif
}
///////////////////////////////////////////////////////////////////////////////
// ����� ��������� � ��������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline void DebugPrint(void*, int level, const char* szFormat, ...)
{
	// ������� ������������� ���������� � ������� �����������
	ULONG componentID = DPFLTR_IHVDRIVER_ID; switch (level)
	{
	// ��������������� ������� �����������
	case TRACE_LEVEL_CRITICAL   : level = DPFLTR_ERROR_LEVEL  ; break; 
	case TRACE_LEVEL_ERROR      : level = DPFLTR_ERROR_LEVEL  ; break; 
	case TRACE_LEVEL_WARNING    : level = DPFLTR_WARNING_LEVEL; break; 
	case TRACE_LEVEL_INFORMATION: level = DPFLTR_INFO_LEVEL   ; break; 
	case TRACE_LEVEL_VERBOSE    : level = DPFLTR_TRACE_LEVEL  ; break; 
	}
    // ������� �� ���������� ���������
    va_list args; va_start(args, szFormat); (void)componentID;

    // �������� ��������� ���������
    ::vDbgPrintEx(componentID, level, szFormat, args); va_end(args);
}
inline void DebugPrintV(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, va_list& args)
{
	// �������� ������� ��������������
	const char* szPrefixFormat = GetDebugPrefix();

	// �������� ��������� ���������
	wpp_vprintln(DebugPrint, nullptr, szPrefixFormat, szComponent, 
		szFlags, level, szFile, line, szFunction, noshrieks, szFormat, args
	); 
}
#else 
inline void FormatPrint(void* context, int, const char* szFormat, ...)
{
	// ��������� �������������� ����
	std::string* message = static_cast<std::string*>(context); 

    // ������� �� ���������� ���������
    va_list args; va_start(args, szFormat);

    // ��������������� ���������
    *message += vsprintf(szFormat, args); va_end(args); 
}
inline void DebugPrint(int, const char* szMessage)
{
#if defined WPP_DEBUG_STDOUT
	// ������� ��������� �� �����
	printf(szMessage); 
#endif 
#if defined _WIN32
	// ������� ��������� � ��������
	::OutputDebugStringA(szMessage); 

#elif defined __linux__
	// ������� ��������� � ��������
#endif 
}
inline void DebugPrintV(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, va_list& args)
{
	// �������� ������� ��������������
	const char* szPrefixFormat = GetDebugPrefix(); if (!szPrefixFormat) return; 

	// ���������� ����������� ������������ �������
	std::locale locale = std::locale::global(std::locale("")); std::string message;
	try { 
		// ��������������� ���������
		wpp_vprintln(FormatPrint, &message, szPrefixFormat, szComponent, 
			szFlags, level, szFile, line, szFunction, noshrieks, szFormat, args
		); 
		// ������������ �����������
		std::locale::global(locale); 
	}
	// ��� ������ ������������ �����������
	catch (...) { std::locale::global(locale); throw; }

	// �������� ��������� ���������
	DebugPrint(level, message.c_str()); 
}
#endif 

inline void DebugPrint(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, ...)
{
    // ������� �� ���������� ���������
    va_list args; va_start(args, szFormat);

    // �������� ��������� ���������
    DebugPrintV(szComponent, szFlags, level, 
		szFile, line, szFunction, noshrieks, szFormat, args
	); 
	va_end(args);
}
}
