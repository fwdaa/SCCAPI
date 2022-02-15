#pragma once

///////////////////////////////////////////////////////////////////////////////
// ѕрефикс вывода сообщений 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline const char* GetDebugPrefix() 
{ 
	// способ форматировани€ префикса
	return "[%9!d!]%8!04X!.%3!04X!::%4!016I64X! [%1!s!] %2!s! "; 
}
#else 
inline const char* GetDebugPrefix() 
{
	// получить параметры управлени€
	if (const ControlParameters* pControlParameters = GetControlParameters())
	{
		// получить способ форматировани€ префикса
		if (const char* szPrefix = pControlParameters->DebugPrefix()) 
		{
			// пропустить начальные пробелы
			szPrefix = szPrefix + strspn(szPrefix, " "); 

			// проверить указание префикса
			if (strcmp(szPrefix, "%0") != 0) return szPrefix; 

			// указать значение префикса по умолчанию
			return "[%9!d!]%8!04X!.%3!04X!::%4!s! [%1!s!] %2!s! "; 
		}
	}
	return nullptr; 
}
#endif
}
///////////////////////////////////////////////////////////////////////////////
// ¬ывод сообщени€ в отладчик
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline void DebugPrint(void*, int level, const char* szFormat, ...)
{
	// извлечь идентификатор компонента и уровень трассировки
	ULONG componentID = DPFLTR_IHVDRIVER_ID; switch (level)
	{
	// скорректировать уровень трассировки
	case TRACE_LEVEL_CRITICAL   : level = DPFLTR_ERROR_LEVEL  ; break; 
	case TRACE_LEVEL_ERROR      : level = DPFLTR_ERROR_LEVEL  ; break; 
	case TRACE_LEVEL_WARNING    : level = DPFLTR_WARNING_LEVEL; break; 
	case TRACE_LEVEL_INFORMATION: level = DPFLTR_INFO_LEVEL   ; break; 
	case TRACE_LEVEL_VERBOSE    : level = DPFLTR_TRACE_LEVEL  ; break; 
	}
    // перейти на переданные аргументы
    va_list args; va_start(args, szFormat); (void)componentID;

    // передать сообщение отладчику
    ::vDbgPrintEx(componentID, level, szFormat, args); va_end(args);
}
inline void DebugPrintV(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, va_list& args)
{
	// получить префикс форматировани€
	const char* szPrefixFormat = GetDebugPrefix();

	// передать сообщение отладчику
	wpp_vprintln(DebugPrint, nullptr, szPrefixFormat, szComponent, 
		szFlags, level, szFile, line, szFunction, noshrieks, szFormat, args
	); 
}
#else 
inline void FormatPrint(void* context, int, const char* szFormat, ...)
{
	// выполнить преобразование типа
	std::string* message = static_cast<std::string*>(context); 

    // перейти на переданные аргументы
    va_list args; va_start(args, szFormat);

    // отформатировать сообщение
    *message += vsprintf(szFormat, args); va_end(args); 
}
inline void DebugPrint(int, const char* szMessage)
{
#if defined WPP_DEBUG_STDOUT
	// вывести сообщение на экран
	printf(szMessage); 
#endif 
#if defined _WIN32
	// вывести сообщение в отладчик
	::OutputDebugStringA(szMessage); 

#elif defined __linux__
	// вывести сообщение в отладчик
#endif 
}
inline void DebugPrintV(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, va_list& args)
{
	// получить префикс форматировани€
	const char* szPrefixFormat = GetDebugPrefix(); if (!szPrefixFormat) return; 

	// установить локализацию операционной системы
	std::locale locale = std::locale::global(std::locale("")); std::string message;
	try { 
		// отформатировать сообщение
		wpp_vprintln(FormatPrint, &message, szPrefixFormat, szComponent, 
			szFlags, level, szFile, line, szFunction, noshrieks, szFormat, args
		); 
		// восстановить локализацию
		std::locale::global(locale); 
	}
	// при ошибке восстановить локализацию
	catch (...) { std::locale::global(locale); throw; }

	// передать сообщение отладчику
	DebugPrint(level, message.c_str()); 
}
#endif 

inline void DebugPrint(const char* szComponent, 
	const char* szFlags, int level, const char* szFile, int line, 
	const char* szFunction, bool noshrieks, const char* szFormat, ...)
{
    // перейти на переданные аргументы
    va_list args; va_start(args, szFormat);

    // передать сообщение отладчику
    DebugPrintV(szComponent, szFlags, level, 
		szFile, line, szFunction, noshrieks, szFormat, args
	); 
	va_end(args);
}
}
