#pragma once
#include <stdio.h>
#include <limits.h>

///////////////////////////////////////////////////////////////////////////////
// Используемые библиотеки
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && !defined _NTDDK_
#pragma comment(lib, "ole32.lib")
#endif

///////////////////////////////////////////////////////////////////////////////
// Форматирование данных 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if !defined _MSC_VER
inline void strncpy_s(char* dest, size_t size, const char* source, size_t count)
{
	// скорректировать размер
	if (count > size - 1) { count = size - 1; } 

	// скопировать символы строки и завершить строку
	::strncpy(dest, source, count); dest[size - 1] = '\0'; 
}
inline int vsnprintf(char* buffer, size_t size, const char* format, va_list args)
{
	// выполнить форматирование строки
	return ::vsnprintf(buffer, size, format, args); 
}
inline int snprintf(char* buffer, size_t size, const char* format, ...)
{
    // перейти на переданные аргументы
    va_list args; va_start(args, format);

	// выполнить форматирование строки
    int cch = ::vsnprintf(buffer, size, format, args);

    // освободить выделенные ресурсы
    va_end(args); return cch;
}
inline int snprintf_ptr(char* buffer, size_t size, const void* ptr)
{
	// указать число цифр адреса и строку форматирования
	int digits = (int)(sizeof(ptr) * 2); const char* szFormat = "%0*zX"; 

    // отформатировать адрес
    return snprintf(buffer, size, szFormat, digits, (uintptr_t)ptr); 
}
#else 
inline void strncpy_s(char* dest, size_t size, const char* source, size_t count)
{
	// скопировать символы строки с завершающим нулем
	if (size > 0) ::strncpy_s(dest, size, source, count); 
}
inline int vsnprintf(char* buffer, size_t size, const char* format, va_list args)
{
	// определить требуемый размер буфера
	int cch = ::_vscprintf(format, args); if (cch <= 0 || size == 0) return cch; 

    // отформатировать сообщение
	return (::_vsnprintf_s(buffer, size, _TRUNCATE, format, args) >= 0) ? cch : -1; 
}
inline int snprintf(char* buffer, size_t size, const char* format, ...)
{
    // перейти на переданные аргументы
    va_list args; va_start(args, format);

	// выполнить форматирование строки
    int cch = vsnprintf(buffer, size, format, args);

    // освободить выделенныве ресурсы
    va_end(args); return cch;
}
inline int snprintf_ptr(char* buffer, size_t size, const void* ptr)
{
	// указать число цифр адреса и строку форматирования
	int digits = (int)(sizeof(ptr) * 2); const char* szFormat = "%0*IX"; 

    // отформатировать адрес
    return snprintf(buffer, size, szFormat, digits, (uintptr_t)ptr); 
}
#endif 

#if !defined _NTDDK_
inline std::string vsprintf(const char* format, va_list args)
{
	// определить требуемый размер буфера
	int cch = vsnprintf(nullptr, 0, format, args); if (cch <= 0) return std::string(); 

    // отформатировать сообщение
	std::string str(cch + 1, 0); cch = vsnprintf(&str[0], cch + 1, format, args); 

	// вернуть строку
	if (cch <= 0) { return std::string(); } str.resize(cch); return str; 
}

inline std::string sprintf(const char* format, ...)
{
    // перейти на переданные аргументы
    va_list args; va_start(args, format);

    // отформатировать сообщение
    std::string str = vsprintf(format, args);

    // вернуть сообщение
    va_end(args); return str;
}
#endif 
}
///////////////////////////////////////////////////////////////////////////////
// Найти позицию первого совпавшего символа в наборе
///////////////////////////////////////////////////////////////////////////////
namespace trace {
inline size_t strcspn(const char* string, const char* control)
{
	// выполнить преобразование типа
	const unsigned char* str  = (const unsigned char*)string;
    const unsigned char* ctrl = (const unsigned char*)control;

	// битовая карта требуемых символов
	unsigned char map[32] = {0}; map[0] |= 1; int count = 0;
	
	// заполнить битовую карту требуемых символов
	for (; *ctrl; ctrl++) map[(*ctrl >> 3) & 0x1F] |= (unsigned char)(1 << (*ctrl & 7));

    // пропустить все несовпадающие символы
	for (; !(map[*str >> 3] & (1 << (*str & 7))); str++, count++) {}

    return count;
}
}
///////////////////////////////////////////////////////////////////////////////
// Номер процессора, идентификтор текущего процесса и потока. 
// Номер процессора       форматируется как переменная типа unsigned int.
// Идентификатор процесса форматируется как переменная типа unsigned int.
// Идентификатор потока   форматируется как переменная типа unsigned long int.
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline ULONG current_processor()
{
	// определить номер процессора
	return ::KeGetCurrentProcessorNumber(); 
}
inline ULONG current_process()
{
	// определить идентификатор процесса
	return (ULONG)(SIZE_T)::PsGetCurrentProcessId(); 
}
inline ULONG current_thread()
{
	// определить идентификатор потока
	return (ULONG)(SIZE_T)::PsGetCurrentThreadId(); 
}
#elif defined _WIN32
inline DWORD current_process()
{
	// определить идентификатор процесса
	return ::GetCurrentProcessId(); 
}
inline DWORD current_thread()
{
	// определить идентификатор потока
	return ::GetCurrentThreadId();
}
#if (_WIN32_WINNT < 0x0502)
inline DWORD current_processor() { return 1; }
#else
inline DWORD current_processor()
{
	// определить номер процессора
	return ::GetCurrentProcessorNumber(); 
}
#endif 
#elif defined __linux__
inline int       current_processor() { return ::sched_getcpu(); }
inline pid_t     current_process  () { return ::getpid      (); }
inline pthread_t current_thread   () { return ::pthread_self(); }
#endif 

///////////////////////////////////////////////////////////////////////////////
// Текущее время. В режиме ядра форматируется как переменная типа 
// unsinged __int64, в режиме пользователя форматируется как переменная 
// типа const char* после вызова функции объекта c_str().
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_
inline LARGE_INTEGER current_datetime()
{
	// получить текущее системное время 
	LARGE_INTEGER st; KeQuerySystemTime(&st); 

	// получить текущее локальное время 
	LARGE_INTEGER lt; ::ExSystemTimeToLocalTime(&st, &lt); return lt; 
}
#elif defined _WIN32
inline std::string datetime_string(const SYSTEMTIME& st)
{
	// указать идентификатор локализации
	LCID lcid = LOCALE_SYSTEM_DEFAULT; std::string datetime;  

	// определить требуемый размер буфера
	int cchDate = ::GetDateFormatA(lcid, 0, &st, nullptr, nullptr, 0); 
	int cchTime = ::GetTimeFormatA(lcid, 0, &st, nullptr, nullptr, 0); 

	// выделить буфер требуемого размера
	datetime.resize(cchDate + cchTime); PSTR szDateTime = &datetime[0]; 

	// отформатировать дату
	cchDate = ::GetDateFormatA(lcid, 0, &st, nullptr, szDateTime, cchDate); 	

	// перейти на время 
	szDateTime += strlen(szDateTime); *szDateTime++ = ' '; 

	// отформатировать время
	cchTime = ::GetTimeFormatA(lcid, 0, &st, nullptr, szDateTime, cchTime); 	

	return datetime; 
}
inline std::string current_datetime()
{
	// отформатировать текущее время
	SYSTEMTIME st; ::GetLocalTime(&st); return datetime_string(st); 
}
#elif defined __linux__
inline std::string current_datetime()
{
	// получить текущее время
	time_t result = ::time(0); char str[26];  

	// отформатировать время
	::ctime_r(&result, str); return std::string(str, 24); 
}
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Извлечение аргументов из списка переменного размера
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T>
inline T valist_extract(va_list& args) { return va_arg(args, T); }

template <>
inline char valist_extract<char>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<char>(va_arg(args, int)); 
}
template <>
inline signed char valist_extract<signed char>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<signed char>(va_arg(args, signed int)); 
}
template <>
inline unsigned char valist_extract<unsigned char>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<unsigned char>(va_arg(args, unsigned int)); 
}
#if defined _MSC_VER
#if !defined _WCHAR_T_DEFINED
template <>
inline wchar_t valist_extract<wchar_t>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<wchar_t>(va_arg(args, unsigned int)); 
}
#endif 
#elif WCHAR_MAX <= UINT_MAX
template <>
inline wchar_t valist_extract<wchar_t>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<wchar_t>(va_arg(args, unsigned int)); 
}
#endif 

template <>
inline signed short valist_extract<signed short>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<signed short>(va_arg(args, signed int)); 
}
template <>
inline unsigned short valist_extract<unsigned short>(va_list& args) 
{ 
	// извлечь аргумент
	return static_cast<unsigned short>(va_arg(args, unsigned int)); 
}
}
///////////////////////////////////////////////////////////////////////////////
// Типы данных MOF (Managed Object Format). Список не является полным: указаны
// только типы, на которые есть ссылки в файле defaultwpp.ini конфигурации WPP, 
// а также типы, подробное описание которых упомянуто на компьютерных форумах. 
///////////////////////////////////////////////////////////////////////////////
// 1. Перечислимые типы значений:
//	  1) ItemListByte - список имен значений для перечислимого типа, 
//       начиная с нуля:
//       представление  = значение размера 1 байт;
//       форматирование = имя из списка определения типа;
//    2) ItemSetByte - список имен значений битов для перечислимого типа, 
//       начиная с младшего:
//       представление  = значение размера 1 байт;
//       форматирование = комбинация имен из определения списка;
//    3) ItemListShort - список имен значений для перечислимого типа, 
//       начиная с нуля:
//       представление  = значение размера 2 байта;
//       форматирование = имя из списка определения типа;
//    4) ItemSetShort - список имен значений битов для перечислимого типа, 
//       начиная с младшего:
//       представление  = значение размера 2 байта;
//       форматирование = комбинация имен из определения списка;
//    5) ItemListLong - список имен значений для перечислимого типа, 
//       начиная с нуля:
//       представление  = значение размера 4 байта;
//       форматирование = имя из списка определения типа;
//    6) ItemSetLong - список имен значений битов для перечислимого типа, 
//       начиная с младшего:
//       представление  = значение размера 4 байта;
//       форматирование = комбинация имен из определения списка;
//    7) ItemEnum - перечисление C++ взаимоисключающих значений:
//       представление  = значение размера 4 байта;
//       форматирование = имя из C++-определения перечисления 
//                        (если доступен .PDB-файл);
//    8) ItemFlagsEnum - перечисление C++ взаимодополняющих флагов:
//       представление  = значение размера 4 байта;
//       форматирование = комбинация имен из C++-определения перечисления 
//                        (если доступен .PDB-файл);
// 2. Простейшие типы значений (значений с фиксированным размером): 
//     1) ItemChar - знаковое 8-разрядное число:
//        представление  = значение размера 1 байт;
//        форматирование = ;
//     2) ItemUChar - беззнаковое  8-разрядное число:
//        представление  = значение размера 1 байт;
//        форматирование = ;
//     3) ItemShort - знаковое 16-разрядное число:
//        представление  = значение размера 2 байта;
//        форматирование = 
//          d, hd = десятичное знаковое представление;
//          u, hu = десятичное беззнаковое представление;
//          o, ho = восьмеричное представление;
//          x, hx = шестнадцатеричное строчное представление;
//          X, hX = шестнадцатеричное прописное представление;
//     4) ItemChar4 - знаковое 32-разрядное число:         
//        представление  = значение размера 4 байта;
//        форматирование = 
//			s = символьное представление из 4 байтов; 
//     5) ItemLong - знаковое 32-разрядное число:
//        представление  = значение размера 4 байта;
//        форматирование = 
//          d, ld = десятичное знаковое представление;
//          u, lu = десятичное беззнаковое представление;
//          o, lo = восьмеричное представление;
//          x, lx = шестнадцатеричное строчное представление;
//          X, lX = шестнадцатеричное прописное представление;
//     6) ItemLongLong - знаковое 64-разрядное число:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          I64d  = десятичное знаковое представление;
//     7) ItemULongLong - беззнаковое 64-разрядное число:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          I64u = десятичное беззнаковое представление;
//     8) ItemLongLongO - знаковое 64-разрядное число:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          I64o = восьмеричное представление;
//     9) ItemLongLongX - знаковое 64-разрядное число:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          I64x = шестнадцатеричное строчное представление;
//    10) ItemLongLongXX - знаковое 64-разрядное число:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          I64X = шестнадцатеричное прописное представление;
//    11) ItemPtr - адрес (указатель) или число разрядности адреса:
//        представление  = значение размера 4/8 байт;
//        форматирование = 
//          Id = десятичное знаковое представление;
//          Iu = десятичное беззнаковое представление;
//          Io = восьмеричное представление;
//          Ix = шестнадцатеричное строчное представление;
//          IX = шестнадцатеричное прописное представление;
//          p  = шестнадцатеричное представление адреса;
//    12) ItemDouble - число с плавающей точкой:
//        представление  = значение размера 8 байт;
//        форматирование = 
//          s = строковое представление числа; 
//    13) ItemGuid - уникальный идентификатор GUID:
//        представление  = значение размера 16 байт;
//        форматирование = 
//          s = строковое представление GUID; 
//    14) ItemIID - идентификатор интерфейса (IID):
//        представление  = значение размера 16 байт;
//        форматирование = 
//          s = имя интерфейса IID (например, IUnknown); 
//    15) ItemCLSID - идентификатор компонента (CLSID):
//        представление  = значение размера 16 байт;
//        форматирование = 
//          s = дружественное имя CLSID; 
//    16) ItemLIBID - идентификатор библиотеки типов (LIBID):
//        представление  = значение размера 16 байт;
//        форматирование = 
//          s = дружественное имя LIBID; 
//    17) ItemTimestamp - отметка времени: 
//        представление  = значение FILETIME размера 8 байт;
//        форматирование = 
//          s = системное представление времени; 
//    18) ItemTimeDelta - продолжительность периода времени: 
//        представление  = число миллисекунд размера 8 байт;
//        форматирование = 
//          s = системное представление продолжительности периода времени; 
//    19) ItemWaitTime - продолжительность периода ожидания: 
//        представление  = число миллисекунд размера 8 байт;
//        форматирование = 
//          s = системное представление продолжительности периода времени; 
//    20) ItemMACAddr - MAC-адрес: 
//         представление = MAC-адрес размера 6 байт;
//         форматирование = 
//          s = MAC-адрес в формате xx:xx:xx:xx:xx:xx; 
//    21) ItemIPAddr - адрес IPv4: 
//         представление = адрес IPv4 размера 4 байта;
//         форматирование = 
//          s = адрес IPv4 в формате xxx.xxx.xxx.xxx; 
//    22) ItemIPV6Addr - адрес IPv6: 
//         представление = адрес IPv6 размера 16 байт;
//         форматирование = 
//          s = строковое представление IPv6-адреса; 
//    23) ItemPort - номер порта TCP/IP: 
//         представление = номер порта размера 2 байта;
//         форматирование = 
//          s = строковое представление номера порта; 
//    24) ItemNTerror - текст ошибки NTSTATUS: 
//         представление = код ошибки NTSTATUS размера 4 байта;
//         форматирование = 
//          s = текст ошибки NTSTATUS; 
//    25) ItemNTSTATUS - cимволическое имя ошибки NTSTATUS: 
//         представление = код ошибки NTSTATUS размера 4 байта;
//         форматирование = 
//          s = cимволическое имя ошибки NTSTATUS; 
//    26) ItemWINERROR - cимволическое имя ошибки WinAPI: 
//         представление = код ошибки WinAPI размера 4 байта;
//         форматирование = 
//          s = cимволическое имя ошибки WinAPI; 
//    27) ItemHRESULT - cимволическое имя ошибки HRESULT: 
//         представление = код ошибки HRESULT размера 4 байта;
//         форматирование = 
//          s = cимволическое имя ошибки HRESULT; 
// 3. Составные типы значений (значений с переменным размером): 
//     1) ItemString - ANSI-строка с завершающим нулем: 
//        представление  = ANSI-кодировка строки с завершающим \0;
//        форматирование = 
//          s = символьное представление строки; 
//     2) ItemWString - Unicode-строка с завершающим нулем: 
//        представление  = UTF16-LE-кодировка строки с завершающим \0;
//        форматирование = 
//          s = символьное представление строки; 
//     3) ItemRString - ANSI-строка с завершающим нулем: 
//        представление  = ANSI-кодировка строки с завершающим \0;
//        форматирование = 
//          s = символьное представление строки после замены символов 
//               \t, \n, \r на пробелы и удаления завершающих пробелов; 
//     4) ItemRWString - Unicode-строка с завершающим нулем: 
//        представление  = UTF16-LE-кодировка строки с завершающим \0;
//        форматирование = 
//          s = символьное представление строки после замены символов 
//               \t, \n, \r на пробелы и удаления завершающих пробелов;
//     5) ItemPString - ANSI-строка с указанием размера: 
//        представление  = 
//          два байта = размер ANSI-кодировки строки в байтах (без завершающего \0); 
//          далее     = ANSI-кодировка строки без завершающего \0; 
//        форматирование = 
//          s = символьное представление строки; 
//     6) ItemPWString - Unicode-строка с указанием размера: 
//        представление  = 
//          два байта = размер UTF16-LE-кодировки строки в байтах (без завершающего \0); 
//          далее     = UTF16-LE-кодировка строки без завершающего \0; 
//        форматирование = 
//          s = символьное представление строки; 
//     7) ItemHEXDump - бинарный буфер: 
//        представление  = 
//          два байта = размер буфера в байтах; 
//          далее     = бинарное содержимое буфера; 
//        форматирование = 
//          s = шестнадцатеричное представление содержимого буфера; 
//     8) ItemSid - идентификатор безопасности (SID): 
//        представление  = бинарное содержимое SID; 
//        форматирование = 
//          s = строковое представление SID; 

///////////////////////////////////////////////////////////////////////////////
// При обработке строки форматирования препроцессор WPP извлекает из нее 
// спецификации вида %<NAME> и %!<NAME>!. Извлеченное имя <NAME> является 
// именем типа WPP, описание которого содержится в стандартном 
// конфигурационном файле defaultwpp.ini. В отличии от типа MOF, который 
// допускает различные способы форматирования, тип WPP связан с единственным 
// способом форматирования (и единственным типом MOF). 
// Типы WPP делятся на 3 категории: перечислимые, простейшие и составные. 
// При использовании простейших и составных типов препроцессору WPP приходится 
// генерировать оберточные функции WPP_SF_<SIG1>...<SIGN>, которые через 
// свои формальные параметры принимают параметры строки форматирования, а 
// тело оберточной функции через предопределенные макросы раскрывает 
// переданные параметры в пары (адрес, размер), передаваемые функции 
// трассировки (по умолчанию, TraceMessage). Для простейших типов (типов, 
// значения которых имеют фиксированный размер) предопределенными макросами 
// являются макросы WPP_LOGTYPEVAL и WPP_LOGTYPEPTR. Макрос WPP_LOGTYPEVAL 
// создает пару (адрес, размер) для типов, передаваемых по значению, а 
// макрос WPP_LOGTYPEPTR создает пару (адрес, размер) для типов, передаваемых 
// через указатель. Для составных типов (типов, значения которых имеют 
// переменный размер) предопределенные макросы должны определяться отдельно 
// и их имя должно быть указано в макросе определения составного типа 
// (DEFINE_CPLX_TYPE). Предопределенные макросы должны определяться на 
// основе макроса WPP_LOGPAIR, который преобразуется в отдельную пару 
// (адрес, размер). 
// Кроме того, для всех строк форматирования препроцессор WPP создает 
// TMF-строку форматирования и указывает соответствие всех ее параметров 
// типам MOF, которое впоследствии на этапе связывания помещается в 
// .PDB-файл. Строка форматирования TMF отличается от исходной строки 
// форматирования тем, что вместо исходных спецификаций %<NAME> и %!<NAME>! 
// в нее помещаются MOF-спецификации %<NUMBER>!<FORMATSPEC>!, где в качестве 
// <NUMBER> указывается номер аргумента, начиная с индекса 10 (первые 
// 9 зарезервированы), а в качестве <FORMATSPEC> указывается способ 
// форматирования MOF (например, %10!I64X!). Кроме того, TMF-строка 
// форматирования начинается с %0 (что означает добавление стандартного 
// префикса при выводе). Префикс и суффикс (окончание) строки форматирования 
// можно переопределить при помощи директив препроцессора USEPREFIX и 
// USESUFFIX. Также при помощи директивы NOPREFIX можно отменить помещение 
// стандартного префикса %0 в TMF-строку форматирования. 

///////////////////////////////////////////////////////////////////////////////
// Перечислимые типы значений (определяются макросом CUSTOM_TYPE)
///////////////////////////////////////////////////////////////////////////////
// ItemListByte:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemListByte(...));
//    cоответствующий тип MOF: ItemListByte;
//    зарезервированные типы WPP:
//	    CUSTOM_TYPE(bool8, ItemListByte(false, true));
//      CUSTOM_TYPE(irql,  ItemListByte(Low, APC, DPC));
//	    CUSTOM_TYPE(pnpmj, ItemListByte(
//        IRP_MJ_CREATE,
//        IRP_MJ_CREATE_NAMED_PIPE,
//        IRP_MJ_CLOSE,
//        IRP_MJ_READ,
//        IRP_MJ_WRITE,
//        IRP_MJ_QUERY_INFORMATION,
//        IRP_MJ_SET_INFORMATION,
//        IRP_MJ_QUERY_EA,
//        IRP_MJ_SET_EA,
//        IRP_MJ_FLUSH_BUFFERS,
//        IRP_MJ_QUERY_VOLUME_INFORMATION,
//        IRP_MJ_SET_VOLUME_INFORMATION,
//        IRP_MJ_DIRECTORY_CONTROL,
//        IRP_MJ_FILE_SYSTEM_CONTROL,
//        IRP_MJ_DEVICE_CONTROL,
//        IRP_MJ_INTERNAL_DEVICE_CONTROL,
//        IRP_MJ_SHUTDOWN,
//        IRP_MJ_LOCK_CONTROL,
//        IRP_MJ_CLEANUP,
//        IRP_MJ_CREATE_MAILSLOT,
//        IRP_MJ_QUERY_SECURITY,
//        IRP_MJ_SET_SECURITY,
//        IRP_MJ_POWER,
//        IRP_MJ_SYSTEM_CONTROL,
//        IRP_MJ_DEVICE_CHANGE,
//        IRP_MJ_QUERY_QUOTA,
//        IRP_MJ_SET_QUOTA,IRP_MJ_PNP
//      ));
//      CUSTOM_TYPE(pnpmn, ItemListByte(
//        IRP_MN_START_DEVICE,
//        IRP_MN_QUERY_REMOVE_DEVICE,
//        IRP_MN_REMOVE_DEVICE,
//        IRP_MN_CANCEL_REMOVE_DEVICE,
//        IRP_MN_STOP_DEVICE,
//        IRP_MN_QUERY_STOP_DEVICE,
//        IRP_MN_CANCEL_STOP_DEVICE,
//        IRP_MN_QUERY_DEVICE_RELATIONS,
//        IRP_MN_QUERY_INTERFACE,
//        IRP_MN_QUERY_CAPABILITIES,
//        IRP_MN_QUERY_RESOURCES,
//        IRP_MN_QUERY_RESOURCE_REQUIREMENTS,
//        IRP_MN_QUERY_DEVICE_TEXT,
//        IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
//        IRP_MN_PNP_14,IRP_MN_READ_CONFIG,
//        IRP_MN_WRITE_CONFIG,
//        IRP_MN_EJECT,
//        IRP_MN_SET_LOCK,
//        IRP_MN_QUERY_ID,
//        IRP_MN_QUERY_PNP_DEVICE_STATE,
//        IRP_MN_QUERY_BUS_INFORMATION,
//        IRP_MN_DEVICE_USAGE_NOTIFICATION,
//        IRP_MN_SURPRISE_REMOVAL
//      ));
//      CUSTOM_TYPE(sysctrl, ItemListByte(
//        IRP_MN_QUERY_ALL_DATA,
//        IRP_MN_QUERY_SINGLE_INSTANCE, 
//        IRP_MN_CHANGE_SINGLE_INSTANCE, 
//        IRP_MN_CHANGE_SINGLE_ITEM, 
//        IRP_MN_ENABLE_EVENTS, 
//        IRP_MN_DISABLE_EVENTS, 
//        IRP_MN_ENABLE_COLLECTION, 
//        IRP_MN_DISABLE_COLLECTION, 
//        IRP_MN_REGINFO, 
//        IRP_MN_EXECUTE_METHOD, 
//        IRP_MN_Reserved_0a, 
//        IRP_MN_REGINFO_EX
//      ));
// ItemSetByte:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemSetByte(...));
//    cоответствующий тип MOF: ItemSetByte;
//    зарезервированные типы WPP:
//      CUSTOM_TYPE(b1, ItemSetByte(1, 2, 3, 4, 5, 6, 7, 8));
// ItemListShort:
//    способ определения: CUSTOM_TYPE(<NAME>, ItemListShort(...));
//    cоответствующий тип MOF: ItemListShort;
//    зарезервированные типы WPP:
//	    CUSTOM_TYPE(bool16, ItemListShort(false, true));
// ItemSetShort:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemSetShort(...));
//    cоответствующий тип MOF: ItemSetShort;
//    зарезервированные типы WPP:
//      CUSTOM_TYPE(b2, ItemSetShort(
//        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
//      ));
// ItemListLong:
//    способ определения: CUSTOM_TYPE(<NAME>, ItemListLong(...));
//    cоответствующий тип MOF: ItemListLong;
//    зарезервированные типы WPP:
//	    CUSTOM_TYPE(bool, ItemListLong(false, true));
//      CUSTOM_TYPE(BOOLEAN, ItemListByte(FALSE, TRUE));
// ItemSetLong:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemSetLong(...));
//    cоответствующий тип MOF: ItemSetLong;
//    зарезервированные типы WPP:
//      CUSTOM_TYPE(b4, ItemSetLong(
//         1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 
//        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
//      ));
// ItemEnum:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemEnum(...));
//    cоответствующий тип MOF: ItemEnum;
// ItemFlagsEnum:
//    cпособ определения: CUSTOM_TYPE(<NAME>, ItemFlagsEnum(...));
//    cоответствующий тип MOF: ItemFlagsEnum;

///////////////////////////////////////////////////////////////////////////////
// Простейшие типы значений (типы, значения которых имеют фиксированный размер). 
// Простейшие типы значений определяются следующими способами: 
// 1) DEFINE_SIMPLE_TYPE(Name, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = имя типа WPP; 
//    EquivType  = имя типа C++, который будет типом формального параметра 
//                 создаваемой оберточной функции;
//    MofType    = имя типа MOF, который будет подставляться в TMF-описание; 
//    FormatSpec = способ форматирования типа MOF; 
//    Sig        = суффикс, добавляемый к имени создаваемой оберточной функции;
//    Priority   = зарезервировано и должно быть 0 для дополнительных 
//                 определений. 
// 2) DEFINE_SIMPLE_TYPE_PTR(Name, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = имя типа WPP; 
//    EquivType  = имя типа указателя C++, который будет типом формального 
//                 параметра создаваемой оберточной функции;
//    MofType    = имя типа MOF, который будет подставляться в TMF-описание; 
//    FormatSpec = способ форматирования типа MOF; 
//    Sig        = суффикс, добавляемый к имени создаваемой оберточной функции;
//    Priority   = зарезервировано и должно быть 0 для дополнительных 
//                 определений. 
// 3) DEFINE_FLAVOR(Name, BaseType, [MofType, FormatSpec])
//    Name       = имя типа WPP; 
//    BaseType   = базовый тип WPP, параметры определения которого подставляются 
//                 при отсутствии параметров MofType или  FormatSpec; 
//    MofType    = имя типа MOF, который будет подставляться в TMF-описание;
//    FormatSpec = способ форматирования типа MOF.
// Определение DEFINE_SIMPLE_TYPE используется для типов, передаваемых по значению,
// оберточная функция которых для передачи пар (адрес, размер) в используемую 
// функцию трассировки использует вызов макроса WPP_LOGTYPEVAL: 
// WPP_LOGTYPEVAL(Type, Value) WPP_LOGPAIR(sizeof(Type), &(Value))
// Определение DEFINE_SIMPLE_TYPE_PTR используется для типов, передаваемых через 
// указатель, оберточная функция которых для передачи пар (адрес, размер) в 
// используемую функцию трассировки использует вызов макроса WPP_LOGTYPEPTR: 
// WPP_LOGTYPEPTR(Value) WPP_LOGPAIR(sizeof(*(Value)), (Value))
// Определение DEFINE_FLAVOR используется для определения синонимов типов 
// WPP, а также типов, отличающихся от базовых отдельными свойствами (именем 
// типа MOF или строка форматирования, которая вставляется в TMF-строку). 
///////////////////////////////////////////////////////////////////////////////
// Name			Synonyms		MofType     FormatSpec     EquivType          Sig
// SCHAR		 c, hc			ItemChar        c          signed char         c
// UCHAR						ItemUChar       c          unsigned char       C
// SBYTE						ItemChar        c          signed char         c
// UBYTE						ItemChar        c          unsigned char       C
// OBYTE						ItemChar        o          signed char         c
// XBYTE						ItemChar        02x        signed char         c
// С			wc, lc			ItemShort       hd         signed short        h
// SSHORT		hi, hd			ItemShort       hd         signed short        h
// USHORT						ItemShort       hu         unsigned short      H
// hu							ItemShort       u          unsigned short      H
// OSHORT						ItemShort       ho         signed short        h
// ho							ItemShort       o          unsigned short      H
// XSHORT						ItemShort       04hX       signed short        h
// hx							ItemShort       x          unsigned short      H
// hX							ItemShort       X          unsigned short      H
// cccc							ItemChar4       s          signed int          d
// SINT			i, d			ItemLong        d          signed int          d
// UINT			u				ItemLong        u          unsigned int        D
// OINT							ItemLong        o          signed int          d
// o							ItemLong        o          unsigned int        D
// XINT							ItemLong        08x        signed int          d
// x							ItemLong        x          unsigned int        D
// X							ItemLong        X          unsigned int        D
// SLONG		li, ld			ItemLong        ld         signed long         l
// ULONG						ItemLong        lu         unsigned long       L
// lu							ItemLong        u          unsigned long       L
// OLONG						ItemLong        lo         signed long         l
// lo							ItemLong        o          unsigned long       L
// XLONG						ItemLong        08lX       signed long         l
// lx							ItemLong        x          unsigned long       L
// lX							ItemLong        X          unsigned long       L
// SINT64		I64d, lld		ItemLongLong    I64d       signed __int64      i
// UINT64		I64u, llu		ItemULongLong   I64u       unsigned __int64    I
// OINT64		I64o, llo		ItemLongLongO   I64o       signed __int64      i
// XINT64		I64x, llx		ItemLongLongX   I64x       signed __int64      i
// XXINT64		I64X, llX		ItemLongLongXX  I64X       signed __int64      i
// SLONGPTR						ItemPtr         Id         LONG_PTR            p
// ULONGPTR						ItemPtr         Iu         ULONG_PTR           P
// OLONGPTR						ItemPtr         Io         LONG_PTR            p
// XLONGPTR						ItemPtr         Ix         LONG_PTR            p
// PTR			p				ItemPtr         p          const void*         q
// HANDLE						ItemPtr         p          const void*         q
// DOUBLE		e, E, f, g, G	ItemDouble      s          double              g
// GUID			guid			ItemGuid        s          LPCGUID           _guid_
// IID							ItemIID         s          LPCGUID           _guid_
// CLSID						ItemCLSID       s          LPCGUID           _guid_
// LIBID						ItemLIBID       s          LPCGUID           _guid_
// TIMESTAMP	datetime		ItemTimeStamp   s          signed __int64      i
// DATE			datetime		ItemTimeStamp   s          signed __int64      i
// TIME			datetime		ItemTimeStamp   s          signed __int64      i
// WAITTIME		due				ItemWaitTime    s          signed __int64      i
// delta						ItemTimeDelta   s          signed __int64      i
// STATUS		status			ItemNTSTATUS    s          signed int          d
// HRESULT		hresult			ItemHRESULT     s          signed int          d
// WINERROR		winerr			ItemWINERROR    s          unsigned int        D
// IPADDR		ipaddr			ItemIPAddr      s          unsigned int        D
// PORT			port			ItemPort        s          unsigned short      H

// (*) Спецификация I64 в столбце FormatSpec, как и тип __int64 в столбце 
// EquivType, являются расширением Microsoft. 
// (**) Символ I в столбце FormatSpec является расширением Microsoft, который 
// соответствует символу z согласно стандарту C++. Символ z в настоящий момент 
// поддерживается Microsoft-реализацией printf, но старые реализации его могут 
// не поддерживать. 

///////////////////////////////////////////////////////////////////////////////
// Составные типы значений (значений с переменным размером).  
// Составные типы значений определяются следующими способами: 
// 1) DEFINE_CPLX_TYPE(Name, MacroName, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = имя типа WPP; 
//    MacroName  = имя макроса, передающего пары (размер, адрес) внутри  
//                 оберточной функции; 
//    EquivType  = имя типа C++, который будет типом параметра создаваемой 
//                 оберточной функции;
//    MofType    = имя типа MOF, который будет подставляться в TMF-описание; 
//    FormatSpec = способ форматирования типа MOF;  
//    Sig        = суффикс <SIG>, добавляемый к имени создаваемой 
//                 оберточной функции;
//    Priority   = зарезервировано и должно быть 0 для дополнительных 
//                 определений. 
// 2) DEFINE_FLAVOR(Name, BaseType, [MofType, FormatSpec])
//    Name       = имя типа WPP; 
//    BaseType   = базовый тип WPP, параметры определения которого подставляются 
//                 при отсутствии параметров MofType или  FormatSpec; 
//    MofType    = имя типа MOF, который будет подставляться в TMF-описание;
//    FormatSpec = способ форматирования типа MOF.
// Определение DEFINE_CPLX_TYPE задает имя предопределенного макроса, который 
// должен быть определен отдельно на основе макроса WPP_LOGPAIR. 
// Определение DEFINE_FLAVOR используется для определения синонимов типов 
// WPP, а также типов, отличающихся от базовых отдельными свойствами (именем 
// типа MOF или строка форматирования, которая вставляется в TMF-строку). 
///////////////////////////////////////////////////////////////////////////////
// Name		Synonyms	MofType     FormatSpec EquivType				   Sig		MacroName
// ASTR		s, hs       ItemString      s      LPCSTR						s		WPP_LOGASTR
// WSTR		S, ls, ws   ItemWString     s      LPCWSTR						S		WPP_LOGWSTR
// ARSTR                ItemRString     s      LPCSTR						s		WPP_LOGASTR
// ARWSTR               ItemRWString    s      LPCWSTR						S		WPP_LOGWSTR
// ANSTR    z, hZ (***) ItemPString     s      const ANSI_STRING*			aZ		WPP_LOGPCSTR
// CSTR		z, hZ (***) ItemPString     s      const CSTRING*				z		WPP_LOGPCSTR
// USTR		Z, wZ (***) ItemPWString    s      PCUNICODE_STRING				Z		WPP_LOGPUSTR
// str                  ItemPString     s      const std::string&		   _str_	WPP_LOGCPPSTR
// wstr                 ItemPWString    s      const std::wstring&		  _wstr_	WPP_LOGCPPSTR
// sv                   ItemPString     s      const std::string_view&	   _sv_		WPP_LOGCPPVEC
// wsv                  ItemPWString    s      const std::wstring_view&	  _wsv_		WPP_LOGCPPVEC
// sid                  ItemSid         s      PSID						  _sid_		WPP_LOGPSID

// (***) Некоторые спецификации имеют различный смысл при интерпретации
// их как тип WPP и функцией printf: тип z (WPP) соответствует printf-спецификации
// %hZ (нестандартное расширение Microsoft), а тип Z (WPP) - printf-спецификации 
// %wZ (нестандартное расширение Microsoft). Кроме того, спецификация %z в printf 
// интерпретируется как синоним printf-спецификации %I (нестандартное расширение 
// Microsoft), а для WPP она означает тип z, который для printf эквивалентен %hZ 
// (нестандартное расширение Microsoft). Поэтому во избежание ошибок для типов 
// const ANSI_STRING* и const CSTRING* в строке форматирования WPP необходимо 
// использовать %hZ, а для типа PCUNICODE_STRING использовать %wZ. 

///////////////////////////////////////////////////////////////////////////////
// Специальное форматирование, допускаемое в исходной строке
///////////////////////////////////////////////////////////////////////////////
// Формат       Подставляемое значение в TMF	Описание
// %!COMPNAME!  Значение __COMPNAME__			имя компонента (первоначально не определено)
// %!FILE!      Значение __FILE__				имя текущего файла
// %!LINE!      Значение __LINE__				номер строки текущего файла
// %!SPACE!     Литерал " "						пробел
// %!FUNC!      Литерал "%!FUNC!"				формат для вставки имени функции  
// %!LEVEL!     Литерал "%!LEVEL!"				формат для вставки уровня трассировки  
// %!STDPREFIX! Литерал "%0"					формат для вставки стандартного префикса  
// %!MOD!       Литерал "%1!s!"					формат для вставки отображаемого имени для Message GUID  
// %!TYP!       Литерал "%2!s!"					формат для вставки имени файла и строки  
// %!TID!       Литерал "%3!x!"					формат для вставки идентификатора потока  
// %!NOW!       Литерал "%4!x!"					формат для вставки времени события  
// %!SEQ!       Литерал "%7!x!"					формат для вставки номера события, генерируемого в сеансе  
// %!PID!       Литерал "%8!x!"					формат для вставки идентификатора процесса  
// %!CPU!       Литерал "%9!x!"					формат для вставки номера процессора  

namespace trace {
///////////////////////////////////////////////////////////////////////////////
// Способы форматирования
///////////////////////////////////////////////////////////////////////////////
typedef void (*pprintf)(void*, int, const char*, ...); 

// форматирование отдельной спецификации
typedef void (*pformat)(pprintf, void*, int, va_list&); 


template <typename T>
inline void stdformat(pprintf print, void* context, int level, const char* format, va_list& args)
{
	// извлечь значение аргумента и выполнить форматирование
	(*print)(context, level, format, valist_extract<T>(args));
}
///////////////////////////////////////////////////////////////////////////////
// Форматирование целых типов
///////////////////////////////////////////////////////////////////////////////
inline void format_hd (pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%hd"  , args); }
inline void format_ho (pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%ho"  , args); }
inline void format_hu (pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%hu"  , args); }
inline void format_hx (pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%hx"  , args); }
inline void format_hX (pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%hX"  , args); }
inline void format_hx2(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%02hx", args); }
inline void format_hX2(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%02hX", args); }
inline void format_hx4(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%04hx", args); }
inline void format_hX4(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%04hX", args); }
inline void format_hx8(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%08hx", args); }
inline void format_hX8(pprintf print, void* context, int level, va_list& args) { stdformat<short    >(print, context, level, "%08hX", args); }
inline void format_d  (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%d"   , args); }
inline void format_o  (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%o"   , args); }
inline void format_u  (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%u"   , args); }
inline void format_x  (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%x"   , args); }
inline void format_X  (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%X"   , args); }
inline void format_x2 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%02x" , args); }
inline void format_X2 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%02X" , args); }
inline void format_x4 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%04x" , args); }
inline void format_X4 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%04X" , args); }
inline void format_x8 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%08x" , args); }
inline void format_X8 (pprintf print, void* context, int level, va_list& args) { stdformat<int      >(print, context, level, "%08X" , args); }
inline void format_ld (pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%ld"  , args); }
inline void format_lo (pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%lo"  , args); }
inline void format_lu (pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%lu"  , args); }
inline void format_lx (pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%lx"  , args); }
inline void format_lX (pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%lX"  , args); }
inline void format_lx2(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%02lx", args); }
inline void format_lX2(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%02lX", args); }
inline void format_lx4(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%04lx", args); }
inline void format_lX4(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%04lX", args); }
inline void format_lx8(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%08lx", args); }
inline void format_lX8(pprintf print, void* context, int level, va_list& args) { stdformat<long     >(print, context, level, "%08lX", args); }
#if defined _MSC_VER
inline void format_I32d(pprintf print, void* context, int level, va_list& args) { stdformat<__int32 >(print, context, level, "%I32d" , args); }
inline void format_I32o(pprintf print, void* context, int level, va_list& args) { stdformat<__int32 >(print, context, level, "%I32o" , args); }
inline void format_I32u(pprintf print, void* context, int level, va_list& args) { stdformat<__int32 >(print, context, level, "%I32u" , args); }
inline void format_I32x(pprintf print, void* context, int level, va_list& args) { stdformat<__int32 >(print, context, level, "%I32x" , args); }
inline void format_I32X(pprintf print, void* context, int level, va_list& args) { stdformat<__int32 >(print, context, level, "%I32X" , args); }
inline void format_I64d(pprintf print, void* context, int level, va_list& args) { stdformat<__int64 >(print, context, level, "%I64d" , args); }
inline void format_I64o(pprintf print, void* context, int level, va_list& args) { stdformat<__int64 >(print, context, level, "%I64o" , args); }
inline void format_I64u(pprintf print, void* context, int level, va_list& args) { stdformat<__int64 >(print, context, level, "%I64u" , args); }
inline void format_I64x(pprintf print, void* context, int level, va_list& args) { stdformat<__int64 >(print, context, level, "%I64x" , args); }
inline void format_I64X(pprintf print, void* context, int level, va_list& args) { stdformat<__int64 >(print, context, level, "%I64X" , args); }
#endif 
#if !defined _MSC_VER || _MSC_VER >= 1800
inline void format_lld(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print,  context, level, "%lld" , args); }
inline void format_llo(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print,  context, level, "%llo" , args); }
inline void format_llu(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print,  context, level, "%llu" , args); }
inline void format_llx(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print,  context, level, "%llx" , args); }
inline void format_llX(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print,  context, level, "%llX" , args); }
inline void format_zd (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print,  context, level, "%zd"  , args); }
inline void format_zo (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print,  context, level, "%zo"  , args); }
inline void format_zu (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print,  context, level, "%zu"  , args); }
inline void format_zx (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print,  context, level, "%zx"  , args); }
inline void format_zX (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print,  context, level, "%zX"  , args); }
#else 
inline void format_lld(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print, context, level, "%I64d", args); }
inline void format_llo(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print, context, level, "%I64o", args); }
inline void format_llu(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print, context, level, "%I64u", args); }
inline void format_llx(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print, context, level, "%I64x", args); }
inline void format_llX(pprintf print, void* context, int level, va_list& args) { stdformat<long long>(print, context, level, "%I64X", args); }
inline void format_zd (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print, context, level, "%Id"  , args); }
inline void format_zo (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print, context, level, "%Io"  , args); }
inline void format_zu (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print, context, level, "%Iu"  , args); }
inline void format_zx (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print, context, level, "%Ix"  , args); }
inline void format_zX (pprintf print, void* context, int level, va_list& args) { stdformat<size_t   >(print, context, level, "%IX"  , args); }
#endif 
inline void format_p  (pprintf print, void* context, int level, va_list& args) { stdformat<void*    >(print, context, level, "%p", args); }

///////////////////////////////////////////////////////////////////////////////
// Форматирование символьных и строковых типов
///////////////////////////////////////////////////////////////////////////////
inline void format_hc(pprintf print, void* context, int level, va_list& args) { stdformat<char    >(print, context, level, "%hc", args); }
inline void format_lc(pprintf print, void* context, int level, va_list& args) { stdformat<wchar_t >(print, context, level, "%lc", args); }

inline void format_hs(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь переданную строку
	const char* sz = valist_extract<const char*>(args); 

	// выполнить форматирование
	(*print)(context, level, "%hs", sz ? sz : "<null>");
}
inline void format_ls(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь переданную строку
	const wchar_t* sz = valist_extract<const wchar_t*>(args); 

	// выполнить форматирование
	(*print)(context, level, "%ls", sz ? sz : L"<null>");
}
#if defined _MSC_VER
inline void format_hZ(pprintf print, void* context, int level, va_list& args) { stdformat<void*   >(print, context, level, "%hZ", args); }
inline void format_lZ(pprintf print, void* context, int level, va_list& args) { stdformat<void*   >(print, context, level, "%lZ", args); }
#elif defined _WIN32
inline void format_hZ(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь отдельный аргумент
	const ANSI_STRING* arg = valist_extract<const ANSI_STRING*>(args); 
	
	// вывести строку
	(*print)(context, level, "%.*hs", arg->Length / sizeof(CHAR), arg->Buffer); 
}
inline void format_lZ(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь отдельный аргумент
	const UNICODE_STRING* arg = valist_extract<const UNICODE_STRING*>(args);
		
	// вывести строку
	(*print)(context, level, "%.*ls", arg->Length / sizeof(WCHAR), arg->Buffer); 
}
#endif 

inline void format_vhs(pprintf print, void* context, int level, va_list& args) 
{ 
#if defined _MSC_VER && _MSC_VER >= 1600 

	// извлечь объект
	const _str& arg = va_arg(args, _str);
#else 
	// извлечь отдельный аргумент
	const char* sz = valist_extract<const char*>(args); 
	
	// создать объект
	_str arg(sz, valist_extract<size_t>(args));
#endif 
	// вывести строку
	(*print)(context, level, "%.*hs", (int)arg.size(), arg.data()); 
}
inline void format_vls(pprintf print, void* context, int level, va_list& args) 
{ 
#if defined _MSC_VER && _MSC_VER >= 1600 

	// извлечь объект
	const _wstr& arg = va_arg(args, _wstr);
#else 
	// извлечь отдельный аргумент
	const wchar_t* sz = valist_extract<const wchar_t*>(args); 
	
	// создать объект
	_wstr arg(sz, valist_extract<size_t>(args));
#endif 
	// вывести строку
	(*print)(context, level, "%.*ls", (int)arg.size(), arg.data()); 
}

///////////////////////////////////////////////////////////////////////////////
// Общие способы форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_space(pprintf print, void* context, int level, va_list&) 
{
	// выполнить форматирование
	(*print)(context, level, " "); 
}

inline void format_bool8(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args); 

	// выполнить форматирование
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}

inline void format_bool16(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args);

	// выполнить форматирование
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}
inline void format_bool(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args); 

	// выполнить форматирование
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}

inline void format_b1(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args); bool first = true; 

	// для всех битов
	for (int i = 8, mask = 0x80; i > 0; mask >>= 1, i--)
	{
		// проверить установку бита
		if ((value & mask) == 0) continue; 

		// указать номер установленного бита
		if (!first) (*print)(context, level, ",%u", i);
		
		// указать номер установленного бита
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_b2(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args); bool first = true; 

	// для всех битов
	for (int i = 16, mask = 0x8000; i > 0; mask >>= 1, i--)
	{
		// проверить установку бита
		if ((value & mask) == 0) continue; 

		// указать номер установленного бита
		if (!first) (*print)(context, level, ",%u", i);
		
		// указать номер установленного бита
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_b4(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение
	int value = valist_extract<int>(args); bool first = true; 

	// для всех битов
	for (int i = 32, mask = 0x80000000; i > 0; mask >>= 1, i--)
	{
		// проверить установку бита
		if ((value & mask) == 0) continue; 

		// указать номер установленного бита
		if (!first) (*print)(context, level, ",%u", i);
		
		// указать номер установленного бита
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_arstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const char* str = valist_extract<const char*>(args); if (!str) return; 

    // пропустить начальные пробелы
    str = str + strspn(str, " "); if (*str == '\0') return; 

    // найти заменяемый символ
    size_t index = strcspn(str, "\t\r\n"); 

    // при наличии заменяемых символов
    while (str[index] != '\0')
    {
	    // записать часть строки
	    (*print)(context, level, "%.*hs ", (int)index, str); str += index + 1;

        // проверить наличие непробельных символов
        if (str[strspn(str, " ")] == '\0') return; 

        // найти заменяемый символ
        index = strcspn(str, "\t\r\n"); 
    }
    // записать часть строки
    (*print)(context, level, "%.*hs", (int)index, str); 
}

inline void format_arwstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const wchar_t* str = valist_extract<const wchar_t*>(args); if (!str) return; 

    // пропустить начальные пробелы
    str = str + wcsspn(str, L" "); if (*str == L'\0') return; 

    // найти заменяемый символ
    size_t index = wcscspn(str, L"\t\r\n"); 

    // при наличии заменяемых символов
    while (str[index] != L'\0')
    {
	    // записать часть строки
	    (*print)(context, level, "%.*ls ", (int)index, str); str += index + 1;

        // проверить наличие непробельных символов
        if (str[wcsspn(str, L" ")] == L'\0') return; 

        // найти заменяемый символ
        index = wcscspn(str, L"\t\r\n"); 
    }
    // записать часть строки
    (*print)(context, level, "%.*ls", (int)index, str); 
}

///////////////////////////////////////////////////////////////////////////////
// Cпособы форматирования для WIN32
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
inline void format_cccc(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь целочисленный аргумент
	ULONG arg = valist_extract<ULONG>(args); 

	// выполнить форматирование
	(*print)(context, level, "%.4hs", &arg); 
}

inline void format_guid(pprintf print, void* context, int level, va_list& args) 
{ 
	// указать строку форматирования
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx"; 

	// извлечь идентификатор
	const GUID* guid = (const GUID*)valist_extract<const void*>(args); 

	// вывести строковое представление идентификатора
	(*print)(context, level, szFormat, guid->Data1, guid->Data2, guid->Data3, 
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]
	);
}

inline void format_abs_delta(pprintf print, void* context, int level, long long delta) 
{
	// определить число полных дней
	long long days = delta / (24 * 60 * 60 * 1000); delta -= days * (24 * 60 * 60 * 1000);

	// определить число полных часов, минут и секунд
	long long hours   = delta / (60 * 60 * 1000); delta -= hours   * (60 * 60 * 1000); 
	long long minutes = delta / (     60 * 1000); delta -= minutes * (     60 * 1000); 
	long long seconds = delta / (          1000); delta -= seconds * (          1000); 

	// указать строку форматирования
	if (days > 0) { const char* szFormat = "%llu~%lu:%lu:%lu.%03lu"; 

		// вывести строковое представление
		(*print)(context, level, szFormat, days, (long)hours, (long)minutes, (long)seconds, (long)delta); 
	}
	// указать строку форматирования
	else if (hours > 0) { const char* szFormat = "%lu:%lu:%lu.%03lu"; 

		// вывести строковое представление
		(*print)(context, level, szFormat, (long)hours, (long)minutes, (long)seconds, (long)delta); 
	}
	// указать строку форматирования
	else if (minutes > 0) { const char* szFormat = "%lu:%lu.%03lu"; 

		// вывести строковое представление
		(*print)(context, level, szFormat, (long)minutes, (long)seconds, (long)delta); 
	}
	// указать строку форматирования
	else { const char* szFormat = "%hs%lu.%03lu"; 

		// вывести строковое представление
		(*print)(context, level, szFormat, (long)seconds, (long)delta); 
	}
}

inline void format_delta(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь число миллисекунд
	long long delta = valist_extract<INT64>(args); if (delta < 0)
	{ 
		// изменить знак числа
		delta = -delta; (*print)(context, level, "-"); 
	}
	// вывести разницу во времени
	format_abs_delta(print, context, level, delta); 
}

inline void format_waittime(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь число миллисекунд
	long long delta = valist_extract<INT64>(args); if (delta > 0)
	{
		// вывести разницу во времени
		format_abs_delta(print, context, level, delta); 
		
		// вывести ключевое слово
		(*print)(context, level, " ago");
	}
	else if (delta < 0) 
	{
		// вывести разницу во времени
		format_abs_delta(print, context, level, -delta); 
		
		// вывести ключевое слово
		(*print)(context, level, " until");
	}
	// указать текущий момент времени
	else (*print)(context, level, "just now");  
}

inline void format_due(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь число миллисекунд
	long long delta = valist_extract<INT64>(args); if (delta > 0)
	{
		// вывести разницу во времени
		format_abs_delta(print, context, level, delta); 
		
		// вывести ключевое слово
		(*print)(context, level, " until");
	}
	else if (delta < 0) 
	{
		// вывести разницу во времени
		format_abs_delta(print, context, level, -delta); 
		
		// вывести ключевое слово
		(*print)(context, level, " ago");
	}
	// указать текущий момент времени
	else (*print)(context, level, "just now");  
}

inline void format_ipaddr(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор
	unsigned long ipaddr = valist_extract<UINT32>(args); 

	// указать строку форматирования
	const char* szFormat = "%hd.%hd.%hd.%hd"; 

	// вывести строковое представление идентификатора
	(*print)(context, level, szFormat,  (ipaddr >> 24) & 0xFF, 
		(ipaddr >> 16) & 0xFF, (ipaddr >>  8) & 0xFF, ipaddr & 0xFF
	);
}

inline void format_port(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор
	unsigned short port = valist_extract<UINT16>(args); 

    // вывести номер порта
	(*print)(context, level, "%hd", port); 
}

inline void format_status(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор
	long status = valist_extract<NTSTATUS>(args);

    // вывести код ошибки
    (*print)(context, level, "NTSTATUS = %08lX", status); 
}

inline void format_winerror(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор
	unsigned long code = valist_extract<ULONG>(args);

    // вывести код ошибки
    (*print)(context, level, "WINERROR = %ld", code); 
}

inline void format_hresult(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор
	long code = valist_extract<LONG>(args);

    // вывести код ошибки
    (*print)(context, level, "HRESULT = %08lX", code); 
}

#endif 

#if defined _NTDDK_
inline void format_sid(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор безопасности
	PSID pSID = valist_extract<PSID>(args); UNICODE_STRING ustr = {0};

    // получить строковое представление идентификатора
    NTSTATUS status = ::RtlConvertSidToUnicodeString(&ustr, pSID, TRUE); 

    // обработать возможную ошибку
    if (!NT_SUCCESS(status)) (*print)(context, level, "S-?-?"); 
    else {
        // вывести строковое представление
        (*print)(context, level, "%.*ls", ustr.Length / sizeof(WCHAR), ustr.Buffer); 

        // освободить выделенную память
        ::RtlFreeUnicodeString(&ustr); 
    }
}

inline void format_iid(pprintf print, void* context, int level, va_list& args) 
{ 
	// вывести строковое представление идентификатора
	format_guid(print, context, level, args); 
}

inline void format_clsid(pprintf print, void* context, int level, va_list& args) 
{ 
	// вывести строковое представление идентификатора
	format_guid(print, context, level, args); 
}

inline void format_libid(pprintf print, void* context, int level, va_list& args) 
{ 
	// вывести строковое представление
	format_guid(print, context, level, args); 
}

inline void format_timestamp(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение времени
	UINT64 value = valist_extract<UINT64>(args); 

	// вывести числовое значение
	(*print)(context, level, "%I64u", value); 
}
#else 
inline void format_e(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%e", args); }
inline void format_E(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%E", args); }
inline void format_f(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%f", args); }
inline void format_F(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%F", args); }
inline void format_g(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%g", args); }
inline void format_G(pprintf print, void* context, int level, va_list& args) { stdformat<double>(print, context, level, "%G", args); }

#if defined _MSC_VER && _MSC_VER >= 1600 
inline void format_str(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const std::string& arg = va_arg(args, std::string);

    // вывести строку
    (*print)(context, level, "%hs", arg.c_str()); 
}

inline void format_wstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const std::wstring& arg = va_arg(args, std::wstring);

    // вывести строку
    (*print)(context, level, "%ls", arg.c_str()); 
}

#if _HAS_CXX17 == 1
inline void format_sv(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const std::string_view& arg = va_arg(args, std::string_view);

    // вывести строку
    (*print)(context, level, "%.*hs", (int)arg.length(), arg.data()); 
}

inline void format_wsv(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь строку
	const std::wstring_view& arg = va_arg(args, std::wstring_view);

    // вывести строку
    (*print)(context, level, "%.*ls", (int)arg.length(), arg.data()); 
}
#endif 
#endif

#if defined _WIN32
inline void format_sid(pprintf print, void* context, int level, va_list& args) 
{ 
	// извлечь идентификатор безопасности
	PSID pSID = valist_extract<PSID>(args); PWSTR szSID = nullptr;

    // получить строковое представление идентификатора
    if (!::ConvertSidToStringSidW(pSID, &szSID)) (*print)(context, level, "S-?-?"); 
    else {
        // вывести строковое представление
        (*print)(context, level, "%ls", szSID); ::LocalFree(szSID); 
    }
}

inline void format_iid(pprintf print, void* context, int level, va_list& args) 
{ 
	// указать строку форматирования
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx"; 

	// извлечь идентификатор
	const IID* iid = (const IID*)valist_extract<const void*>(args); 

	// получить строковое представление идентификатора
	LPOLESTR szIID = nullptr; if (SUCCEEDED(::StringFromIID(*iid, &szIID)))
	{
		// вывести строковое представление
		(*print)(context, level, "%ls", szIID); ::CoTaskMemFree(szIID); 
	}
	else {
		// вывести строковое представление идентификатора
		(*print)(context, level, szFormat, iid->Data1, iid->Data2, iid->Data3, 
			iid->Data4[0], iid->Data4[1], iid->Data4[2], iid->Data4[3],
			iid->Data4[4], iid->Data4[5], iid->Data4[6], iid->Data4[7]
		);
	}
}

inline void format_clsid(pprintf print, void* context, int level, va_list& args) 
{ 
	// указать строку форматирования
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx}"; 

	// извлечь идентификатор
	const CLSID* clsid = (const CLSID*)valist_extract<const void*>(args); 

	// получить строковое представление идентификатора
	LPOLESTR szCLSID = nullptr; if (SUCCEEDED(::ProgIDFromCLSID(*clsid, &szCLSID)))
	{
		// вывести строковое представление
		(*print)(context, level, "%ls", szCLSID); ::CoTaskMemFree(szCLSID); 
	}
	// получить строковое представление идентификатора
	else if (SUCCEEDED(::StringFromCLSID(*clsid, &szCLSID)))
	{
		// вывести строковое представление
		(*print)(context, level, "%ls", szCLSID); ::CoTaskMemFree(szCLSID); 
	}
	else {
		// вывести строковое представление идентификатора
		(*print)(context, level, szFormat, clsid->Data1, clsid->Data2, clsid->Data3, 
			clsid->Data4[0], clsid->Data4[1], clsid->Data4[2], clsid->Data4[3],
			clsid->Data4[4], clsid->Data4[5], clsid->Data4[6], clsid->Data4[7]
		);
	}
}

inline void format_libid(pprintf print, void* context, int level, va_list& args) 
{ 
	// вывести строковое представление
	format_guid(print, context, level, args); 
}

inline void format_timestamp(pprintf print, void* context, int level, va_list& args) 
{
	// извлечь значение времени
	unsigned long long value = valist_extract<UINT64>(args); SYSTEMTIME st; 

	// получить системное время
	if (::FileTimeToSystemTime((const FILETIME*)&value, &st))
	{
		// отформатировать системное время
		std::string datetime = datetime_string(st); 

		// вывести строковое представление
		(*print)(context, level, "%hs", datetime.c_str());
	}
	// вывести числовое значение
	else (*print)(context, level, "%llu", value);  
}

#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Таблица соответствия спецификации и способа форматирования. Состоит из 
// элементов типа wpp_format_entry, в которых format - спецификация 
// форматирования, а func - адрес функции форматирования. Таблица является 
// расширяемой: если поле func содержит нулевое значение, то поле format 
// содержит адрес следующего фрагмента таблицы форматирования. Признаком 
// последнего фрагмента таблицы форматирования является наличие нулевых 
// значений в обоих полях format и func. 
///////////////////////////////////////////////////////////////////////////////
struct wpp_format_entry { const char* format; pformat func; }; 

static wpp_format_entry _wpp_format_table[] = {
    { "bool8"		, format_bool8 		}, 	
    { "b1"			, format_b1 		}, 	
    { "bool16"		, format_bool16		}, 	
    { "b2"			, format_b2 		}, 	
    { "bool"		, format_bool		}, 	
    { "b4"			, format_b4 		}, 	
    { "c"     		, format_hc 		}, 	
    { "hc"    		, format_hc 		}, 	
    { "lc"    		, format_lc 		}, 	
    { "wc"    		, format_lc 		}, 	
    { "hi"    		, format_hd 		}, 
    { "hd"    		, format_hd 		}, 
    { "hu"    		, format_hu 		}, 
    { "ho"    		, format_ho 		}, 
    { "hx"    		, format_hx 		}, 
    { "hX"    		, format_hX 		}, 	
    { "i"     		, format_d  		}, 	
    { "d"     		, format_d  		}, 	
    { "u"     		, format_u  		}, 	
    { "o"     		, format_o  		}, 	
    { "x"     		, format_x  		}, 	
    { "X"     		, format_X  		}, 	
    { "li"    		, format_ld 		}, 	
    { "ld"    		, format_ld 		}, 	
    { "lu"    		, format_lu 		}, 	
    { "lo"    		, format_lo 		}, 	
    { "lx"    		, format_lx 		}, 	
    { "lX"    		, format_lX 		}, 	
    { "lli"   		, format_lld 		}, 	
    { "lld"   		, format_lld 		}, 	
    { "llu"   		, format_llu 		}, 	
    { "llo"   		, format_llo 		}, 	
    { "llx"   		, format_llx 		}, 	
    { "llX"   		, format_llX 		}, 	
    { "p"			, format_p 			}, 	
    { "s"			, format_hs			}, 	
    { "hs"			, format_hs			}, 	
    { "ls"			, format_ls			}, 	
    { "ws"			, format_ls			}, 	
    { ".*s"			, format_vhs		}, 	
    { ".*hs"		, format_vhs		}, 	
    { ".*ls"		, format_vls		}, 	
    { ".*ws"		, format_vls		}, 	
    { "SPACE" 		, format_space		}, 
    { "SCHAR" 		, format_hc 		}, 
    { "UCHAR" 		, format_hc 		}, 
    { "SBYTE" 		, format_hc 		}, 
    { "UBYTE" 		, format_hc 		}, 
    { "OBYTE" 		, format_ho  		}, 
    { "XBYTE" 		, format_x2 		}, 
    { "SSHORT"		, format_hd 		}, 	
    { "USHORT"		, format_hu 		}, 	
    { "OSHORT"		, format_ho 		}, 	
    { "XSHORT"		, format_hX4 		}, 	
    { "SINT"  		, format_d  		}, 	
    { "UINT"  		, format_u  		}, 	
    { "OINT"  		, format_o  		}, 	
    { "XINT"  		, format_x8  		}, 	
    { "SLONG" 		, format_ld 		}, 	
    { "ULONG" 		, format_lu 		}, 	
    { "OLONG" 		, format_lo 		}, 	
    { "XLONG" 		, format_lX8 		}, 	
    { "SLONGPTR"	, format_zd 		}, 	
    { "OLONGPTR"	, format_zo 		}, 	
    { "XLONGPTR"	, format_zx 		}, 	
    { "PTR"			, format_p 			}, 	
    { "ASTR"		, format_hs			}, 	
    { "WSTR"		, format_ls			}, 	
    { "ARSTR"		, format_arstr		}, 	
    { "ARWSTR"		, format_arwstr		}, 	
#if !defined _NTDDK_
    { "e"			, format_e 			}, 	
    { "E"			, format_E 			}, 	
    { "f"			, format_f 			}, 	
    { "F"			, format_F 			}, 	
    { "g"			, format_g 			}, 	
    { "G"			, format_G 			}, 	
    { "DOUBLE"		, format_G 			}, 	
#if defined _MSC_VER && _MSC_VER >= 1600 
	{ "str"			, format_str		}, 	
	{ "wstr"		, format_wstr		}, 	
#if defined _HAS_CXX17 && _HAS_CXX17 == 1
	{ "sv"			, format_sv			}, 	
	{ "wsv"			, format_wsv		}, 	
#endif 
#endif 
#endif 
#if defined _MSC_VER
    { "C"     		, format_lc 		}, 	
    { "S"			, format_ls			}, 	
    { "I64i"  		, format_I64d 		}, 	
    { "I64d"  		, format_I64d 		}, 	
    { "I64u"  		, format_I64u 		}, 	
    { "I64o"  		, format_I64o 		}, 	
    { "I64x"  		, format_I64x 		}, 	
    { "I64X"  		, format_I64X 		}, 	
    { "SINT64"		, format_I64d 		}, 	
    { "UINT64"		, format_I64u 		}, 	
    { "OINT64"		, format_I64o 		}, 	
    { "XINT64"		, format_I64x 		}, 	
    { "XXINT64"		, format_I64X 		}, 	
#endif 
#if defined _WIN32
    { "cccc"		, format_cccc		}, 	
    { "z"			, format_hZ			}, 	
    { "hZ"			, format_hZ			}, 	
    { "Z"			, format_lZ			}, 	
    { "wZ"			, format_lZ			}, 	
    { "CSTR"		, format_hZ			}, 	
    { "ANSTR"		, format_hZ			}, 	
    { "USTR"		, format_lZ			}, 	
    { "HANDLE"		, format_p 			}, 	
    { "sid"			, format_sid		}, 	
    { "GUID"		, format_guid		}, 	
    { "IID"			, format_iid		}, 	
    { "CLSID"		, format_clsid		}, 	
    { "LIBID"		, format_libid		}, 	
    { "TIMESTAMP"	, format_timestamp	}, 
    { "DATE"		, format_timestamp	}, 
    { "TIME"		, format_timestamp	}, 
    { "datetime"	, format_timestamp	}, 
    { "WAITTIME"	, format_waittime	}, 
    { "due"			, format_due		}, 
    { "delta"		, format_delta		}, 
    { "IPADDR"		, format_ipaddr		}, 	
    { "PORT"		, format_port		}, 
    { "STATUS"		, format_status		}, 	
    { "WINERROR"	, format_winerror	}, 	
    { "HRESULT"		, format_hresult	}, 	
#endif 
	{ nullptr		, nullptr			} 
}; 
// таблица форматирования
inline wpp_format_entry* wpp_format_table() { return _wpp_format_table; }

inline const wpp_format_entry* wpp_find_format(const char* format)
{
	// найти позицию завершения формата
	const char* szEnd = format + strcspn(format, "!"); 

	// для всех фрагментов таблицы
	for (const wpp_format_entry* fragment = wpp_format_table(); fragment; )
	{
		// перейти на первый элемент фрагмента
		const wpp_format_entry* entry = fragment; 

		// для всех элементов таблицы
		for (; entry->func; entry++)
		{
			// определить размер строки
			size_t length = strlen(entry->format); 

			// проверить размер строки
			if (format + length != szEnd) continue; 

			// проверить совпадение формата
			if (strncmp(entry->format, format, length) == 0) return entry; 
		}
		// перейти на следующий фрагмент
		fragment = (const wpp_format_entry*)entry->format; 
	}
	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////////
// Расширение таблицы форматирования
///////////////////////////////////////////////////////////////////////////////
inline void wpp_extend_format_table(const char* format, const wpp_format_entry* table)
{
	// для всех фрагментов таблицы
	for (wpp_format_entry* fragment = wpp_format_table(); fragment; )
	{
		// перейти на первый элемент фрагмента
		wpp_format_entry* entry = fragment; 

		// для всех элементов таблицы
		for (; entry->func; entry++)
		{
			// проверить несовпадение формата
			if (strcmp(entry->format, format) == 0) return; 
		}
		// перейти на следующий фрагмент
		fragment = (wpp_format_entry*)entry->format; 

		// установить адрес нового фрагмента
		if (!fragment) entry->format = (const char*)table; 
	}
}

#if !defined _NTDDK_
#define WPP_FORMAT_TABLE_EXTENSION(FORMAT, FUNC)				\
static struct wpp_format_table_ ## FORMAT						\
{																\
	wpp_format_table_ ## FORMAT()								\
	{															\
	    static trace::wpp_format_entry table[] = {				\
	    	{ WPP_STRINGIZE(FORMAT), FUNC 		}, 				\
	    	{ nullptr	           , nullptr	} 				\
		};														\
		trace::wpp_extend_format_table(table[0].format, table);	\
	}															\
} wpp_format_table_ ## FORMAT;
#endif

///////////////////////////////////////////////////////////////////////////////
// Строковое имя уровня трассировки
///////////////////////////////////////////////////////////////////////////////
inline const char* wpp_level_name(int level)
{
	switch (level)
	{
	case TRACE_LEVEL_NONE		: return "TRACE_LEVEL_NONE"; 
	case TRACE_LEVEL_CRITICAL	: return "TRACE_LEVEL_CRITICAL"; 
	case TRACE_LEVEL_ERROR		: return "TRACE_LEVEL_ERROR"; 
	case TRACE_LEVEL_WARNING	: return "TRACE_LEVEL_WARNING"; 
	case TRACE_LEVEL_INFORMATION: return "TRACE_LEVEL_INFORMATION"; 
	case TRACE_LEVEL_VERBOSE    : return "TRACE_LEVEL_VERBOSE"; 
	}
	return "TRACE_LEVEL_<UNKNOWN>"; 
}
///////////////////////////////////////////////////////////////////////////////
// Специальное форматирование WPP
///////////////////////////////////////////////////////////////////////////////
inline size_t wpp_special_format(pprintf print, void* context, 
	const char* szFormat, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction) 
{ 
	// для имени компонента
	if (strncmp(szFormat, "%!COMPNAME!", 11) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, szComponent); return 11;  
	}
	// для имени компонента
	if (strncmp(szFormat, "%!MOD!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, szComponent); return 6;  
	}
	// для имени флага
	if (strncmp(szFormat, "%!FLAGS!", 8) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, szFlags); return 8; 
	}
	// для уровня трассировки
	if (strncmp(szFormat, "%!LEVEL!", 8) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, wpp_level_name(level)); return 8; 
	}
	// для имени файла
	if (strncmp(szFormat, "%!FILE!", 7) == 0) 
	{ 
		// выполнить форматирование
		(*print)(context, level, szFile); return 7; 
	}
	// для номера строки файла
	if (strncmp(szFormat, "%!LINE!", 7) == 0) 
	{
		// выполнить форматирование
		(*print)(context, level, "%u", line); return 7; 
	}
	// для имени функции
	if (strncmp(szFormat, "%!FUNC!", 7) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, szFunction); return 7; 
	}
	// для имени файла и строки  
	if (strncmp(szFormat, "%!TYP!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, szFile); 
		
		// выполнить форматирование
		(*print)(context, level, " %d", line); return 6; 
	}
	// для номера процессора
	if (strncmp(szFormat, "%!CPU!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, "%d", current_processor()); return 6; 
	}
	// для идентификатора процесса
	if (strncmp(szFormat, "%!PID!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, "%d", current_process()); return 6; 
	}
	// для идентификатора потока
	if (strncmp(szFormat, "%!TID!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, "%ld", current_thread()); return 6; 
	}
#if defined _NTDDK_
	// для текущего времени
	if (strncmp(szFormat, "%!NOW!", 6) == 0)
	{
		// выполнить форматирование
		(*print)(context, level, "%016I64X", current_datetime()); return 6; 
	}
#else
	// для текущего времени
	if (strncmp(szFormat, "%!NOW!", 6) == 0)
	{
		// получить текущее время
		std::string datetime = current_datetime();  

		// выполнить форматирование
		(*print)(context, level, "%hs", datetime.c_str()); return 6; 
	}
#endif 
	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Форматирование префикса
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_ || !defined _WIN32
inline void wpp_prefix_format(pprintf print, void* context, 
	const char* szFormat, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction)
{
	// найти спецификацию форматирования
	size_t index = strcspn(szFormat, "%"); 

	// при нахождении спецификации
	for (; szFormat[index] != '\0'; index = strcspn(szFormat, "%"))
	{
		// в случае экранирования
		if (szFormat[index + 1] == '\0') { break; } if (szFormat[index + 1] == '%')
		{
			// вывести часть строки
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 

			// перейти на следующую часть 
			szFormat += index + 2; continue; 
		}
		// вывести часть строки
		(*print)(context, level, "%.*hs", (int)index, szFormat); szFormat += index; 

		// при указании спецификации WPP
		if (szFormat[1] == '!')
		{
			// выполнить специальное форматирование
			if (size_t cch = wpp_special_format(print, context, szFormat, 
				szComponent, szFlags, level, szFile, line, szFunction)) 
			{
				szFormat += cch; continue; 
			}
			// перейти на следующую часть 
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		// проверить указание номера переменной
		if ('1' > szFormat[1] || szFormat[1] > '9')
		{
			// вывести часть строки
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		// сохранить адрес номера переменной
		const char* szOrdinal = szFormat + 1; char format[128]; 

		// при указании спецификации
		if (*(szFormat += 2) == '!')
		{ 
			// найти завершающий символ спецификации
			if (const char* szEnd = strchr(szFormat + 1, '!')) 
			{ 
				// скопировать отдельную спецификацию
				strncpy_s(format + 1, sizeof(format) - 1, szFormat + 1, szEnd - (szFormat + 1)); 

				// пропустить спецификацию
				format[0] = '%'; szFormat = szEnd + 1; 
			}
		}
		switch (*szOrdinal)
		{
		case '1': {
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%hs", 3); 

			// вывести имя компонента
			(*print)(context, level, format, szComponent); break; 
		}
		case '2': {
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%hs", 3); 

			// вывести имя файла и номер строки
			(*print)(context, level, format, szFile); (*print)(context, level, " %d", line); break;
		}
		case '3': {
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%lu", 3); 

			// вывести идентификатор потока
			(*print)(context, level, format, current_thread()); break;
		}
#if defined _NTDDK_
		case '4': {
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// вывести текущее время
			(*print)(context, level, format, current_datetime()); break;
		}
		case '5': {
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// указать значение по умолчанию
			LARGE_INTEGER time; time.QuadPart = 0; 
			
			// вывести время в режиме ядра
			(*print)(context, level, format, time); break;
		}
		case '6': { 
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// указать значение по умолчанию
			LARGE_INTEGER time; time.QuadPart = 0; 
			
			// вывести время в режиме пользователя
			(*print)(context, level, format, time); break;
		}
#else 
		case '4': {
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// получить текущее время
			std::string datetime = current_datetime(); 
			
			// вывести текущее время
			(*print)(context, level, format, datetime.c_str()); break;
		}
		case '5': {
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// вывести время в режиме ядра
			(*print)(context, level, format, "?"); break;
		}
		case '6': { 
			// при отсутствии указания форматирования
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// указать способ форматирования по умолчанию
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// вывести время в режиме пользователя
			(*print)(context, level, format, "?"); break;
		}
#endif 
		case '7': { 
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%ld", 3); 

			// вывести номер сообщения
			(*print)(context, level, format, 0L); break;
		}
		case '8': {
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%u", 2); 

			// вывести идентификатор процесса
			(*print)(context, level, format, current_process()); break;
		}
		case '9': {
			// указать способ форматирования по умолчанию
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%u", 2); 

			// вывести идентификатор процессора
			(*print)(context, level, format, current_processor()); break;
		}}
	}
	// вывести оставшуюся часть строки
	if (*szFormat) (*print)(context, level, "%hs", szFormat); 
}
#else 
inline void wpp_prefix_format(pprintf print, void* context, 
	const char* szPrefix, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction)
{
	// скопировать префикс
	std::string prefix(szPrefix); if (prefix.length() == 0) return; 

	// выделить динамические буферы
	std::string message; std::string fileLine; std::string datetime; 

	// выделить память для параметров префикса
	DWORD_PTR prefixArgs[9] = { (DWORD_PTR)szComponent }; 
	
	// при наличии имени файла
	if (prefix.find("%2") != std::string::npos) 
	{
		// отформатировать номер строки
		char szLine[16]; sprintf_s(szLine, sizeof(szLine), "%d", line); 

		// объединить имя файла и строку
		fileLine = szFile; fileLine += " "; fileLine += szLine; 
		
		// указать имя файла и строку
		prefixArgs[1] = (DWORD_PTR)fileLine.c_str(); 
	}
	// при наличии отметки времени
	if (prefix.find("%4") != std::string::npos) { datetime = current_datetime();
	
		// указать текущее время
		prefixArgs[3] = (DWORD_PTR)datetime.c_str(); 
	}
	// указать номер процессора, идентификаторы процесса и потока
	if (prefix.find("%9") != std::string::npos) prefixArgs[8] = current_processor();
	if (prefix.find("%8") != std::string::npos) prefixArgs[7] = current_process  ();
	if (prefix.find("%3") != std::string::npos) prefixArgs[2] = current_thread   ();

	// указать неизвестные данные
	if (prefix.find("%5") != std::string::npos) prefixArgs[4] = (DWORD_PTR)"?";
	if (prefix.find("%6") != std::string::npos) prefixArgs[5] = (DWORD_PTR)"?";

	// указать имя уровня трассировки
	PCSTR szLevel = wpp_level_name(level); 

	// для всех позиций имени компонента
	for (size_t pos = prefix.find("%!COMPNAME!"); pos != std::string::npos; )
	{
		// заменить строку форматирования
		prefix.replace(pos, 11, szComponent);

		// найти позицию имени компонента
		pos = prefix.find("%!COMPNAME!", pos + strlen(szComponent));
	}
	// для всех позиций описания флагов
	for (size_t pos = prefix.find("%!FLAGS!"); pos != std::string::npos; )
	{
		// заменить строку форматирования
		prefix.replace(pos, 8, szFlags);

		// найти позицию описания флагов
		pos = prefix.find("%!FLAGS!", pos + strlen(szFlags)); 
	}
	// для всех позиций описания уровня
	for (size_t pos = prefix.find("%!LEVEL!"); pos != std::string::npos; )
	{
		// заменить строку форматирования
		prefix.replace(pos, 8, szLevel);

		// найти позицию описания флагов
		pos = prefix.find("%!LEVEL!", pos + strlen(szLevel));
	}
	// для всех позиций имени функции
	for (size_t pos = prefix.find("%!FUNC!"); pos != std::string::npos; )
	{
		// заменить строку форматирования
		prefix.replace(pos, 7, szFunction);

		// найти позицию имени функции
		pos = prefix.find("%!FUNC!", pos + strlen(szFunction));
	}
	// указать способ форматирования функции
	DWORD dwFlags = FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY; 

	// указать имя уровня трассировки
	PSTR szMessage; dwFlags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;

	// отформатировать сообщение
	if (::FormatMessageA(dwFlags, prefix.c_str(), 0, 
		LANG_SYSTEM_DEFAULT, (PSTR)&szMessage, 0, (va_list*)prefixArgs))
	{
		// вывести отформатированную строку
		(*print)(context, level, "%hs", szMessage); ::LocalFree(szMessage);
	}
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Выполнить форматирование WPP
///////////////////////////////////////////////////////////////////////////////
inline bool wpp_vprintln(pprintf print, void* context, 
	const char* szPrefix, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction, 
	bool noshrieks, const char* szFormat, va_list& args)
{
	// вывести префикс
	wpp_prefix_format(print, context, szPrefix, 
		szComponent, szFlags, level, szFile, line, szFunction
	); 
	// найти спецификацию форматирования или перевод строки
	size_t index = strcspn(szFormat, "%\n"); 

	// при нахождении спецификации или перевода строки
	for (; szFormat[index] != '\0'; index = strcspn(szFormat, "%\n"))
	{
		// для перевода строки в конце
		if (szFormat[index] == '\n' && szFormat[index + 1] == '\0')
		{
			// вывести часть строки без перевода строки
			(*print)(context, level, "%.*hs", (int)index, szFormat); 
			
			// перейти на следующую часть 
			szFormat += index + 1; break;
		}
		// для перевода строки в середине
		if (szFormat[index] == '\n' && szFormat[index + 1] != '\0')
		{
			// вывести часть строки с переводом строки
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 
			
			// вывести префикс
			wpp_prefix_format(print, context, szPrefix, 
				szComponent, szFlags, level, szFile, line, szFunction
			); 
			// перейти на следующую часть 
			szFormat += index + 1; continue;
		}
		// в случае экранирования
		if (szFormat[index + 1] == '\0') { break; } if (szFormat[index + 1] == '%')
		{
			// вывести часть строки
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 

			// перейти на следующую часть 
			szFormat += index + 2; continue; 
		}
		// вывести часть строки
		(*print)(context, level, "%.*hs", (int)index, szFormat); szFormat += index; 

		// при указании спецификации WPP
		if (szFormat[1] == '!')
		{
			// выполнить специальное форматирование
			if (size_t cch = wpp_special_format(print, context, szFormat, 
				szComponent, szFlags, level, szFile, line, szFunction)) 
			{
				szFormat += cch; continue; 
			}
			// найти элемент таблицы форматирования
			if (const wpp_format_entry* entry = wpp_find_format(szFormat + 2))
			{
				// определить размер имени типа
				size_t cch = strlen(entry->format); 

				// при наличии завершающего символа
				if (szFormat[2 + cch] == '!') { szFormat += 2 + cch + 1;
				
					// выполнить форматирование
					(*entry->func)(print, context, level, args); continue;
				}
			}
			// перейти на следующую часть 
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		if (noshrieks)
		{
			// найти элемент таблицы форматирования
			if (const wpp_format_entry* entry = wpp_find_format(szFormat + 1))
			{
				// пропустить спецификацию
				size_t cch = strlen(entry->format); szFormat += 1 + cch; 

				// выполнить форматирование
				(*entry->func)(print, context, level, args); continue; 
			}
		}
		// пропустить поле флагов
		const char* szNext = szFormat + 1 + strspn(szFormat + 1, " +-0#"); 

		// пропустить поле размера
		if (*szNext == '*') { return false; } szNext += strspn(szNext, "0123456789"); 
			
		// при наличии поля точности
		if (*szNext == '.') { if (*++szNext == '*') return false; 
		
			// пропустить поле точности
			szNext += strspn(szNext, "0123456789"); 
		}
		// сохранить текущую позицию
		const char* szSize = szNext; char format[128];
			
		// пропустить указание размера
#if defined _MSC_VER
		if (strncmp(szSize, "I64", 3) == 0) szNext += 3; else 
		if (strncmp(szSize, "I32", 3) == 0) szNext += 3; else 
		if (strncmp(szSize, "I"  , 1) == 0) szNext += 1; else 
#else 
		if (strncmp(szSize, "z"  , 1) == 0) szNext += 1; else 
#endif 
		if (strncmp(szSize, "hh" , 2) == 0) szNext += 2; else 
		if (strncmp(szSize, "h"  , 1) == 0) szNext += 1; else 
		if (strncmp(szSize, "w"  , 1) == 0) szNext += 1; else 
		if (strncmp(szSize, "ll" , 2) == 0) szNext += 2; else 
		if (strncmp(szSize, "l"  , 1) == 0) szNext += 1; else 
		if (strncmp(szSize, "L"  , 1) == 0) szNext += 1; else 
		if (strncmp(szSize, "j"  , 1) == 0) szNext += 1;
			
		// скопировать отдельную спецификацию
		strncpy_s(format, sizeof(format), szFormat, szNext + 1 - szFormat); 

		// в зависимости от способа форматирования
		switch (*((szFormat = szNext + 1) - 1))
		{
		// для целочисленных значений
		case 'i': case 'd': case 'o': case 'u': case 'x': case 'X': 
		{
			// в зависимости от размера
			if (szSize[0] == 'h' && szSize[1] == 'h') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<char>(args));  
			}
			// в зависимости от размера
			else if (szSize[0] == 'h') 
			{
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<short>(args));  
			}
			// в зависимости от размера
			else if (szSize[0] == 'l' && szSize[1] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<long long>(args));  
			} 
			// в зависимости от размера
			else if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<long>(args));  
			} 
#if defined _MSC_VER
			// в зависимости от размера
			else if (szSize[0] == 'I' && szSize[1] == '3' && szSize[2] == '2') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<__int32>(args));  
			} 
			// в зависимости от размера
			else if (szSize[0] == 'I' && szSize[1] == '6' && szSize[2] == '4') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<__int64>(args));  
			} 
			// в зависимости от размера
			else if (szSize[0] == 'I') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<size_t>(args));  
			} 
#else 
			// в зависимости от размера
			else if (szSize[0] == 'z') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<size_t>(args));  
			} 
#endif 
			// в зависимости от размера
			else if (szSize[0] == 'j') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<ptrdiff_t>(args));  
			} 
			else {
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<int>(args));  
			}
			break;
		}
#if !defined _NTDDK_
		// для чисел с плавающей точкой
		case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': 
		{	
			// в зависимости от размера
			if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<double>(args));  
			} 
			// в зависимости от размера
			else if (szSize[0] == 'L') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<long double>(args));  
			} 
			else {
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<double>(args));  
			}
			break; 
		}
#endif 
		case 'p': {
			// извлечь значение и вывести его представление
			(*print)(context, level, format, valist_extract<const void*>(args)); break; 
		}
		case 'c': 
		{
			// в зависимости от размера
			if (szSize[0] == 'h') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<char>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'w') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			else {
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<char>(args));
			}
			break; 
		}
		case 's': 
		{
			// в зависимости от размера
			if (szSize[0] == 'h') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'w') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			else {
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			break; 
		}
#if defined _MSC_VER
		case 'C':
		{
			// в зависимости от размера
			if (szSize[0] == 'h') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<char>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			else { 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			break; 
		}
		case 'S': 
		{
			// в зависимости от размера
			if (szSize[0] == 'h') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			// в зависимости от размера
			else if (szSize[0] == 'l') 
			{ 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			else { 
				// извлечь значение и вывести его представление
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			break; 
		}
		// извлечь значение и вывести его представление
		case 'z': format_hZ(print, context, level, args); break; 
#endif 
#if defined _WIN32
		case 'Z': 
		{
			// извлечь значение и вывести его представление
			if (szSize[0] == 'h') format_hZ(print, context, level, args); else 
			if (szSize[0] == 'l') format_lZ(print, context, level, args); else 
			if (szSize[0] == 'w') format_lZ(print, context, level, args); else 

			// вывести представление
			format_hZ(print, context, level, args); break; 
		}
#endif 
		default: return false; 
		}
	}
	// вывести оставшуюся часть строки
	(*print)(context, level, "%hs\n", szFormat); return true; 
}

inline void wpp_println(pprintf print, void* context, const char* szPrefix, 
	const char* szComponent, const char* szFlags, int level, const char* szFile, 
	int line, const char* szFunction, bool noshrieks, const char* szFormat, ...)
{
    // перейти на переданные аргументы
    va_list args; va_start(args, szFormat);

    // вывести сообщение
    wpp_vprintln(print, context, szPrefix, szComponent, szFlags, level, 
		szFile, line, szFunction, noshrieks, szFormat, args
	); 
	va_end(args); 
}
}

