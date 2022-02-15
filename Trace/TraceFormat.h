#pragma once
#include <stdio.h>
#include <limits.h>

///////////////////////////////////////////////////////////////////////////////
// ������������ ����������
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && !defined _NTDDK_
#pragma comment(lib, "ole32.lib")
#endif

///////////////////////////////////////////////////////////////////////////////
// �������������� ������ 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if !defined _MSC_VER
inline void strncpy_s(char* dest, size_t size, const char* source, size_t count)
{
	// ��������������� ������
	if (count > size - 1) { count = size - 1; } 

	// ����������� ������� ������ � ��������� ������
	::strncpy(dest, source, count); dest[size - 1] = '\0'; 
}
inline int vsnprintf(char* buffer, size_t size, const char* format, va_list args)
{
	// ��������� �������������� ������
	return ::vsnprintf(buffer, size, format, args); 
}
inline int snprintf(char* buffer, size_t size, const char* format, ...)
{
    // ������� �� ���������� ���������
    va_list args; va_start(args, format);

	// ��������� �������������� ������
    int cch = ::vsnprintf(buffer, size, format, args);

    // ���������� ���������� �������
    va_end(args); return cch;
}
inline int snprintf_ptr(char* buffer, size_t size, const void* ptr)
{
	// ������� ����� ���� ������ � ������ ��������������
	int digits = (int)(sizeof(ptr) * 2); const char* szFormat = "%0*zX"; 

    // ��������������� �����
    return snprintf(buffer, size, szFormat, digits, (uintptr_t)ptr); 
}
#else 
inline void strncpy_s(char* dest, size_t size, const char* source, size_t count)
{
	// ����������� ������� ������ � ����������� �����
	if (size > 0) ::strncpy_s(dest, size, source, count); 
}
inline int vsnprintf(char* buffer, size_t size, const char* format, va_list args)
{
	// ���������� ��������� ������ ������
	int cch = ::_vscprintf(format, args); if (cch <= 0 || size == 0) return cch; 

    // ��������������� ���������
	return (::_vsnprintf_s(buffer, size, _TRUNCATE, format, args) >= 0) ? cch : -1; 
}
inline int snprintf(char* buffer, size_t size, const char* format, ...)
{
    // ������� �� ���������� ���������
    va_list args; va_start(args, format);

	// ��������� �������������� ������
    int cch = vsnprintf(buffer, size, format, args);

    // ���������� ����������� �������
    va_end(args); return cch;
}
inline int snprintf_ptr(char* buffer, size_t size, const void* ptr)
{
	// ������� ����� ���� ������ � ������ ��������������
	int digits = (int)(sizeof(ptr) * 2); const char* szFormat = "%0*IX"; 

    // ��������������� �����
    return snprintf(buffer, size, szFormat, digits, (uintptr_t)ptr); 
}
#endif 

#if !defined _NTDDK_
inline std::string vsprintf(const char* format, va_list args)
{
	// ���������� ��������� ������ ������
	int cch = vsnprintf(nullptr, 0, format, args); if (cch <= 0) return std::string(); 

    // ��������������� ���������
	std::string str(cch + 1, 0); cch = vsnprintf(&str[0], cch + 1, format, args); 

	// ������� ������
	if (cch <= 0) { return std::string(); } str.resize(cch); return str; 
}

inline std::string sprintf(const char* format, ...)
{
    // ������� �� ���������� ���������
    va_list args; va_start(args, format);

    // ��������������� ���������
    std::string str = vsprintf(format, args);

    // ������� ���������
    va_end(args); return str;
}
#endif 
}
///////////////////////////////////////////////////////////////////////////////
// ����� ������� ������� ���������� ������� � ������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
inline size_t strcspn(const char* string, const char* control)
{
	// ��������� �������������� ����
	const unsigned char* str  = (const unsigned char*)string;
    const unsigned char* ctrl = (const unsigned char*)control;

	// ������� ����� ��������� ��������
	unsigned char map[32] = {0}; map[0] |= 1; int count = 0;
	
	// ��������� ������� ����� ��������� ��������
	for (; *ctrl; ctrl++) map[(*ctrl >> 3) & 0x1F] |= (unsigned char)(1 << (*ctrl & 7));

    // ���������� ��� ������������� �������
	for (; !(map[*str >> 3] & (1 << (*str & 7))); str++, count++) {}

    return count;
}
}
///////////////////////////////////////////////////////////////////////////////
// ����� ����������, ������������ �������� �������� � ������. 
// ����� ����������       ������������� ��� ���������� ���� unsigned int.
// ������������� �������� ������������� ��� ���������� ���� unsigned int.
// ������������� ������   ������������� ��� ���������� ���� unsigned long int.
///////////////////////////////////////////////////////////////////////////////
namespace trace {
#if defined _NTDDK_
inline ULONG current_processor()
{
	// ���������� ����� ����������
	return ::KeGetCurrentProcessorNumber(); 
}
inline ULONG current_process()
{
	// ���������� ������������� ��������
	return (ULONG)(SIZE_T)::PsGetCurrentProcessId(); 
}
inline ULONG current_thread()
{
	// ���������� ������������� ������
	return (ULONG)(SIZE_T)::PsGetCurrentThreadId(); 
}
#elif defined _WIN32
inline DWORD current_process()
{
	// ���������� ������������� ��������
	return ::GetCurrentProcessId(); 
}
inline DWORD current_thread()
{
	// ���������� ������������� ������
	return ::GetCurrentThreadId();
}
#if (_WIN32_WINNT < 0x0502)
inline DWORD current_processor() { return 1; }
#else
inline DWORD current_processor()
{
	// ���������� ����� ����������
	return ::GetCurrentProcessorNumber(); 
}
#endif 
#elif defined __linux__
inline int       current_processor() { return ::sched_getcpu(); }
inline pid_t     current_process  () { return ::getpid      (); }
inline pthread_t current_thread   () { return ::pthread_self(); }
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� �����. � ������ ���� ������������� ��� ���������� ���� 
// unsinged __int64, � ������ ������������ ������������� ��� ���������� 
// ���� const char* ����� ������ ������� ������� c_str().
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_
inline LARGE_INTEGER current_datetime()
{
	// �������� ������� ��������� ����� 
	LARGE_INTEGER st; KeQuerySystemTime(&st); 

	// �������� ������� ��������� ����� 
	LARGE_INTEGER lt; ::ExSystemTimeToLocalTime(&st, &lt); return lt; 
}
#elif defined _WIN32
inline std::string datetime_string(const SYSTEMTIME& st)
{
	// ������� ������������� �����������
	LCID lcid = LOCALE_SYSTEM_DEFAULT; std::string datetime;  

	// ���������� ��������� ������ ������
	int cchDate = ::GetDateFormatA(lcid, 0, &st, nullptr, nullptr, 0); 
	int cchTime = ::GetTimeFormatA(lcid, 0, &st, nullptr, nullptr, 0); 

	// �������� ����� ���������� �������
	datetime.resize(cchDate + cchTime); PSTR szDateTime = &datetime[0]; 

	// ��������������� ����
	cchDate = ::GetDateFormatA(lcid, 0, &st, nullptr, szDateTime, cchDate); 	

	// ������� �� ����� 
	szDateTime += strlen(szDateTime); *szDateTime++ = ' '; 

	// ��������������� �����
	cchTime = ::GetTimeFormatA(lcid, 0, &st, nullptr, szDateTime, cchTime); 	

	return datetime; 
}
inline std::string current_datetime()
{
	// ��������������� ������� �����
	SYSTEMTIME st; ::GetLocalTime(&st); return datetime_string(st); 
}
#elif defined __linux__
inline std::string current_datetime()
{
	// �������� ������� �����
	time_t result = ::time(0); char str[26];  

	// ��������������� �����
	::ctime_r(&result, str); return std::string(str, 24); 
}
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ���������� �� ������ ����������� �������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T>
inline T valist_extract(va_list& args) { return va_arg(args, T); }

template <>
inline char valist_extract<char>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<char>(va_arg(args, int)); 
}
template <>
inline signed char valist_extract<signed char>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<signed char>(va_arg(args, signed int)); 
}
template <>
inline unsigned char valist_extract<unsigned char>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<unsigned char>(va_arg(args, unsigned int)); 
}
#if defined _MSC_VER
#if !defined _WCHAR_T_DEFINED
template <>
inline wchar_t valist_extract<wchar_t>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<wchar_t>(va_arg(args, unsigned int)); 
}
#endif 
#elif WCHAR_MAX <= UINT_MAX
template <>
inline wchar_t valist_extract<wchar_t>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<wchar_t>(va_arg(args, unsigned int)); 
}
#endif 

template <>
inline signed short valist_extract<signed short>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<signed short>(va_arg(args, signed int)); 
}
template <>
inline unsigned short valist_extract<unsigned short>(va_list& args) 
{ 
	// ������� ��������
	return static_cast<unsigned short>(va_arg(args, unsigned int)); 
}
}
///////////////////////////////////////////////////////////////////////////////
// ���� ������ MOF (Managed Object Format). ������ �� �������� ������: �������
// ������ ����, �� ������� ���� ������ � ����� defaultwpp.ini ������������ WPP, 
// � ����� ����, ��������� �������� ������� ��������� �� ������������ �������. 
///////////////////////////////////////////////////////////////////////////////
// 1. ������������ ���� ��������:
//	  1) ItemListByte - ������ ���� �������� ��� ������������� ����, 
//       ������� � ����:
//       �������������  = �������� ������� 1 ����;
//       �������������� = ��� �� ������ ����������� ����;
//    2) ItemSetByte - ������ ���� �������� ����� ��� ������������� ����, 
//       ������� � ��������:
//       �������������  = �������� ������� 1 ����;
//       �������������� = ���������� ���� �� ����������� ������;
//    3) ItemListShort - ������ ���� �������� ��� ������������� ����, 
//       ������� � ����:
//       �������������  = �������� ������� 2 �����;
//       �������������� = ��� �� ������ ����������� ����;
//    4) ItemSetShort - ������ ���� �������� ����� ��� ������������� ����, 
//       ������� � ��������:
//       �������������  = �������� ������� 2 �����;
//       �������������� = ���������� ���� �� ����������� ������;
//    5) ItemListLong - ������ ���� �������� ��� ������������� ����, 
//       ������� � ����:
//       �������������  = �������� ������� 4 �����;
//       �������������� = ��� �� ������ ����������� ����;
//    6) ItemSetLong - ������ ���� �������� ����� ��� ������������� ����, 
//       ������� � ��������:
//       �������������  = �������� ������� 4 �����;
//       �������������� = ���������� ���� �� ����������� ������;
//    7) ItemEnum - ������������ C++ ����������������� ��������:
//       �������������  = �������� ������� 4 �����;
//       �������������� = ��� �� C++-����������� ������������ 
//                        (���� �������� .PDB-����);
//    8) ItemFlagsEnum - ������������ C++ ����������������� ������:
//       �������������  = �������� ������� 4 �����;
//       �������������� = ���������� ���� �� C++-����������� ������������ 
//                        (���� �������� .PDB-����);
// 2. ���������� ���� �������� (�������� � ������������� ��������): 
//     1) ItemChar - �������� 8-��������� �����:
//        �������������  = �������� ������� 1 ����;
//        �������������� = ;
//     2) ItemUChar - �����������  8-��������� �����:
//        �������������  = �������� ������� 1 ����;
//        �������������� = ;
//     3) ItemShort - �������� 16-��������� �����:
//        �������������  = �������� ������� 2 �����;
//        �������������� = 
//          d, hd = ���������� �������� �������������;
//          u, hu = ���������� ����������� �������������;
//          o, ho = ������������ �������������;
//          x, hx = ����������������� �������� �������������;
//          X, hX = ����������������� ��������� �������������;
//     4) ItemChar4 - �������� 32-��������� �����:         
//        �������������  = �������� ������� 4 �����;
//        �������������� = 
//			s = ���������� ������������� �� 4 ������; 
//     5) ItemLong - �������� 32-��������� �����:
//        �������������  = �������� ������� 4 �����;
//        �������������� = 
//          d, ld = ���������� �������� �������������;
//          u, lu = ���������� ����������� �������������;
//          o, lo = ������������ �������������;
//          x, lx = ����������������� �������� �������������;
//          X, lX = ����������������� ��������� �������������;
//     6) ItemLongLong - �������� 64-��������� �����:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          I64d  = ���������� �������� �������������;
//     7) ItemULongLong - ����������� 64-��������� �����:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          I64u = ���������� ����������� �������������;
//     8) ItemLongLongO - �������� 64-��������� �����:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          I64o = ������������ �������������;
//     9) ItemLongLongX - �������� 64-��������� �����:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          I64x = ����������������� �������� �������������;
//    10) ItemLongLongXX - �������� 64-��������� �����:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          I64X = ����������������� ��������� �������������;
//    11) ItemPtr - ����� (���������) ��� ����� ����������� ������:
//        �������������  = �������� ������� 4/8 ����;
//        �������������� = 
//          Id = ���������� �������� �������������;
//          Iu = ���������� ����������� �������������;
//          Io = ������������ �������������;
//          Ix = ����������������� �������� �������������;
//          IX = ����������������� ��������� �������������;
//          p  = ����������������� ������������� ������;
//    12) ItemDouble - ����� � ��������� ������:
//        �������������  = �������� ������� 8 ����;
//        �������������� = 
//          s = ��������� ������������� �����; 
//    13) ItemGuid - ���������� ������������� GUID:
//        �������������  = �������� ������� 16 ����;
//        �������������� = 
//          s = ��������� ������������� GUID; 
//    14) ItemIID - ������������� ���������� (IID):
//        �������������  = �������� ������� 16 ����;
//        �������������� = 
//          s = ��� ���������� IID (��������, IUnknown); 
//    15) ItemCLSID - ������������� ���������� (CLSID):
//        �������������  = �������� ������� 16 ����;
//        �������������� = 
//          s = ������������� ��� CLSID; 
//    16) ItemLIBID - ������������� ���������� ����� (LIBID):
//        �������������  = �������� ������� 16 ����;
//        �������������� = 
//          s = ������������� ��� LIBID; 
//    17) ItemTimestamp - ������� �������: 
//        �������������  = �������� FILETIME ������� 8 ����;
//        �������������� = 
//          s = ��������� ������������� �������; 
//    18) ItemTimeDelta - ����������������� ������� �������: 
//        �������������  = ����� ����������� ������� 8 ����;
//        �������������� = 
//          s = ��������� ������������� ����������������� ������� �������; 
//    19) ItemWaitTime - ����������������� ������� ��������: 
//        �������������  = ����� ����������� ������� 8 ����;
//        �������������� = 
//          s = ��������� ������������� ����������������� ������� �������; 
//    20) ItemMACAddr - MAC-�����: 
//         ������������� = MAC-����� ������� 6 ����;
//         �������������� = 
//          s = MAC-����� � ������� xx:xx:xx:xx:xx:xx; 
//    21) ItemIPAddr - ����� IPv4: 
//         ������������� = ����� IPv4 ������� 4 �����;
//         �������������� = 
//          s = ����� IPv4 � ������� xxx.xxx.xxx.xxx; 
//    22) ItemIPV6Addr - ����� IPv6: 
//         ������������� = ����� IPv6 ������� 16 ����;
//         �������������� = 
//          s = ��������� ������������� IPv6-������; 
//    23) ItemPort - ����� ����� TCP/IP: 
//         ������������� = ����� ����� ������� 2 �����;
//         �������������� = 
//          s = ��������� ������������� ������ �����; 
//    24) ItemNTerror - ����� ������ NTSTATUS: 
//         ������������� = ��� ������ NTSTATUS ������� 4 �����;
//         �������������� = 
//          s = ����� ������ NTSTATUS; 
//    25) ItemNTSTATUS - c������������ ��� ������ NTSTATUS: 
//         ������������� = ��� ������ NTSTATUS ������� 4 �����;
//         �������������� = 
//          s = c������������ ��� ������ NTSTATUS; 
//    26) ItemWINERROR - c������������ ��� ������ WinAPI: 
//         ������������� = ��� ������ WinAPI ������� 4 �����;
//         �������������� = 
//          s = c������������ ��� ������ WinAPI; 
//    27) ItemHRESULT - c������������ ��� ������ HRESULT: 
//         ������������� = ��� ������ HRESULT ������� 4 �����;
//         �������������� = 
//          s = c������������ ��� ������ HRESULT; 
// 3. ��������� ���� �������� (�������� � ���������� ��������): 
//     1) ItemString - ANSI-������ � ����������� �����: 
//        �������������  = ANSI-��������� ������ � ����������� \0;
//        �������������� = 
//          s = ���������� ������������� ������; 
//     2) ItemWString - Unicode-������ � ����������� �����: 
//        �������������  = UTF16-LE-��������� ������ � ����������� \0;
//        �������������� = 
//          s = ���������� ������������� ������; 
//     3) ItemRString - ANSI-������ � ����������� �����: 
//        �������������  = ANSI-��������� ������ � ����������� \0;
//        �������������� = 
//          s = ���������� ������������� ������ ����� ������ �������� 
//               \t, \n, \r �� ������� � �������� ����������� ��������; 
//     4) ItemRWString - Unicode-������ � ����������� �����: 
//        �������������  = UTF16-LE-��������� ������ � ����������� \0;
//        �������������� = 
//          s = ���������� ������������� ������ ����� ������ �������� 
//               \t, \n, \r �� ������� � �������� ����������� ��������;
//     5) ItemPString - ANSI-������ � ��������� �������: 
//        �������������  = 
//          ��� ����� = ������ ANSI-��������� ������ � ������ (��� ������������ \0); 
//          �����     = ANSI-��������� ������ ��� ������������ \0; 
//        �������������� = 
//          s = ���������� ������������� ������; 
//     6) ItemPWString - Unicode-������ � ��������� �������: 
//        �������������  = 
//          ��� ����� = ������ UTF16-LE-��������� ������ � ������ (��� ������������ \0); 
//          �����     = UTF16-LE-��������� ������ ��� ������������ \0; 
//        �������������� = 
//          s = ���������� ������������� ������; 
//     7) ItemHEXDump - �������� �����: 
//        �������������  = 
//          ��� ����� = ������ ������ � ������; 
//          �����     = �������� ���������� ������; 
//        �������������� = 
//          s = ����������������� ������������� ����������� ������; 
//     8) ItemSid - ������������� ������������ (SID): 
//        �������������  = �������� ���������� SID; 
//        �������������� = 
//          s = ��������� ������������� SID; 

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ������ �������������� ������������ WPP ��������� �� ��� 
// ������������ ���� %<NAME> � %!<NAME>!. ����������� ��� <NAME> �������� 
// ������ ���� WPP, �������� �������� ���������� � ����������� 
// ���������������� ����� defaultwpp.ini. � ������� �� ���� MOF, ������� 
// ��������� ��������� ������� ��������������, ��� WPP ������ � ������������ 
// �������� �������������� (� ������������ ����� MOF). 
// ���� WPP ������� �� 3 ���������: ������������, ���������� � ���������. 
// ��� ������������� ���������� � ��������� ����� ������������� WPP ���������� 
// ������������ ���������� ������� WPP_SF_<SIG1>...<SIGN>, ������� ����� 
// ���� ���������� ��������� ��������� ��������� ������ ��������������, � 
// ���� ���������� ������� ����� ���������������� ������� ���������� 
// ���������� ��������� � ���� (�����, ������), ������������ ������� 
// ����������� (�� ���������, TraceMessage). ��� ���������� ����� (�����, 
// �������� ������� ����� ������������� ������) ����������������� ��������� 
// �������� ������� WPP_LOGTYPEVAL � WPP_LOGTYPEPTR. ������ WPP_LOGTYPEVAL 
// ������� ���� (�����, ������) ��� �����, ������������ �� ��������, � 
// ������ WPP_LOGTYPEPTR ������� ���� (�����, ������) ��� �����, ������������ 
// ����� ���������. ��� ��������� ����� (�����, �������� ������� ����� 
// ���������� ������) ���������������� ������� ������ ������������ �������� 
// � �� ��� ������ ���� ������� � ������� ����������� ���������� ���� 
// (DEFINE_CPLX_TYPE). ���������������� ������� ������ ������������ �� 
// ������ ������� WPP_LOGPAIR, ������� ������������� � ��������� ���� 
// (�����, ������). 
// ����� ����, ��� ���� ����� �������������� ������������ WPP ������� 
// TMF-������ �������������� � ��������� ������������ ���� �� ���������� 
// ����� MOF, ������� ������������ �� ����� ���������� ���������� � 
// .PDB-����. ������ �������������� TMF ���������� �� �������� ������ 
// �������������� ���, ��� ������ �������� ������������ %<NAME> � %!<NAME>! 
// � ��� ���������� MOF-������������ %<NUMBER>!<FORMATSPEC>!, ��� � �������� 
// <NUMBER> ����������� ����� ���������, ������� � ������� 10 (������ 
// 9 ���������������), � � �������� <FORMATSPEC> ����������� ������ 
// �������������� MOF (��������, %10!I64X!). ����� ����, TMF-������ 
// �������������� ���������� � %0 (��� �������� ���������� ������������ 
// �������� ��� ������). ������� � ������� (���������) ������ �������������� 
// ����� �������������� ��� ������ �������� ������������� USEPREFIX � 
// USESUFFIX. ����� ��� ������ ��������� NOPREFIX ����� �������� ��������� 
// ������������ �������� %0 � TMF-������ ��������������. 

///////////////////////////////////////////////////////////////////////////////
// ������������ ���� �������� (������������ �������� CUSTOM_TYPE)
///////////////////////////////////////////////////////////////////////////////
// ItemListByte:
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemListByte(...));
//    c�������������� ��� MOF: ItemListByte;
//    ����������������� ���� WPP:
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
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemSetByte(...));
//    c�������������� ��� MOF: ItemSetByte;
//    ����������������� ���� WPP:
//      CUSTOM_TYPE(b1, ItemSetByte(1, 2, 3, 4, 5, 6, 7, 8));
// ItemListShort:
//    ������ �����������: CUSTOM_TYPE(<NAME>, ItemListShort(...));
//    c�������������� ��� MOF: ItemListShort;
//    ����������������� ���� WPP:
//	    CUSTOM_TYPE(bool16, ItemListShort(false, true));
// ItemSetShort:
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemSetShort(...));
//    c�������������� ��� MOF: ItemSetShort;
//    ����������������� ���� WPP:
//      CUSTOM_TYPE(b2, ItemSetShort(
//        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
//      ));
// ItemListLong:
//    ������ �����������: CUSTOM_TYPE(<NAME>, ItemListLong(...));
//    c�������������� ��� MOF: ItemListLong;
//    ����������������� ���� WPP:
//	    CUSTOM_TYPE(bool, ItemListLong(false, true));
//      CUSTOM_TYPE(BOOLEAN, ItemListByte(FALSE, TRUE));
// ItemSetLong:
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemSetLong(...));
//    c�������������� ��� MOF: ItemSetLong;
//    ����������������� ���� WPP:
//      CUSTOM_TYPE(b4, ItemSetLong(
//         1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 
//        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
//      ));
// ItemEnum:
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemEnum(...));
//    c�������������� ��� MOF: ItemEnum;
// ItemFlagsEnum:
//    c����� �����������: CUSTOM_TYPE(<NAME>, ItemFlagsEnum(...));
//    c�������������� ��� MOF: ItemFlagsEnum;

///////////////////////////////////////////////////////////////////////////////
// ���������� ���� �������� (����, �������� ������� ����� ������������� ������). 
// ���������� ���� �������� ������������ ���������� ���������: 
// 1) DEFINE_SIMPLE_TYPE(Name, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = ��� ���� WPP; 
//    EquivType  = ��� ���� C++, ������� ����� ����� ����������� ��������� 
//                 ����������� ���������� �������;
//    MofType    = ��� ���� MOF, ������� ����� ������������� � TMF-��������; 
//    FormatSpec = ������ �������������� ���� MOF; 
//    Sig        = �������, ����������� � ����� ����������� ���������� �������;
//    Priority   = ��������������� � ������ ���� 0 ��� �������������� 
//                 �����������. 
// 2) DEFINE_SIMPLE_TYPE_PTR(Name, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = ��� ���� WPP; 
//    EquivType  = ��� ���� ��������� C++, ������� ����� ����� ����������� 
//                 ��������� ����������� ���������� �������;
//    MofType    = ��� ���� MOF, ������� ����� ������������� � TMF-��������; 
//    FormatSpec = ������ �������������� ���� MOF; 
//    Sig        = �������, ����������� � ����� ����������� ���������� �������;
//    Priority   = ��������������� � ������ ���� 0 ��� �������������� 
//                 �����������. 
// 3) DEFINE_FLAVOR(Name, BaseType, [MofType, FormatSpec])
//    Name       = ��� ���� WPP; 
//    BaseType   = ������� ��� WPP, ��������� ����������� �������� ������������� 
//                 ��� ���������� ���������� MofType ���  FormatSpec; 
//    MofType    = ��� ���� MOF, ������� ����� ������������� � TMF-��������;
//    FormatSpec = ������ �������������� ���� MOF.
// ����������� DEFINE_SIMPLE_TYPE ������������ ��� �����, ������������ �� ��������,
// ���������� ������� ������� ��� �������� ��� (�����, ������) � ������������ 
// ������� ����������� ���������� ����� ������� WPP_LOGTYPEVAL: 
// WPP_LOGTYPEVAL(Type, Value) WPP_LOGPAIR(sizeof(Type), &(Value))
// ����������� DEFINE_SIMPLE_TYPE_PTR ������������ ��� �����, ������������ ����� 
// ���������, ���������� ������� ������� ��� �������� ��� (�����, ������) � 
// ������������ ������� ����������� ���������� ����� ������� WPP_LOGTYPEPTR: 
// WPP_LOGTYPEPTR(Value) WPP_LOGPAIR(sizeof(*(Value)), (Value))
// ����������� DEFINE_FLAVOR ������������ ��� ����������� ��������� ����� 
// WPP, � ����� �����, ������������ �� ������� ���������� ���������� (������ 
// ���� MOF ��� ������ ��������������, ������� ����������� � TMF-������). 
///////////////////////////////////////////////////////////////////////////////
// Name			Synonyms		MofType     FormatSpec     EquivType          Sig
// SCHAR		 c, hc			ItemChar        c          signed char         c
// UCHAR						ItemUChar       c          unsigned char       C
// SBYTE						ItemChar        c          signed char         c
// UBYTE						ItemChar        c          unsigned char       C
// OBYTE						ItemChar        o          signed char         c
// XBYTE						ItemChar        02x        signed char         c
// �			wc, lc			ItemShort       hd         signed short        h
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

// (*) ������������ I64 � ������� FormatSpec, ��� � ��� __int64 � ������� 
// EquivType, �������� ����������� Microsoft. 
// (**) ������ I � ������� FormatSpec �������� ����������� Microsoft, ������� 
// ������������� ������� z �������� ��������� C++. ������ z � ��������� ������ 
// �������������� Microsoft-����������� printf, �� ������ ���������� ��� ����� 
// �� ������������. 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���� �������� (�������� � ���������� ��������).  
// ��������� ���� �������� ������������ ���������� ���������: 
// 1) DEFINE_CPLX_TYPE(Name, MacroName, EquivType, MofType, FormatSpec, Sig, Priority)
//    Name       = ��� ���� WPP; 
//    MacroName  = ��� �������, ����������� ���� (������, �����) ������  
//                 ���������� �������; 
//    EquivType  = ��� ���� C++, ������� ����� ����� ��������� ����������� 
//                 ���������� �������;
//    MofType    = ��� ���� MOF, ������� ����� ������������� � TMF-��������; 
//    FormatSpec = ������ �������������� ���� MOF;  
//    Sig        = ������� <SIG>, ����������� � ����� ����������� 
//                 ���������� �������;
//    Priority   = ��������������� � ������ ���� 0 ��� �������������� 
//                 �����������. 
// 2) DEFINE_FLAVOR(Name, BaseType, [MofType, FormatSpec])
//    Name       = ��� ���� WPP; 
//    BaseType   = ������� ��� WPP, ��������� ����������� �������� ������������� 
//                 ��� ���������� ���������� MofType ���  FormatSpec; 
//    MofType    = ��� ���� MOF, ������� ����� ������������� � TMF-��������;
//    FormatSpec = ������ �������������� ���� MOF.
// ����������� DEFINE_CPLX_TYPE ������ ��� ����������������� �������, ������� 
// ������ ���� ��������� �������� �� ������ ������� WPP_LOGPAIR. 
// ����������� DEFINE_FLAVOR ������������ ��� ����������� ��������� ����� 
// WPP, � ����� �����, ������������ �� ������� ���������� ���������� (������ 
// ���� MOF ��� ������ ��������������, ������� ����������� � TMF-������). 
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

// (***) ��������� ������������ ����� ��������� ����� ��� �������������
// �� ��� ��� WPP � �������� printf: ��� z (WPP) ������������� printf-������������
// %hZ (������������� ���������� Microsoft), � ��� Z (WPP) - printf-������������ 
// %wZ (������������� ���������� Microsoft). ����� ����, ������������ %z � printf 
// ���������������� ��� ������� printf-������������ %I (������������� ���������� 
// Microsoft), � ��� WPP ��� �������� ��� z, ������� ��� printf ������������ %hZ 
// (������������� ���������� Microsoft). ������� �� ��������� ������ ��� ����� 
// const ANSI_STRING* � const CSTRING* � ������ �������������� WPP ���������� 
// ������������ %hZ, � ��� ���� PCUNICODE_STRING ������������ %wZ. 

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������������, ����������� � �������� ������
///////////////////////////////////////////////////////////////////////////////
// ������       ������������� �������� � TMF	��������
// %!COMPNAME!  �������� __COMPNAME__			��� ���������� (������������� �� ����������)
// %!FILE!      �������� __FILE__				��� �������� �����
// %!LINE!      �������� __LINE__				����� ������ �������� �����
// %!SPACE!     ������� " "						������
// %!FUNC!      ������� "%!FUNC!"				������ ��� ������� ����� �������  
// %!LEVEL!     ������� "%!LEVEL!"				������ ��� ������� ������ �����������  
// %!STDPREFIX! ������� "%0"					������ ��� ������� ������������ ��������  
// %!MOD!       ������� "%1!s!"					������ ��� ������� ������������� ����� ��� Message GUID  
// %!TYP!       ������� "%2!s!"					������ ��� ������� ����� ����� � ������  
// %!TID!       ������� "%3!x!"					������ ��� ������� �������������� ������  
// %!NOW!       ������� "%4!x!"					������ ��� ������� ������� �������  
// %!SEQ!       ������� "%7!x!"					������ ��� ������� ������ �������, ������������� � ������  
// %!PID!       ������� "%8!x!"					������ ��� ������� �������������� ��������  
// %!CPU!       ������� "%9!x!"					������ ��� ������� ������ ����������  

namespace trace {
///////////////////////////////////////////////////////////////////////////////
// ������� ��������������
///////////////////////////////////////////////////////////////////////////////
typedef void (*pprintf)(void*, int, const char*, ...); 

// �������������� ��������� ������������
typedef void (*pformat)(pprintf, void*, int, va_list&); 


template <typename T>
inline void stdformat(pprintf print, void* context, int level, const char* format, va_list& args)
{
	// ������� �������� ��������� � ��������� ��������������
	(*print)(context, level, format, valist_extract<T>(args));
}
///////////////////////////////////////////////////////////////////////////////
// �������������� ����� �����
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
// �������������� ���������� � ��������� �����
///////////////////////////////////////////////////////////////////////////////
inline void format_hc(pprintf print, void* context, int level, va_list& args) { stdformat<char    >(print, context, level, "%hc", args); }
inline void format_lc(pprintf print, void* context, int level, va_list& args) { stdformat<wchar_t >(print, context, level, "%lc", args); }

inline void format_hs(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ���������� ������
	const char* sz = valist_extract<const char*>(args); 

	// ��������� ��������������
	(*print)(context, level, "%hs", sz ? sz : "<null>");
}
inline void format_ls(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ���������� ������
	const wchar_t* sz = valist_extract<const wchar_t*>(args); 

	// ��������� ��������������
	(*print)(context, level, "%ls", sz ? sz : L"<null>");
}
#if defined _MSC_VER
inline void format_hZ(pprintf print, void* context, int level, va_list& args) { stdformat<void*   >(print, context, level, "%hZ", args); }
inline void format_lZ(pprintf print, void* context, int level, va_list& args) { stdformat<void*   >(print, context, level, "%lZ", args); }
#elif defined _WIN32
inline void format_hZ(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� ��������
	const ANSI_STRING* arg = valist_extract<const ANSI_STRING*>(args); 
	
	// ������� ������
	(*print)(context, level, "%.*hs", arg->Length / sizeof(CHAR), arg->Buffer); 
}
inline void format_lZ(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� ��������
	const UNICODE_STRING* arg = valist_extract<const UNICODE_STRING*>(args);
		
	// ������� ������
	(*print)(context, level, "%.*ls", arg->Length / sizeof(WCHAR), arg->Buffer); 
}
#endif 

inline void format_vhs(pprintf print, void* context, int level, va_list& args) 
{ 
#if defined _MSC_VER && _MSC_VER >= 1600 

	// ������� ������
	const _str& arg = va_arg(args, _str);
#else 
	// ������� ��������� ��������
	const char* sz = valist_extract<const char*>(args); 
	
	// ������� ������
	_str arg(sz, valist_extract<size_t>(args));
#endif 
	// ������� ������
	(*print)(context, level, "%.*hs", (int)arg.size(), arg.data()); 
}
inline void format_vls(pprintf print, void* context, int level, va_list& args) 
{ 
#if defined _MSC_VER && _MSC_VER >= 1600 

	// ������� ������
	const _wstr& arg = va_arg(args, _wstr);
#else 
	// ������� ��������� ��������
	const wchar_t* sz = valist_extract<const wchar_t*>(args); 
	
	// ������� ������
	_wstr arg(sz, valist_extract<size_t>(args));
#endif 
	// ������� ������
	(*print)(context, level, "%.*ls", (int)arg.size(), arg.data()); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_space(pprintf print, void* context, int level, va_list&) 
{
	// ��������� ��������������
	(*print)(context, level, " "); 
}

inline void format_bool8(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args); 

	// ��������� ��������������
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}

inline void format_bool16(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args);

	// ��������� ��������������
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}
inline void format_bool(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args); 

	// ��������� ��������������
	(*print)(context, level, "%hs", value ? "true" : "false"); 
}

inline void format_b1(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args); bool first = true; 

	// ��� ���� �����
	for (int i = 8, mask = 0x80; i > 0; mask >>= 1, i--)
	{
		// ��������� ��������� ����
		if ((value & mask) == 0) continue; 

		// ������� ����� �������������� ����
		if (!first) (*print)(context, level, ",%u", i);
		
		// ������� ����� �������������� ����
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_b2(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args); bool first = true; 

	// ��� ���� �����
	for (int i = 16, mask = 0x8000; i > 0; mask >>= 1, i--)
	{
		// ��������� ��������� ����
		if ((value & mask) == 0) continue; 

		// ������� ����� �������������� ����
		if (!first) (*print)(context, level, ",%u", i);
		
		// ������� ����� �������������� ����
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_b4(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ��������
	int value = valist_extract<int>(args); bool first = true; 

	// ��� ���� �����
	for (int i = 32, mask = 0x80000000; i > 0; mask >>= 1, i--)
	{
		// ��������� ��������� ����
		if ((value & mask) == 0) continue; 

		// ������� ����� �������������� ����
		if (!first) (*print)(context, level, ",%u", i);
		
		// ������� ����� �������������� ����
		else { (*print)(context, level, "%u", i); first = false; }
	}
}

inline void format_arstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������
	const char* str = valist_extract<const char*>(args); if (!str) return; 

    // ���������� ��������� �������
    str = str + strspn(str, " "); if (*str == '\0') return; 

    // ����� ���������� ������
    size_t index = strcspn(str, "\t\r\n"); 

    // ��� ������� ���������� ��������
    while (str[index] != '\0')
    {
	    // �������� ����� ������
	    (*print)(context, level, "%.*hs ", (int)index, str); str += index + 1;

        // ��������� ������� ������������ ��������
        if (str[strspn(str, " ")] == '\0') return; 

        // ����� ���������� ������
        index = strcspn(str, "\t\r\n"); 
    }
    // �������� ����� ������
    (*print)(context, level, "%.*hs", (int)index, str); 
}

inline void format_arwstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������
	const wchar_t* str = valist_extract<const wchar_t*>(args); if (!str) return; 

    // ���������� ��������� �������
    str = str + wcsspn(str, L" "); if (*str == L'\0') return; 

    // ����� ���������� ������
    size_t index = wcscspn(str, L"\t\r\n"); 

    // ��� ������� ���������� ��������
    while (str[index] != L'\0')
    {
	    // �������� ����� ������
	    (*print)(context, level, "%.*ls ", (int)index, str); str += index + 1;

        // ��������� ������� ������������ ��������
        if (str[wcsspn(str, L" ")] == L'\0') return; 

        // ����� ���������� ������
        index = wcscspn(str, L"\t\r\n"); 
    }
    // �������� ����� ������
    (*print)(context, level, "%.*ls", (int)index, str); 
}

///////////////////////////////////////////////////////////////////////////////
// C������ �������������� ��� WIN32
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
inline void format_cccc(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������������� ��������
	ULONG arg = valist_extract<ULONG>(args); 

	// ��������� ��������������
	(*print)(context, level, "%.4hs", &arg); 
}

inline void format_guid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������ ��������������
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx"; 

	// ������� �������������
	const GUID* guid = (const GUID*)valist_extract<const void*>(args); 

	// ������� ��������� ������������� ��������������
	(*print)(context, level, szFormat, guid->Data1, guid->Data2, guid->Data3, 
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]
	);
}

inline void format_abs_delta(pprintf print, void* context, int level, long long delta) 
{
	// ���������� ����� ������ ����
	long long days = delta / (24 * 60 * 60 * 1000); delta -= days * (24 * 60 * 60 * 1000);

	// ���������� ����� ������ �����, ����� � ������
	long long hours   = delta / (60 * 60 * 1000); delta -= hours   * (60 * 60 * 1000); 
	long long minutes = delta / (     60 * 1000); delta -= minutes * (     60 * 1000); 
	long long seconds = delta / (          1000); delta -= seconds * (          1000); 

	// ������� ������ ��������������
	if (days > 0) { const char* szFormat = "%llu~%lu:%lu:%lu.%03lu"; 

		// ������� ��������� �������������
		(*print)(context, level, szFormat, days, (long)hours, (long)minutes, (long)seconds, (long)delta); 
	}
	// ������� ������ ��������������
	else if (hours > 0) { const char* szFormat = "%lu:%lu:%lu.%03lu"; 

		// ������� ��������� �������������
		(*print)(context, level, szFormat, (long)hours, (long)minutes, (long)seconds, (long)delta); 
	}
	// ������� ������ ��������������
	else if (minutes > 0) { const char* szFormat = "%lu:%lu.%03lu"; 

		// ������� ��������� �������������
		(*print)(context, level, szFormat, (long)minutes, (long)seconds, (long)delta); 
	}
	// ������� ������ ��������������
	else { const char* szFormat = "%hs%lu.%03lu"; 

		// ������� ��������� �������������
		(*print)(context, level, szFormat, (long)seconds, (long)delta); 
	}
}

inline void format_delta(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ����� �����������
	long long delta = valist_extract<INT64>(args); if (delta < 0)
	{ 
		// �������� ���� �����
		delta = -delta; (*print)(context, level, "-"); 
	}
	// ������� ������� �� �������
	format_abs_delta(print, context, level, delta); 
}

inline void format_waittime(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ����� �����������
	long long delta = valist_extract<INT64>(args); if (delta > 0)
	{
		// ������� ������� �� �������
		format_abs_delta(print, context, level, delta); 
		
		// ������� �������� �����
		(*print)(context, level, " ago");
	}
	else if (delta < 0) 
	{
		// ������� ������� �� �������
		format_abs_delta(print, context, level, -delta); 
		
		// ������� �������� �����
		(*print)(context, level, " until");
	}
	// ������� ������� ������ �������
	else (*print)(context, level, "just now");  
}

inline void format_due(pprintf print, void* context, int level, va_list& args) 
{
	// ������� ����� �����������
	long long delta = valist_extract<INT64>(args); if (delta > 0)
	{
		// ������� ������� �� �������
		format_abs_delta(print, context, level, delta); 
		
		// ������� �������� �����
		(*print)(context, level, " until");
	}
	else if (delta < 0) 
	{
		// ������� ������� �� �������
		format_abs_delta(print, context, level, -delta); 
		
		// ������� �������� �����
		(*print)(context, level, " ago");
	}
	// ������� ������� ������ �������
	else (*print)(context, level, "just now");  
}

inline void format_ipaddr(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� �������������
	unsigned long ipaddr = valist_extract<UINT32>(args); 

	// ������� ������ ��������������
	const char* szFormat = "%hd.%hd.%hd.%hd"; 

	// ������� ��������� ������������� ��������������
	(*print)(context, level, szFormat,  (ipaddr >> 24) & 0xFF, 
		(ipaddr >> 16) & 0xFF, (ipaddr >>  8) & 0xFF, ipaddr & 0xFF
	);
}

inline void format_port(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� �������������
	unsigned short port = valist_extract<UINT16>(args); 

    // ������� ����� �����
	(*print)(context, level, "%hd", port); 
}

inline void format_status(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� �������������
	long status = valist_extract<NTSTATUS>(args);

    // ������� ��� ������
    (*print)(context, level, "NTSTATUS = %08lX", status); 
}

inline void format_winerror(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� �������������
	unsigned long code = valist_extract<ULONG>(args);

    // ������� ��� ������
    (*print)(context, level, "WINERROR = %ld", code); 
}

inline void format_hresult(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� �������������
	long code = valist_extract<LONG>(args);

    // ������� ��� ������
    (*print)(context, level, "HRESULT = %08lX", code); 
}

#endif 

#if defined _NTDDK_
inline void format_sid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������������� ������������
	PSID pSID = valist_extract<PSID>(args); UNICODE_STRING ustr = {0};

    // �������� ��������� ������������� ��������������
    NTSTATUS status = ::RtlConvertSidToUnicodeString(&ustr, pSID, TRUE); 

    // ���������� ��������� ������
    if (!NT_SUCCESS(status)) (*print)(context, level, "S-?-?"); 
    else {
        // ������� ��������� �������������
        (*print)(context, level, "%.*ls", ustr.Length / sizeof(WCHAR), ustr.Buffer); 

        // ���������� ���������� ������
        ::RtlFreeUnicodeString(&ustr); 
    }
}

inline void format_iid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� ������������� ��������������
	format_guid(print, context, level, args); 
}

inline void format_clsid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� ������������� ��������������
	format_guid(print, context, level, args); 
}

inline void format_libid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� �������������
	format_guid(print, context, level, args); 
}

inline void format_timestamp(pprintf print, void* context, int level, va_list& args) 
{
	// ������� �������� �������
	UINT64 value = valist_extract<UINT64>(args); 

	// ������� �������� ��������
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
	// ������� ������
	const std::string& arg = va_arg(args, std::string);

    // ������� ������
    (*print)(context, level, "%hs", arg.c_str()); 
}

inline void format_wstr(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������
	const std::wstring& arg = va_arg(args, std::wstring);

    // ������� ������
    (*print)(context, level, "%ls", arg.c_str()); 
}

#if _HAS_CXX17 == 1
inline void format_sv(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������
	const std::string_view& arg = va_arg(args, std::string_view);

    // ������� ������
    (*print)(context, level, "%.*hs", (int)arg.length(), arg.data()); 
}

inline void format_wsv(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������
	const std::wstring_view& arg = va_arg(args, std::wstring_view);

    // ������� ������
    (*print)(context, level, "%.*ls", (int)arg.length(), arg.data()); 
}
#endif 
#endif

#if defined _WIN32
inline void format_sid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������������� ������������
	PSID pSID = valist_extract<PSID>(args); PWSTR szSID = nullptr;

    // �������� ��������� ������������� ��������������
    if (!::ConvertSidToStringSidW(pSID, &szSID)) (*print)(context, level, "S-?-?"); 
    else {
        // ������� ��������� �������������
        (*print)(context, level, "%ls", szSID); ::LocalFree(szSID); 
    }
}

inline void format_iid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������ ��������������
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx"; 

	// ������� �������������
	const IID* iid = (const IID*)valist_extract<const void*>(args); 

	// �������� ��������� ������������� ��������������
	LPOLESTR szIID = nullptr; if (SUCCEEDED(::StringFromIID(*iid, &szIID)))
	{
		// ������� ��������� �������������
		(*print)(context, level, "%ls", szIID); ::CoTaskMemFree(szIID); 
	}
	else {
		// ������� ��������� ������������� ��������������
		(*print)(context, level, szFormat, iid->Data1, iid->Data2, iid->Data3, 
			iid->Data4[0], iid->Data4[1], iid->Data4[2], iid->Data4[3],
			iid->Data4[4], iid->Data4[5], iid->Data4[6], iid->Data4[7]
		);
	}
}

inline void format_clsid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ������ ��������������
	const char* szFormat = "%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx}"; 

	// ������� �������������
	const CLSID* clsid = (const CLSID*)valist_extract<const void*>(args); 

	// �������� ��������� ������������� ��������������
	LPOLESTR szCLSID = nullptr; if (SUCCEEDED(::ProgIDFromCLSID(*clsid, &szCLSID)))
	{
		// ������� ��������� �������������
		(*print)(context, level, "%ls", szCLSID); ::CoTaskMemFree(szCLSID); 
	}
	// �������� ��������� ������������� ��������������
	else if (SUCCEEDED(::StringFromCLSID(*clsid, &szCLSID)))
	{
		// ������� ��������� �������������
		(*print)(context, level, "%ls", szCLSID); ::CoTaskMemFree(szCLSID); 
	}
	else {
		// ������� ��������� ������������� ��������������
		(*print)(context, level, szFormat, clsid->Data1, clsid->Data2, clsid->Data3, 
			clsid->Data4[0], clsid->Data4[1], clsid->Data4[2], clsid->Data4[3],
			clsid->Data4[4], clsid->Data4[5], clsid->Data4[6], clsid->Data4[7]
		);
	}
}

inline void format_libid(pprintf print, void* context, int level, va_list& args) 
{ 
	// ������� ��������� �������������
	format_guid(print, context, level, args); 
}

inline void format_timestamp(pprintf print, void* context, int level, va_list& args) 
{
	// ������� �������� �������
	unsigned long long value = valist_extract<UINT64>(args); SYSTEMTIME st; 

	// �������� ��������� �����
	if (::FileTimeToSystemTime((const FILETIME*)&value, &st))
	{
		// ��������������� ��������� �����
		std::string datetime = datetime_string(st); 

		// ������� ��������� �������������
		(*print)(context, level, "%hs", datetime.c_str());
	}
	// ������� �������� ��������
	else (*print)(context, level, "%llu", value);  
}

#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ������������ ������������ � ������� ��������������. ������� �� 
// ��������� ���� wpp_format_entry, � ������� format - ������������ 
// ��������������, � func - ����� ������� ��������������. ������� �������� 
// �����������: ���� ���� func �������� ������� ��������, �� ���� format 
// �������� ����� ���������� ��������� ������� ��������������. ��������� 
// ���������� ��������� ������� �������������� �������� ������� ������� 
// �������� � ����� ����� format � func. 
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
// ������� ��������������
inline wpp_format_entry* wpp_format_table() { return _wpp_format_table; }

inline const wpp_format_entry* wpp_find_format(const char* format)
{
	// ����� ������� ���������� �������
	const char* szEnd = format + strcspn(format, "!"); 

	// ��� ���� ���������� �������
	for (const wpp_format_entry* fragment = wpp_format_table(); fragment; )
	{
		// ������� �� ������ ������� ���������
		const wpp_format_entry* entry = fragment; 

		// ��� ���� ��������� �������
		for (; entry->func; entry++)
		{
			// ���������� ������ ������
			size_t length = strlen(entry->format); 

			// ��������� ������ ������
			if (format + length != szEnd) continue; 

			// ��������� ���������� �������
			if (strncmp(entry->format, format, length) == 0) return entry; 
		}
		// ������� �� ��������� ��������
		fragment = (const wpp_format_entry*)entry->format; 
	}
	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void wpp_extend_format_table(const char* format, const wpp_format_entry* table)
{
	// ��� ���� ���������� �������
	for (wpp_format_entry* fragment = wpp_format_table(); fragment; )
	{
		// ������� �� ������ ������� ���������
		wpp_format_entry* entry = fragment; 

		// ��� ���� ��������� �������
		for (; entry->func; entry++)
		{
			// ��������� ������������ �������
			if (strcmp(entry->format, format) == 0) return; 
		}
		// ������� �� ��������� ��������
		fragment = (wpp_format_entry*)entry->format; 

		// ���������� ����� ������ ���������
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
// ��������� ��� ������ �����������
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
// ����������� �������������� WPP
///////////////////////////////////////////////////////////////////////////////
inline size_t wpp_special_format(pprintf print, void* context, 
	const char* szFormat, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction) 
{ 
	// ��� ����� ����������
	if (strncmp(szFormat, "%!COMPNAME!", 11) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, szComponent); return 11;  
	}
	// ��� ����� ����������
	if (strncmp(szFormat, "%!MOD!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, szComponent); return 6;  
	}
	// ��� ����� �����
	if (strncmp(szFormat, "%!FLAGS!", 8) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, szFlags); return 8; 
	}
	// ��� ������ �����������
	if (strncmp(szFormat, "%!LEVEL!", 8) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, wpp_level_name(level)); return 8; 
	}
	// ��� ����� �����
	if (strncmp(szFormat, "%!FILE!", 7) == 0) 
	{ 
		// ��������� ��������������
		(*print)(context, level, szFile); return 7; 
	}
	// ��� ������ ������ �����
	if (strncmp(szFormat, "%!LINE!", 7) == 0) 
	{
		// ��������� ��������������
		(*print)(context, level, "%u", line); return 7; 
	}
	// ��� ����� �������
	if (strncmp(szFormat, "%!FUNC!", 7) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, szFunction); return 7; 
	}
	// ��� ����� ����� � ������  
	if (strncmp(szFormat, "%!TYP!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, szFile); 
		
		// ��������� ��������������
		(*print)(context, level, " %d", line); return 6; 
	}
	// ��� ������ ����������
	if (strncmp(szFormat, "%!CPU!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, "%d", current_processor()); return 6; 
	}
	// ��� �������������� ��������
	if (strncmp(szFormat, "%!PID!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, "%d", current_process()); return 6; 
	}
	// ��� �������������� ������
	if (strncmp(szFormat, "%!TID!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, "%ld", current_thread()); return 6; 
	}
#if defined _NTDDK_
	// ��� �������� �������
	if (strncmp(szFormat, "%!NOW!", 6) == 0)
	{
		// ��������� ��������������
		(*print)(context, level, "%016I64X", current_datetime()); return 6; 
	}
#else
	// ��� �������� �������
	if (strncmp(szFormat, "%!NOW!", 6) == 0)
	{
		// �������� ������� �����
		std::string datetime = current_datetime();  

		// ��������� ��������������
		(*print)(context, level, "%hs", datetime.c_str()); return 6; 
	}
#endif 
	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ��������
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_ || !defined _WIN32
inline void wpp_prefix_format(pprintf print, void* context, 
	const char* szFormat, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction)
{
	// ����� ������������ ��������������
	size_t index = strcspn(szFormat, "%"); 

	// ��� ���������� ������������
	for (; szFormat[index] != '\0'; index = strcspn(szFormat, "%"))
	{
		// � ������ �������������
		if (szFormat[index + 1] == '\0') { break; } if (szFormat[index + 1] == '%')
		{
			// ������� ����� ������
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 

			// ������� �� ��������� ����� 
			szFormat += index + 2; continue; 
		}
		// ������� ����� ������
		(*print)(context, level, "%.*hs", (int)index, szFormat); szFormat += index; 

		// ��� �������� ������������ WPP
		if (szFormat[1] == '!')
		{
			// ��������� ����������� ��������������
			if (size_t cch = wpp_special_format(print, context, szFormat, 
				szComponent, szFlags, level, szFile, line, szFunction)) 
			{
				szFormat += cch; continue; 
			}
			// ������� �� ��������� ����� 
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		// ��������� �������� ������ ����������
		if ('1' > szFormat[1] || szFormat[1] > '9')
		{
			// ������� ����� ������
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		// ��������� ����� ������ ����������
		const char* szOrdinal = szFormat + 1; char format[128]; 

		// ��� �������� ������������
		if (*(szFormat += 2) == '!')
		{ 
			// ����� ����������� ������ ������������
			if (const char* szEnd = strchr(szFormat + 1, '!')) 
			{ 
				// ����������� ��������� ������������
				strncpy_s(format + 1, sizeof(format) - 1, szFormat + 1, szEnd - (szFormat + 1)); 

				// ���������� ������������
				format[0] = '%'; szFormat = szEnd + 1; 
			}
		}
		switch (*szOrdinal)
		{
		case '1': {
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%hs", 3); 

			// ������� ��� ����������
			(*print)(context, level, format, szComponent); break; 
		}
		case '2': {
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%hs", 3); 

			// ������� ��� ����� � ����� ������
			(*print)(context, level, format, szFile); (*print)(context, level, " %d", line); break;
		}
		case '3': {
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%lu", 3); 

			// ������� ������������� ������
			(*print)(context, level, format, current_thread()); break;
		}
#if defined _NTDDK_
		case '4': {
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// ������� ������� �����
			(*print)(context, level, format, current_datetime()); break;
		}
		case '5': {
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// ������� �������� �� ���������
			LARGE_INTEGER time; time.QuadPart = 0; 
			
			// ������� ����� � ������ ����
			(*print)(context, level, format, time); break;
		}
		case '6': { 
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%016I64X", 8); 
			}
			// ������� �������� �� ���������
			LARGE_INTEGER time; time.QuadPart = 0; 
			
			// ������� ����� � ������ ������������
			(*print)(context, level, format, time); break;
		}
#else 
		case '4': {
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// �������� ������� �����
			std::string datetime = current_datetime(); 
			
			// ������� ������� �����
			(*print)(context, level, format, datetime.c_str()); break;
		}
		case '5': {
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// ������� ����� � ������ ����
			(*print)(context, level, format, "?"); break;
		}
		case '6': { 
			// ��� ���������� �������� ��������������
			if (szFormat == szOrdinal + 1 || strcmp(format, "%s") == 0) 
			{
				// ������� ������ �������������� �� ���������
				strncpy_s(format, sizeof(format), "%hs", 3); 
			}
			// ������� ����� � ������ ������������
			(*print)(context, level, format, "?"); break;
		}
#endif 
		case '7': { 
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%ld", 3); 

			// ������� ����� ���������
			(*print)(context, level, format, 0L); break;
		}
		case '8': {
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%u", 2); 

			// ������� ������������� ��������
			(*print)(context, level, format, current_process()); break;
		}
		case '9': {
			// ������� ������ �������������� �� ���������
			if (szFormat == szOrdinal + 1) strncpy_s(format, sizeof(format), "%u", 2); 

			// ������� ������������� ����������
			(*print)(context, level, format, current_processor()); break;
		}}
	}
	// ������� ���������� ����� ������
	if (*szFormat) (*print)(context, level, "%hs", szFormat); 
}
#else 
inline void wpp_prefix_format(pprintf print, void* context, 
	const char* szPrefix, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction)
{
	// ����������� �������
	std::string prefix(szPrefix); if (prefix.length() == 0) return; 

	// �������� ������������ ������
	std::string message; std::string fileLine; std::string datetime; 

	// �������� ������ ��� ���������� ��������
	DWORD_PTR prefixArgs[9] = { (DWORD_PTR)szComponent }; 
	
	// ��� ������� ����� �����
	if (prefix.find("%2") != std::string::npos) 
	{
		// ��������������� ����� ������
		char szLine[16]; sprintf_s(szLine, sizeof(szLine), "%d", line); 

		// ���������� ��� ����� � ������
		fileLine = szFile; fileLine += " "; fileLine += szLine; 
		
		// ������� ��� ����� � ������
		prefixArgs[1] = (DWORD_PTR)fileLine.c_str(); 
	}
	// ��� ������� ������� �������
	if (prefix.find("%4") != std::string::npos) { datetime = current_datetime();
	
		// ������� ������� �����
		prefixArgs[3] = (DWORD_PTR)datetime.c_str(); 
	}
	// ������� ����� ����������, �������������� �������� � ������
	if (prefix.find("%9") != std::string::npos) prefixArgs[8] = current_processor();
	if (prefix.find("%8") != std::string::npos) prefixArgs[7] = current_process  ();
	if (prefix.find("%3") != std::string::npos) prefixArgs[2] = current_thread   ();

	// ������� ����������� ������
	if (prefix.find("%5") != std::string::npos) prefixArgs[4] = (DWORD_PTR)"?";
	if (prefix.find("%6") != std::string::npos) prefixArgs[5] = (DWORD_PTR)"?";

	// ������� ��� ������ �����������
	PCSTR szLevel = wpp_level_name(level); 

	// ��� ���� ������� ����� ����������
	for (size_t pos = prefix.find("%!COMPNAME!"); pos != std::string::npos; )
	{
		// �������� ������ ��������������
		prefix.replace(pos, 11, szComponent);

		// ����� ������� ����� ����������
		pos = prefix.find("%!COMPNAME!", pos + strlen(szComponent));
	}
	// ��� ���� ������� �������� ������
	for (size_t pos = prefix.find("%!FLAGS!"); pos != std::string::npos; )
	{
		// �������� ������ ��������������
		prefix.replace(pos, 8, szFlags);

		// ����� ������� �������� ������
		pos = prefix.find("%!FLAGS!", pos + strlen(szFlags)); 
	}
	// ��� ���� ������� �������� ������
	for (size_t pos = prefix.find("%!LEVEL!"); pos != std::string::npos; )
	{
		// �������� ������ ��������������
		prefix.replace(pos, 8, szLevel);

		// ����� ������� �������� ������
		pos = prefix.find("%!LEVEL!", pos + strlen(szLevel));
	}
	// ��� ���� ������� ����� �������
	for (size_t pos = prefix.find("%!FUNC!"); pos != std::string::npos; )
	{
		// �������� ������ ��������������
		prefix.replace(pos, 7, szFunction);

		// ����� ������� ����� �������
		pos = prefix.find("%!FUNC!", pos + strlen(szFunction));
	}
	// ������� ������ �������������� �������
	DWORD dwFlags = FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY; 

	// ������� ��� ������ �����������
	PSTR szMessage; dwFlags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;

	// ��������������� ���������
	if (::FormatMessageA(dwFlags, prefix.c_str(), 0, 
		LANG_SYSTEM_DEFAULT, (PSTR)&szMessage, 0, (va_list*)prefixArgs))
	{
		// ������� ����������������� ������
		(*print)(context, level, "%hs", szMessage); ::LocalFree(szMessage);
	}
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� �������������� WPP
///////////////////////////////////////////////////////////////////////////////
inline bool wpp_vprintln(pprintf print, void* context, 
	const char* szPrefix, const char* szComponent, const char* szFlags, 
	int level, const char* szFile, int line, const char* szFunction, 
	bool noshrieks, const char* szFormat, va_list& args)
{
	// ������� �������
	wpp_prefix_format(print, context, szPrefix, 
		szComponent, szFlags, level, szFile, line, szFunction
	); 
	// ����� ������������ �������������� ��� ������� ������
	size_t index = strcspn(szFormat, "%\n"); 

	// ��� ���������� ������������ ��� �������� ������
	for (; szFormat[index] != '\0'; index = strcspn(szFormat, "%\n"))
	{
		// ��� �������� ������ � �����
		if (szFormat[index] == '\n' && szFormat[index + 1] == '\0')
		{
			// ������� ����� ������ ��� �������� ������
			(*print)(context, level, "%.*hs", (int)index, szFormat); 
			
			// ������� �� ��������� ����� 
			szFormat += index + 1; break;
		}
		// ��� �������� ������ � ��������
		if (szFormat[index] == '\n' && szFormat[index + 1] != '\0')
		{
			// ������� ����� ������ � ��������� ������
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 
			
			// ������� �������
			wpp_prefix_format(print, context, szPrefix, 
				szComponent, szFlags, level, szFile, line, szFunction
			); 
			// ������� �� ��������� ����� 
			szFormat += index + 1; continue;
		}
		// � ������ �������������
		if (szFormat[index + 1] == '\0') { break; } if (szFormat[index + 1] == '%')
		{
			// ������� ����� ������
			(*print)(context, level, "%.*hs", (int)(index + 1), szFormat); 

			// ������� �� ��������� ����� 
			szFormat += index + 2; continue; 
		}
		// ������� ����� ������
		(*print)(context, level, "%.*hs", (int)index, szFormat); szFormat += index; 

		// ��� �������� ������������ WPP
		if (szFormat[1] == '!')
		{
			// ��������� ����������� ��������������
			if (size_t cch = wpp_special_format(print, context, szFormat, 
				szComponent, szFlags, level, szFile, line, szFunction)) 
			{
				szFormat += cch; continue; 
			}
			// ����� ������� ������� ��������������
			if (const wpp_format_entry* entry = wpp_find_format(szFormat + 2))
			{
				// ���������� ������ ����� ����
				size_t cch = strlen(entry->format); 

				// ��� ������� ������������ �������
				if (szFormat[2 + cch] == '!') { szFormat += 2 + cch + 1;
				
					// ��������� ��������������
					(*entry->func)(print, context, level, args); continue;
				}
			}
			// ������� �� ��������� ����� 
			(*print)(context, level, "%.*hs", 2, szFormat); szFormat += 2; continue;
		}
		if (noshrieks)
		{
			// ����� ������� ������� ��������������
			if (const wpp_format_entry* entry = wpp_find_format(szFormat + 1))
			{
				// ���������� ������������
				size_t cch = strlen(entry->format); szFormat += 1 + cch; 

				// ��������� ��������������
				(*entry->func)(print, context, level, args); continue; 
			}
		}
		// ���������� ���� ������
		const char* szNext = szFormat + 1 + strspn(szFormat + 1, " +-0#"); 

		// ���������� ���� �������
		if (*szNext == '*') { return false; } szNext += strspn(szNext, "0123456789"); 
			
		// ��� ������� ���� ��������
		if (*szNext == '.') { if (*++szNext == '*') return false; 
		
			// ���������� ���� ��������
			szNext += strspn(szNext, "0123456789"); 
		}
		// ��������� ������� �������
		const char* szSize = szNext; char format[128];
			
		// ���������� �������� �������
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
			
		// ����������� ��������� ������������
		strncpy_s(format, sizeof(format), szFormat, szNext + 1 - szFormat); 

		// � ����������� �� ������� ��������������
		switch (*((szFormat = szNext + 1) - 1))
		{
		// ��� ������������� ��������
		case 'i': case 'd': case 'o': case 'u': case 'x': case 'X': 
		{
			// � ����������� �� �������
			if (szSize[0] == 'h' && szSize[1] == 'h') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<char>(args));  
			}
			// � ����������� �� �������
			else if (szSize[0] == 'h') 
			{
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<short>(args));  
			}
			// � ����������� �� �������
			else if (szSize[0] == 'l' && szSize[1] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<long long>(args));  
			} 
			// � ����������� �� �������
			else if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<long>(args));  
			} 
#if defined _MSC_VER
			// � ����������� �� �������
			else if (szSize[0] == 'I' && szSize[1] == '3' && szSize[2] == '2') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<__int32>(args));  
			} 
			// � ����������� �� �������
			else if (szSize[0] == 'I' && szSize[1] == '6' && szSize[2] == '4') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<__int64>(args));  
			} 
			// � ����������� �� �������
			else if (szSize[0] == 'I') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<size_t>(args));  
			} 
#else 
			// � ����������� �� �������
			else if (szSize[0] == 'z') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<size_t>(args));  
			} 
#endif 
			// � ����������� �� �������
			else if (szSize[0] == 'j') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<ptrdiff_t>(args));  
			} 
			else {
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<int>(args));  
			}
			break;
		}
#if !defined _NTDDK_
		// ��� ����� � ��������� ������
		case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': 
		{	
			// � ����������� �� �������
			if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<double>(args));  
			} 
			// � ����������� �� �������
			else if (szSize[0] == 'L') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<long double>(args));  
			} 
			else {
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<double>(args));  
			}
			break; 
		}
#endif 
		case 'p': {
			// ������� �������� � ������� ��� �������������
			(*print)(context, level, format, valist_extract<const void*>(args)); break; 
		}
		case 'c': 
		{
			// � ����������� �� �������
			if (szSize[0] == 'h') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<char>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'w') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			else {
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<char>(args));
			}
			break; 
		}
		case 's': 
		{
			// � ����������� �� �������
			if (szSize[0] == 'h') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'w') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			else {
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			break; 
		}
#if defined _MSC_VER
		case 'C':
		{
			// � ����������� �� �������
			if (szSize[0] == 'h') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<char>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			else { 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<wchar_t>(args));
			}
			break; 
		}
		case 'S': 
		{
			// � ����������� �� �������
			if (szSize[0] == 'h') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const char*>(args));
			}
			// � ����������� �� �������
			else if (szSize[0] == 'l') 
			{ 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			else { 
				// ������� �������� � ������� ��� �������������
				(*print)(context, level, format, valist_extract<const wchar_t*>(args));
			}
			break; 
		}
		// ������� �������� � ������� ��� �������������
		case 'z': format_hZ(print, context, level, args); break; 
#endif 
#if defined _WIN32
		case 'Z': 
		{
			// ������� �������� � ������� ��� �������������
			if (szSize[0] == 'h') format_hZ(print, context, level, args); else 
			if (szSize[0] == 'l') format_lZ(print, context, level, args); else 
			if (szSize[0] == 'w') format_lZ(print, context, level, args); else 

			// ������� �������������
			format_hZ(print, context, level, args); break; 
		}
#endif 
		default: return false; 
		}
	}
	// ������� ���������� ����� ������
	(*print)(context, level, "%hs\n", szFormat); return true; 
}

inline void wpp_println(pprintf print, void* context, const char* szPrefix, 
	const char* szComponent, const char* szFlags, int level, const char* szFile, 
	int line, const char* szFunction, bool noshrieks, const char* szFormat, ...)
{
    // ������� �� ���������� ���������
    va_list args; va_start(args, szFormat);

    // ������� ���������
    wpp_vprintln(print, context, szPrefix, szComponent, szFlags, level, 
		szFile, line, szFunction, noshrieks, szFormat, args
	); 
	va_end(args); 
}
}

