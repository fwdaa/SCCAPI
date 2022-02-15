#pragma once
///////////////////////////////////////////////////////////////////////////////
// Определение nullptr
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1700
#if !defined _MANAGED || _MANAGED == 0
#define nullptr 0
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
// Стандартные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include <wmistr.h>                     // определения WMI
#include <evntrace.h>                   // определения ETW
#else 
#define TRACE_LEVEL_NONE            0   // отсутствие трассировки
#define TRACE_LEVEL_CRITICAL        1   // критическая ошибка
#define TRACE_LEVEL_ERROR           2   // ошибка
#define TRACE_LEVEL_WARNING         3   // предупреждение
#define TRACE_LEVEL_INFORMATION     4   // информация
#define TRACE_LEVEL_VERBOSE         5   // детализированная информация
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение имени функции
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER
#define __FUNC__    __FUNCSIG__
#else 
#define __FUNC__    __func__
#endif 

///////////////////////////////////////////////////////////////////////////////
// Запрет встраивания функций
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER
#define WPP_NOINLINE        __declspec(noinline)
#else 
#define WPP_NOINLINE        __attribute__((noinline)) 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Создание литеральной строки
///////////////////////////////////////////////////////////////////////////////
#define WPP_STR(      x)          # x
#define WPP_STRINGIZE(x)    WPP_STR(x)

///////////////////////////////////////////////////////////////////////////////
// Создание уникального имени переменной
///////////////////////////////////////////////////////////////////////////////
#define WPP_GLUE(x, y)      x ## y
#define WPP_VAR(LINE )      WPP_GLUE(Trace, LINE)

///////////////////////////////////////////////////////////////////////////////
// Настройка провайдера трассировки
///////////////////////////////////////////////////////////////////////////////
#if !defined WPP_CONTROL_NAME
#error [Trace.h] The WPP_CONTROL_NAME should be defined prior to including Trace.h
#endif

// Указать имя компонента
#if !defined __COMPNAME__
#define __COMPNAME__ WPP_CONTROL_NAME
#endif 

// Определение дополнительных компонентов
#if !defined WPP_STATIC_LIB_GUIDS
#define WPP_STATIC_LIB_GUIDS
#endif 

// Определение идентификаторов трассировки
#if defined WPP_CONTROL_GUID
#define WPP_CONTROL_GUIDS                                           \
    WPP_DEFINE_CONTROL_GUID(WPP_CONTROL_NAME, WPP_CONTROL_GUID,     \
        WPP_DEFINE_BIT(ALL)                                         \
    )                                                               \
    WPP_STATIC_LIB_GUIDS
#endif
// Строковое представление имени провайдера
#define WPP_COMPNAME WPP_STRINGIZE(__COMPNAME__)

///////////////////////////////////////////////////////////////////////////////
// Дополнительно используемые файлы
///////////////////////////////////////////////////////////////////////////////
#include <stdarg.h>         // функции с переменным числом аргументов
#include <string.h>         // строковые функции 

#if !defined _NTDDK_
#include <stdlib.h>         // функции общего назначения
#include <string>           // строковые функции C++
#if _HAS_CXX17 == 1
#include <string_view>      // строковое расширение C++17
#endif
#if defined _WIN32
#include <winternl.h>		// дополнительные определения Windows 
#include <sddl.h>			// система безопасности Windows
#include <objbase.h>        // определения COM
#endif 
#if defined __linux__
#include <unistd.h>         // определения Unix
#include <pthread.h>        // информация потоков
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Указание правильного соглашения о вызове функции TraceMessageVa. 
// В некоторых версиях файла evntrace.h stdcall-функция TraceMessageVa 
// объявлена без указания соглашения о вызове, что при использовании 
// компилятором по умолчанию соглашения __cdecl приводит к формированию 
// неправильного декорированного имени функции и нарушению стека при 
// выполнении функции. 
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS && !defined _NTDDK_
#if defined _MSC_VER && !defined _WIN64
#pragma comment(linker, "/alternatename:_TraceMessageVa=_TraceMessageVa@24")

// указать правильный прототип функции
typedef ULONG (WINAPI *PFN_TRACE_MESSAGE_VA)(TRACEHANDLE, ULONG, LPCGUID, USHORT, va_list);

// вызвать функцию трассировки
inline ULONG WINAPI CallTraceMessageVa(TRACEHANDLE LoggerHandle,
    ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList)
{
    // выполнить преобразование типа
    PFN_TRACE_MESSAGE_VA pfn = (PFN_TRACE_MESSAGE_VA)::TraceMessageVa; 

    // выполнить трассировку
    return (*pfn)(LoggerHandle, MessageFlags, MessageGuid, MessageNumber, MessageArgList); 
}
#else 
// вызвать функцию трассировки
inline ULONG WINAPI CallTraceMessageVa(TRACEHANDLE LoggerHandle,
    ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList)
{
    // выполнить трассировку
    return ::TraceMessageVa(LoggerHandle, 
        MessageFlags, (LPGUID)MessageGuid, MessageNumber, MessageArgList
    ); 
}
#endif 
#endif

// Во избежание дублирования определения компонентов в .tmc-файлах при сборке
// Release-версии необходимо удалять неиспользуемые символы через опцию 
// связывания /OPT:REF. 

///////////////////////////////////////////////////////////////////////////////
// Трассировка строк фиксированного размера
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(.*s , WPP_LOGCPPVEC, const trace::_str &, ItemPString,  "s",  str, 0);
// DEFINE_CPLX_TYPE(.*hs, WPP_LOGCPPVEC, const trace::_str &, ItemPString,  "s",  str, 0);
// DEFINE_CPLX_TYPE(.*ls, WPP_LOGCPPVEC, const trace::_wstr&, ItemPWString, "s", wstr, 0);
// DEFINE_CPLX_TYPE(.*ws, WPP_LOGCPPVEC, const trace::_wstr&, ItemPWString, "s", wstr, 0);
// end_wpp

namespace trace { 
struct _str { const char* _sz; size_t _cch;
    
    // конструктор
    _str(const char* sz, size_t cch) : _sz(sz), _cch(cch) {} 

    // адрес строки
    const char* data() const { return _sz; }

    // размер строки
    size_t size() const { return _cch; }
};
struct _wstr { const wchar_t* _sz; size_t _cch;
    
    // конструктор
    _wstr(const wchar_t* sz, size_t cch) : _sz(sz), _cch(cch) {}

    // адрес строки
    const wchar_t* data() const { return _sz; }

    // размер строки
    size_t size() const { return _cch; }
};
}

///////////////////////////////////////////////////////////////////////////////
// Параметры трассировки (переменные окружения)
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
namespace trace {
extern std::string GetEnvironmentVariable(const char*);
class ControlParameters
{ 
	// конструктор
	public: ControlParameters() { Update(); } private: std::string prefix;

    // обновить значения переменных
    public: void Update() { prefix = GetEnvironmentVariable("TRACE_FORMAT_PREFIX"); }
	// значение префикса
	public: const char* DebugPrefix() const 
	{ 
		// значение префикса
		return (prefix.length() != 0) ? prefix.c_str() : nullptr; 
	}
};
#if !defined WPP_CONTROL_GUIDS 
inline const ControlParameters* GetControlParameters() 
{ 
	// получить способ записи префикса
	static ControlParameters parameters; return &parameters;
}
#else 
// получить параметры трассировки
const ControlParameters* GetControlParameters(); 
#endif 
}
#endif

///////////////////////////////////////////////////////////////////////////////
// Включаемые заголовочные файлы
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#include "TraceUTF.h"       // преобразование кодировок
#endif 
#include "TraceFormat.h"    // форматирование строк
#include "TraceDebug.h"     // вывод сообщений в отладчик

///////////////////////////////////////////////////////////////////////////////
// Предварительное объявление функций
///////////////////////////////////////////////////////////////////////////////
void WppTraceStringA(int level, const char   * sz, size_t cch = -1); 
void WppTraceStringW(int level, const wchar_t* sz, size_t cch = -1); 

///////////////////////////////////////////////////////////////////////////////
// Вывод сообщения в отладчик. Служебная информация WPP выводится при 
// помощи макроса WppDebug(n, MsgArgs), где n - внутренний номер, а 
// MsgArgs - заключенные в круглые скобки строка форматирования и ее 
// параметры. В используемой реализации указанная информация будет 
// передаваться отладчику с уровнем трассировки TRACE_LEVEL_INFORMATION. 
///////////////////////////////////////////////////////////////////////////////
inline void WppDebugPrintV(int level, const char* szFile, 
    int line, const char* szFunction, const char* szFormat, va_list& args)
{
    // отменить удаление неиспользуемых функций
    void (*pfnA)(int, const char   *, size_t) = &WppTraceStringA; (*pfnA)(0, nullptr, 0); 
    void (*pfnW)(int, const wchar_t*, size_t) = &WppTraceStringW; (*pfnW)(0, nullptr, 0);

#if !defined _NTDDK_ && defined WPP_CONTROL_GUIDS
	// проверить необходимость вывода
	if (level == TRACE_LEVEL_VERBOSE) return; 
#endif 
	// проверить необходимость вывода
	if (level == TRACE_LEVEL_NONE) return; 

    // передать сообщение отладчику
    trace::DebugPrintV(WPP_COMPNAME, "ALL", level, 
        szFile, line, szFunction, false, szFormat, args
	); 
}

inline void WppDebugPrint(int level, const char* szFile, 
    int line, const char* szFunction, const char* szFormat, ...)
{
    // перейти на переменное число параметров
    va_list args; va_start(args, szFormat); 

    // передать сообщение отладчику
	WppDebugPrintV(level, szFile, line, szFunction, szFormat, args); 	

	// освободить выделенные ресурсы
	va_end(args);
}
// добавление фиксированных параметров 
#define WPP_DEBUG_PRINT(...)	WppDebugPrint(	\
	TRACE_LEVEL_INFORMATION,                    \
	__FILE__, __LINE__, __FUNC__, __VA_ARGS__	\
)
// перенаправление служебной информации
#define WppDebug(n, MsgArgs) WPP_DEBUG_PRINT MsgArgs

///////////////////////////////////////////////////////////////////////////////
// Выполнение любой трассировки вида ATRACE(TRACELEVEL,...,MSG,...) определяется 
// следующим алгоритмом: 
// WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_<XXX>(...), MSG,...)
// WPP_TRACELEVEL_<XXX>_PRE(TRACELEVEL, ...)
// ((
//     WPP_TRACELEVEL_<XXX>_ENABLED(TRACELEVEL, ...)
//     ? WPP_INVOKE_WPP_DEBUG((MSG,...)), WPP_SF_<SIG>(...), 1 : 0
// ))
// WPP_TRACELEVEL_<XXX>_POST(TRACELEVEL, ...)
///////////////////////////////////////////////////////////////////////////////
// 1) Макрос WPP_LOG_ALWAYS используется для дополнительного вывода сообщений 
//    в отладчик. Ему передаются все параметры, возвращаемые макросом
//    WPP_EX_TRACELEVEL_<XXX>, а также строка форматирования и ее аргументы. 
//    Параметры, возвращаемые макросом WPP_EX_TRACELEVEL_<XXX>, используются 
//    для проверки необходимости вывода сообщений, а также определения уровня 
//    трассировки, используемого в отладчике. Если переданный уровень равен 
//    TRACE_LEVEL_NONE, то вывод в отладчик не производится. В противном случае, 
//    a) в режиме ядра вывод в отладчик осуществляется в соответствии со 
//       следующей таблицей: 
//       TRACE_LEVEL_CRITICAL    -> DPFLTR_ERROR_LEVEL;
//       TRACE_LEVEL_ERROR       -> DPFLTR_ERROR_LEVEL;
//       TRACE_LEVEL_WARNING     -> DPFLTR_WARNING_LEVEL;
//       TRACE_LEVEL_INFORMATION -> DPFLTR_INFO_LEVEL;
//       TRACE_LEVEL_VERBOSE     -> DPFLTR_TRACE_LEVEL;
//    b) в режиме пользователя уровень трассировки игнорируется и вывод 
//       в отладчик производится всегда, за исключением уровня 
//       TRACE_LEVEL_VERBOSE при наличии ETW-трассировки. 
// 2) Макрос WPP_EX_TRACELEVEL_<XXX>, как уже сказано выше, предназначен 
//    для передачи дополнительных параметров макросу WPP_LOG_ALWAYS. Среди 
//    указанных параметров должен быть уровень трассировки, используемый 
//    в отладчике. 
// 3) Макрос WPP_TRACELEVEL_<XXX>_PRE предназначен для выполнения 
//    дополнительных предварительных действий до непосредственного момента 
//    трассировки. 
// 4) Макрос WPP_TRACELEVEL_<XXX>_ENABLED проверяет необходимость 
//    выполнения трассировки (например, соответствие уровня трассировки 
//    используемому уровню трассировки в сеансе). 
// 5) Макрос WPP_INVOKE_WPP_DEBUG выполняется только отладочном режиме 
//    непосредственно перед трассировкой, принимает в качестве параметров 
//    строку форматирования и ее аргументы и определяется через макрос 
//    WPP_DEBUG. Если макрос WPP_DEBUG не определен, то макрос 
//    WPP_INVOKE_WPP_DEBUG ничего не выполняет. 
// 6) Функция WPP_SF_<SIG> является оберточной функцией для макроса 
//    трассировки WPP_TRACE, который непосредственно и выполняет 
//    трассировку параметров. По умолчанию в режиме пользователя
//    макрос WPP_TRACE раскрывается в вызов функции TraceMessage. 
// 7) Макрос WPP_TRACELEVEL_<XXX>_POST предназначен для выполнения 
//    дополнительных завершающих действий. 
///////////////////////////////////////////////////////////////////////////////
// Замечания к реализации. 
///////////////////////////////////////////////////////////////////////////////
// 1) Поскольку строка форматирования и ее аргументы во всех версиях продукта
//    (Debug и Release) передаются только макросу WPP_LOG_ALWAYS, то 
//    вывод в отладчик отфоматированной строки может быть только при 
//    выполнении макроса WPP_LOG_ALWAYS (вариант сохранения параметров 
//    в макросе WPP_LOG_ALWAYS не рассматривается, поскольку для такой 
//    реализации потребуется шаблонный класс с переменным числом параметров, 
//    что не поддерживается в старых версиях Visual Studio, например, 2008). 
// 2) Поскольку при проверке отсутствия ошибок среди аргументов функции 
//    форматирования присутствует аргумент признака (кода) ошибки, который 
//    может раскрываться в вызов функции, то макрос WPP_LOG_ALWAYS должен 
//    сохранить его во временной переменной для последующего использования 
//    указанной временной переменной, а не повторного раскрытия макроса, 
//    приводящего к новому вызову функции. 
// 3) Для проверки необходимости вывода отформатированного сообщения в 
//    отладчик макросу WPP_LOG_ALWAYS должна передаваться функция или 
//    другой макрос проверки допустимости вывода (например, макрос
//    WPP_TRACELEVEL_<XXX>_ENABLED). В текущей реализации это выполняется 
//    передачей макросу WPP_LOG_ALWAYS адреса функции проверки допустимости, 
//    которая будет однократно вызвана внутри макроса WPP_LOG_ALWAYS.
// 4) Объединяя п.1)-3), макрос WPP_EX_TRACELEVEL_<XXX> должен передать 
//    макросу WPP_LOG_ALWAYS как минимум 4 параметра: 
//    a) тип переменной, в которой должен сохраняться однократно 
//       вычисляемый аргумент (код или признак ошибки); 
//    b) значение однократно вычисляемого аргумента; 
//    с) имя функции, проверяющей допустимость вывода; 
//    d) уровень трассировки, выполняемой отладчиком. 
// 5) Если в качестве результата макроса WPP_EX_TRACELEVEL_<XXX> указать 
//    упомянутые параметры через запятую без дополнительных разделителей, 
//    то компилятор Microsoft ошибочно (не в соответствии со стандартом) 
//    не "распакует" результат в последовательные параметры макроса 
//    WPP_LOG_ALWAYS, а в "упакованном" виде весь результат (т.е. все 
//    параметры) передаcт на место первого параметра макроса. Поэтому 
//    для возможности использования указанных параметров применяется 
//    следующий совместимый со стандартом метод: 
//    a) макрос WPP_EX_TRACELEVEL_<XXX> возвращает указанные параметры в 
//       круглых скобках (что дополнительно наглядно группирует параметры); 
//    b) определяются 4 макросные функции извлечения параметров: 
//       #define WPP_LOG_EXTRACT_TYPE( TYPE, VALUE, CHECK, LEVEL) TYPE
//       #define WPP_LOG_EXTRACT_VALUE(TYPE, VALUE, CHECK, LEVEL) VALUE
//       #define WPP_LOG_EXTRACT_CHECK(TYPE, VALUE, CHECK, LEVEL) CHECK
//       #define WPP_LOG_EXTRACT_LEVEL(TYPE, VALUE, CHECK, LEVEL) LEVEL 
//    c) указанные макросные функции вставляются в макрос WPP_LOG_ALWAYS 
//       без скобок (чтобы избежать преждевременного раскрытия). Скобки же 
//       подставляются при подстановке результата макроса 
//       WPP_EX_TRACELEVEL_<XXX>. 
///////////////////////////////////////////////////////////////////////////////
#if !defined WPP_CONTROL_GUIDS 
#ifdef WPP_DEBUG
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) WPP_DEBUG(MsgArgs)
#else
#define WPP_INVOKE_WPP_DEBUG(MsgArgs) (void)0
#endif
#endif

// извлечение отдельных параметров 
#define WPP_LOG_EXTRACT_TYPE( TYPE, VALUE, CHECK, LEVEL)    TYPE
#define WPP_LOG_EXTRACT_VALUE(TYPE, VALUE, CHECK, LEVEL)    VALUE
#define WPP_LOG_EXTRACT_CHECK(TYPE, VALUE, CHECK, LEVEL)    CHECK
#define WPP_LOG_EXTRACT_LEVEL(TYPE, VALUE, CHECK, LEVEL)    LEVEL

// вывод в отладчик
#define WPP_LOG_ALWAYS(ARGS, ...)                {      \
    WPP_LOG_EXTRACT_TYPE ARGS WPP_VAR(__LINE__) =       \
        WPP_LOG_EXTRACT_VALUE ARGS;                     \
    if (WPP_LOG_EXTRACT_CHECK ARGS(WPP_VAR(__LINE__)))  \
    WppDebugPrint(										\
        WPP_LOG_EXTRACT_LEVEL ARGS,                  	\
        __FILE__, __LINE__, __FUNC__,                	\
        __VA_ARGS__                                     \
    ); 

///////////////////////////////////////////////////////////////////////////////
// Переопределение функции трассировки для предотвращения изменения кода 
// последней ошибки в системе (что происходило в старых версиях функции 
// TraceMessage)
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS && !defined _NTDDK_
inline DWORD WppTraceMessage(
    IN TRACEHANDLE hLogger, IN ULONG messageFlags, 
    IN LPCGUID messageGuid, IN USHORT messageNumber, ...)
{
    // сохранить код последней ошибки
    DWORD lastError = ::GetLastError();

    // перейти на переменное число аргументов
    va_list args; va_start(args, messageNumber);

    // выполнить стандартную функцию трассировки
    DWORD code = CallTraceMessageVa(
        hLogger, messageFlags, messageGuid, messageNumber, args
    );
    // восстановить код ошибки
    va_end(args); ::SetLastError(lastError); return code; 
}
// функции трассировки и обработки событий 
#define WPP_REGISTER_TRACE_GUIDS    WppRegisterTraceGuids
#define WPP_UNREGISTER_TRACE_GUIDS  WppUnregisterTraceGuids
#define WPP_PRIVATE_ENABLE_CALLBACK WppNotificationCallback
#define WPP_TRACE                   WppTraceMessage
#endif 

///////////////////////////////////////////////////////////////////////////////
// Основная трассировка выполняется через функцию ATRACE(TRACELEVEL, MSG, ...), 
// второй параметр которой (строка форматирования) должен быть известен на 
// этапе компиляции. 
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC ATRACE(TRACELEVEL, MSG, ...);
// end_wpp

inline bool wpp_dummy(int) { return true; }

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL(LEVEL)            (int, 0, wpp_dummy, LEVEL)

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_PRE(LEVEL)           (void)WPP_VAR(__LINE__);

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_POST(LEVEL)          ;}

#ifdef WPP_CONTROL_GUIDS

// Описатель сеанса трассировки
#define WPP_TRACELEVEL_LOGGER(LEVEL)        WppGetLogger(),

// Проверка допустимости трассировки для указанного уровня
#define WPP_TRACELEVEL_ENABLED(LEVEL)       (WppGetControl()->Level >= LEVEL)

#else 

// Проверка допустимости трассировки
#define WPP_TRACELEVEL_ENABLED(LEVEL)       (1) 

// Вывод трассировки
#define ATRACE(LEVEL, ...)                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL(LEVEL), __VA_ARGS__)      \
    WPP_TRACELEVEL_PRE(LEVEL)                                  \
    (void)((                                                   \
        WPP_TRACELEVEL_ENABLED(LEVEL)                          \
        ? WPP_INVOKE_WPP_DEBUG((__VA_ARGS__)), 1 : 0           \
    ))                                                         \
    WPP_TRACELEVEL_POST(LEVEL)                                       
#endif 

///////////////////////////////////////////////////////////////////////////////
// Передача строкового представления класса с функцией name()
///////////////////////////////////////////////////////////////////////////////
#define WPP_LOG_CPPNAME(x)     WPP_LOGPAIR((x).name().length() + 1, (x).name().c_str())

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок POSIX
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(POSIX, WPP_LOG_CPPNAME, const posix_error&, ItemString, "s", posix , 0);
// FUNC AE_CHECK_POSIX{TRACELEVEL=TRACE_LEVEL_ERROR}(POSIX);
// USESUFFIX(AE_CHECK_POSIX, "ERROR %!POSIX!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_POSIX(LEVEL, ERRNO)       	(int, ERRNO, is_posix_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_POSIX_PRE(LEVEL, ERRNO)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)   	                \
    is_posix_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_POSIX_RAISE(FILE, LINE)                          \
    posix_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// Проверка наличия ошибки
#define WPP_TRACELEVEL_POSIX_POST(LEVEL, ERRNO)                         \
    ; if (WPP_TRACELEVEL_POSIX_ENABLED(LEVEL, ERRNO)) {                 \
         WPP_TRACELEVEL_POSIX_RAISE(__FILE__, __LINE__)                 \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_POSIX_LOGGER(LEVEL, ERRNO)   	WppGetLogger(),
#else 
#define AE_CHECK_POSIX(ERRNO)                                                                     		    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_POSIX(TRACE_LEVEL_ERROR, ERRNO), "ERROR %!POSIX!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_POSIX_PRE(TRACE_LEVEL_ERROR, ERRNO)                                            		    \
    (void)((                                                                                                \
        WPP_TRACELEVEL_POSIX_ENABLED(TRACE_LEVEL_ERROR, ERRNO)                                    		    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!POSIX!", WPP_VAR(__LINE__))), 1 : 0                                \
    ))                                                                                            		    \
    WPP_TRACELEVEL_POSIX_POST(TRACE_LEVEL_ERROR, ERRNO)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок NTSTATUS
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_NTSTATUS{TRACELEVEL=TRACE_LEVEL_ERROR}(NTSTATUS);
// USESUFFIX(AE_CHECK_NTSTATUS, "ERROR %!STATUS!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_NTSTATUS(LEVEL, STATUS)        (NTSTATUS, STATUS, is_native_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_NTSTATUS_PRE(LEVEL, STATUS)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)                      \
    is_native_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_exception(native_error(WPP_VAR(LINE)), FILE, LINE).trace();     \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        native_error(WPP_VAR(LINE)).value()                 		        \
    );  
#else
#define WPP_TRACELEVEL_NTSTATUS_RAISE(FILE, LINE)                           \
    windows_exception(native_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// Проверка наличия ошибки
#define WPP_TRACELEVEL_NTSTATUS_POST(LEVEL, STATUS)                         \
    ; if (WPP_TRACELEVEL_NTSTATUS_ENABLED(LEVEL, STATUS)) {                 \
         WPP_TRACELEVEL_NTSTATUS_RAISE(__FILE__, __LINE__)                  \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_NTSTATUS_LOGGER(LEVEL, STATUS)    WppGetLogger(),
#else 
#define AE_CHECK_NTSTATUS(STATUS)                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_NTSTATUS(TRACE_LEVEL_ERROR, STATUS), "ERROR %!STATUS!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_NTSTATUS_PRE(TRACE_LEVEL_ERROR, STATUS)                                                       \
    (void)((                                                                                                     \
        WPP_TRACELEVEL_NTSTATUS_ENABLED(TRACE_LEVEL_ERROR, STATUS)                                               \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!STATUS!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                                           \
    WPP_TRACELEVEL_NTSTATUS_POST(TRACE_LEVEL_ERROR, STATUS)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок HRESULT
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_HRESULT{TRACELEVEL=TRACE_LEVEL_ERROR}(HRESULT);
// USESUFFIX(AE_CHECK_HRESULT, "ERROR %!HRESULT!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)        		(HRESULT, HR, is_hresult_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)   		                \
    is_hresult_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_exception(hresult_error(WPP_VAR(LINE)), FILE, LINE).trace();    \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_HRESULT_RAISE(FILE, LINE)                            \
    windows_exception(hresult_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// Проверка наличия ошибки
#define WPP_TRACELEVEL_HRESULT_POST(LEVEL, HR)                              \
    ; if (WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)) {                      \
         WPP_TRACELEVEL_HRESULT_RAISE(__FILE__, __LINE__)                   \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL, HR)    		WppGetLogger(),
#else 
#define AE_CHECK_HRESULT(HR)                                                                                  \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_HRESULT(TRACE_LEVEL_ERROR, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))   \
    WPP_TRACELEVEL_HRESULT_PRE(TRACE_LEVEL_ERROR, HR)                                                         \
    (void)((                                                                                                  \
        WPP_TRACELEVEL_HRESULT_ENABLED(TRACE_LEVEL_ERROR, HR)                                                 \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                \
    ))                                                                                                        \
    WPP_TRACELEVEL_HRESULT_POST(TRACE_LEVEL_ERROR, HR)                                  
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок Windows 
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINERROR{TRACELEVEL=TRACE_LEVEL_ERROR}(WINERROR);
// USESUFFIX(AE_CHECK_WINERROR, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINERROR(LEVEL, ERROR)        (DWORD, ERROR, is_windows_error, LEVEL)

// Сохранение кода ошибки
#define WPP_TRACELEVEL_WINERROR_PRE(LEVEL, ERROR)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)                       \
    is_windows_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_exception(windows_error(WPP_VAR(LINE)), FILE, LINE).trace();    \
    throw gcnew System::ComponentModel::Win32Exception(                     \
        HRESULT_FROM_WIN32(WPP_VAR(LINE))                                   \
    );
#else
#define WPP_TRACELEVEL_WINERROR_RAISE(FILE, LINE)                           \
    windows_exception(windows_error(WPP_VAR(LINE)), FILE, LINE).raise();
#endif 

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINERROR_POST(LEVEL, ERROR)                          \
    ; if (WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)) {                  \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINERROR_LOGGER(LEVEL, ERROR)    WppGetLogger(),
#else 
#define AE_CHECK_WINERROR(ERROR)                                                                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINERROR(TRACE_LEVEL_ERROR, ERROR), "ERROR %!WINERROR!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_WINERROR_PRE(TRACE_LEVEL_ERROR, ERROR)                                                            \
    (void)((                                                                                                         \
        WPP_TRACELEVEL_WINERROR_ENABLED(TRACE_LEVEL_ERROR, ERROR)                                                    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                      \
    ))                                                                                                               \
    WPP_TRACELEVEL_WINERROR_POST(TRACE_LEVEL_ERROR, ERROR)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок WinAPI
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINAPI{TRACELEVEL=TRACE_LEVEL_ERROR}(WINAPI);
// USESUFFIX(AE_CHECK_WINAPI, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINAPI(LEVEL, RET)            (DWORD, (RET) ? ERROR_SUCCESS : ::GetLastError(), is_windows_error, LEVEL)

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_WINAPI_PRE(LEVEL, RET)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)                           \
    is_windows_error(WPP_VAR(__LINE__))

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINAPI_POST(LEVEL, RET)                              \
    ; if (WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)) {                      \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINAPI_LOGGER(LEVEL, RET)        WppGetLogger(),
#else 
#define AE_CHECK_WINAPI(RET)                                                                                     \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINAPI(TRACE_LEVEL_ERROR, RET), "ERROR %!WINERROR!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_WINAPI_PRE(TRACE_LEVEL_ERROR, RET)                                                            \
    (void)((                                                                                                     \
        WPP_TRACELEVEL_WINAPI_ENABLED(TRACE_LEVEL_ERROR, RET)                                                    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__))), 1 : 0                                  \
    ))                                                                                                           \
    WPP_TRACELEVEL_WINAPI_POST(TRACE_LEVEL_ERROR, RET)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок WinSock
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_WINSOCK{TRACELEVEL=TRACE_LEVEL_ERROR}(WINSOCK);
// USESUFFIX(AE_CHECK_WINSOCK, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_WINSOCK(LEVEL, CODE)            (DWORD, ((CODE) >= 0) ? ERROR_SUCCESS : ::WSAGetLastError(), is_windows_error, LEVEL)

// Отсутствие дополнительных действий
#define WPP_TRACELEVEL_WINSOCK_PRE(LEVEL, CODE)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, CODE)                         \
    is_windows_error(WPP_VAR(__LINE__))

// Проверка наличия ошибки
#define WPP_TRACELEVEL_WINSOCK_POST(LEVEL, CODE)                            \
    ; if (WPP_TRACELEVEL_WINSOCK_ENABLED(LEVEL, CODE)) {                    \
         WPP_TRACELEVEL_WINERROR_RAISE(__FILE__, __LINE__)                  \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_WINSOCK_LOGGER(LEVEL, CODE)        WppGetLogger(),
#else 
#define AE_CHECK_WINSOCK(CODE)                                                                                 	\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_WINSOCK(TRACE_LEVEL_ERROR, CODE), "ERROR %!WINERROR!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_WINSOCK_PRE(TRACE_LEVEL_ERROR, CODE)                                                         \
    (void)((                                                                                                    \
        WPP_TRACELEVEL_WINSOCK_ENABLED(TRACE_LEVEL_ERROR, CODE)                                                 \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!WINERROR!", WPP_VAR(__LINE__)), 1 : 0                                	\
    ))                                                                                                          \
    WPP_TRACELEVEL_WINSOCK_POST(TRACE_LEVEL_ERROR, CODE)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка системных ошибок 
// (признака завершения для WinAPI и кода завершения для POSIX)
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_SYSAPI{TRACELEVEL=TRACE_LEVEL_ERROR}(SYSAPI);
// USESUFFIX(AE_CHECK_SYSAPI, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

#if defined WPP_CONTROL_GUIDS

// Описатель сеанса трассировки
#define WPP_TRACELEVEL_SYSAPI_LOGGER(LEVEL, RET)    WPP_TRACELEVEL_WINAPI_LOGGER(LEVEL, RET)

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_SYSAPI(LEVEL, RET)        WPP_EX_TRACELEVEL_WINAPI(LEVEL, RET)

// Сохранение кода ошибки
#define WPP_TRACELEVEL_SYSAPI_PRE(LEVEL, RET)       WPP_TRACELEVEL_WINAPI_PRE(LEVEL, RET)

// Проверка наличия трассировки
#define WPP_TRACELEVEL_SYSAPI_ENABLED(LEVEL, RET)   WPP_TRACELEVEL_WINAPI_ENABLED(LEVEL, RET)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_SYSAPI_POST(LEVEL, RET)      WPP_TRACELEVEL_WINAPI_POST(LEVEL, RET)

#elif defined _WIN32
#define AE_CHECK_SYSAPI(RET)    AE_CHECK_WINAPI(RET)
#else 
#define AE_CHECK_SYSAPI(CODE)   AE_CHECK_POSIX(CODE)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка обобщенных ошибок 
// (с указанием кода для Windows и кода для POSIX)
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_RAISE_GENERIC{TRACELEVEL=TRACE_LEVEL_ERROR}(POSIX, WINERROR);
// USESUFFIX(AE_RAISE_GENERIC, "ERROR %!WINERROR!", WPP_VAR(__LINE__));
// end_wpp

#if defined WPP_CONTROL_GUIDS

// Описатель сеанса трассировки
#define WPP_TRACELEVEL_POSIX_WINERROR_LOGGER(LEVEL, ERRNO, ERROR)    WPP_TRACELEVEL_WINERROR_LOGGER(LEVEL, ERROR)

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_POSIX_WINERROR(LEVEL, ERRNO, ERROR)        WPP_EX_TRACELEVEL_WINERROR(LEVEL, ERROR)

// Сохранение кода ошибки
#define WPP_TRACELEVEL_POSIX_WINERROR_PRE(LEVEL, ERRNO, ERROR)       WPP_TRACELEVEL_WINERROR_PRE(LEVEL, ERROR)

// Проверка наличия трассировки
#define WPP_TRACELEVEL_POSIX_WINERROR_ENABLED(LEVEL, ERRNO, ERROR)   WPP_TRACELEVEL_WINERROR_ENABLED(LEVEL, ERROR)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_POSIX_WINERROR_POST(LEVEL, ERRNO, ERROR)      WPP_TRACELEVEL_WINERROR_POST(LEVEL, ERROR)

#elif defined _WIN32
#define AE_RAISE_GENERIC(ERRNO, ERROR)   AE_CHECK_WINERROR(ERROR)
#else 
#define AE_RAISE_GENERIC(ERRNO, ERROR)   AE_CHECK_POSIX(ERRNO)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок COM
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// FUNC AE_CHECK_COM{TRACELEVEL=TRACE_LEVEL_ERROR}(OBJ, IID, HRESULT);
// USESUFFIX(AE_CHECK_COM, "ERROR %!HRESULT!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(LEVEL, OBJ, IID, HR)        WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(LEVEL, OBJ, IID, HR)       WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)

// Проверка наличия трассировки
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)   WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)

// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)                  \
    com_exception(OBJ, IID, WPP_VAR(LINE), FILE, LINE).trace();                     \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)                  \
    com_exception(OBJ, IID, WPP_VAR(LINE), FILE, LINE).raise();
#endif 

// Проверка наличия ошибки
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(LEVEL, OBJ, IID, HR)                    \
    ; if (WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)) {            \
         WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, __FILE__, __LINE__)         \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_LOGGER(LEVEL, OBJ, IID, HR)    WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL, HR)
#else 
#define AE_CHECK_COM(OBJ, IID, HR)                                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(TRACE_LEVEL_ERROR, OBJ, IID, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                           \
    (void)((                                                                                                                      \
        WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                   \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                                    \
    ))                                                                                                                            \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                  
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок PKCS11
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(PKCS11, WPP_LOG_CPPNAME, const pkcs11_error&, ItemString, "s", pkcs11, 0);
// FUNC AE_CHECK_PKCS11{TRACELEVEL=TRACE_LEVEL_ERROR}(PKCS11);
// USESUFFIX(AE_CHECK_PKCS11, "ERROR %!PKCS11!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_PKCS11(LEVEL, CODE)       	(CK_ULONG, CODE, is_pkcs11_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_PKCS11_PRE(LEVEL, CODE)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)   	                    \
    is_pkcs11_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)    	                        \
    pkcs11_exception(WPP_VAR(LINE), FILE, LINE).trace();                    \
    throw gcnew Aladdin::PKCS11::Exception(WPP_VAR(LINE));
#else 
#define WPP_TRACELEVEL_PKCS11_RAISE(FILE, LINE)           	                \
    pkcs11_exception(WPP_VAR(LINE), FILE, LINE).raise();    
#endif 

// Проверка наличия ошибки
#define WPP_TRACELEVEL_PKCS11_POST(LEVEL, CODE)                             \
    ; if (WPP_TRACELEVEL_PKCS11_ENABLED(LEVEL, CODE)) {                     \
         WPP_TRACELEVEL_PKCS11_RAISE(__FILE__, __LINE__)                    \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_PKCS11_LOGGER(LEVEL, CODE)   	WppGetLogger(),
#else 
#define AE_CHECK_PKCS11(CODE)                                                               			    	\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_PKCS11(TRACE_LEVEL_ERROR, CODE), "ERROR %!PKCS11!", WPP_VAR(__LINE__))   	\
    WPP_TRACELEVEL_PKCS11_PRE(TRACE_LEVEL_ERROR, CODE)                               	            			\
    (void)((                                                                                      			    \
        WPP_TRACELEVEL_PKCS11_ENABLED(TRACE_LEVEL_ERROR, CODE)                       	            			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!PKCS11!", WPP_VAR(__LINE__))), 1 : 0                                	\
    ))                                                                                      					\
    WPP_TRACELEVEL_PKCS11_POST(TRACE_LEVEL_ERROR, CODE)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок OpenSSL
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(OPENSSL, WPP_LOG_CPPNAME, const openssl_error&, ItemString, "s", openssl, 0);
// FUNC AE_CHECK_OPENSSL{TRACELEVEL=TRACE_LEVEL_ERROR}(OPENSSL);
// USESUFFIX(AE_CHECK_OPENSSL, "ERROR %!OPENSSL!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_OPENSSL(LEVEL, RET)       	(unsigned long, (RET) ? 0 : ERR_get_error(), is_openssl_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_OPENSSL_PRE(LEVEL, RET)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)   	                    \
    is_openssl_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_OPENSSL_RAISE(FILE, LINE)                            \
    openssl_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// Проверка наличия ошибки
#define WPP_TRACELEVEL_OPENSSL_POST(LEVEL, RET)                             \
    ; if (WPP_TRACELEVEL_OPENSSL_ENABLED(LEVEL, RET)) {                     \
         WPP_TRACELEVEL_OPENSSL_RAISE(__FILE__, __LINE__)                   \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OPENSSL_LOGGER(LEVEL, RET)   	WppGetLogger(),
#else 
#define AE_CHECK_OPENSSL(RET)                                                                     		        \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OPENSSL(TRACE_LEVEL_ERROR, RET), "ERROR %!OPENSSL!", WPP_VAR(__LINE__))    \
    WPP_TRACELEVEL_OPENSSL_PRE(TRACE_LEVEL_ERROR, RET)                                            		        \
    (void)((                                                                                                    \
        WPP_TRACELEVEL_OPENSSL_ENABLED(TRACE_LEVEL_ERROR, RET)                                    		        \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!OPENSSL!", WPP_VAR(__LINE__))), 1 : 0                                  \
    ))                                                                                            		        \
    WPP_TRACELEVEL_OPENSSL_POST(TRACE_LEVEL_ERROR, RET)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок ODBC
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(ODBC, WPP_LOG_CPPNAME, const odbc_error&, ItemString, "s", odbc, 0);
// FUNC AE_CHECK_ODBC{TRACELEVEL=TRACE_LEVEL_ERROR}(CAT, HANDLE, TYPE, ODBC);
// USESUFFIX(AE_CHECK_ODBC, "ERROR %!ODBC!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_CAT_HANDLE_TYPE_ODBC(LEVEL, CAT, HANDLE, TYPE, ODBC)       	(odbc_error, odbc_error(CAT, ODBC), is_odbc_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_PRE(LEVEL, CAT, HANDLE, TYPE, ODBC)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(LEVEL, CAT, HANDLE, TYPE, ODBC)   	        \
    is_odbc_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_RAISE(HANDLE, TYPE, FILE, LINE)    	                \
    odbc_exception(WPP_VAR(LINE), HANDLE, TYPE, FILE, LINE).raise();    

// Проверка наличия ошибки
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_POST(LEVEL, CAT, HANDLE, TYPE, ODBC)                \
    ; if (WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(LEVEL, CAT, HANDLE, TYPE, ODBC)) {        \
         WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_RAISE(HANDLE, TYPE, __FILE__, __LINE__)            \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_LOGGER(LEVEL, CAT, HANDLE, TYPE, ODBC)   	WppGetLogger(),
#else 
#define AE_CHECK_ODBC(CAT, HANDLE, TYPE, ODBC)                                                               			            		\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_CAT_HANDLE_TYPE_ODBC(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC), "ERROR %!ODBC!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_PRE(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                               	            		\
    (void)((                                                                                      							            	\
        WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_ENABLED(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                       	            		\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!ODBC!", WPP_VAR(__LINE__))), 1 : 0                                									\
    ))                                                                                      							            		\
    WPP_TRACELEVEL_CAT_HANDLE_TYPE_ODBC_POST(TRACE_LEVEL_ERROR, CAT, HANDLE, TYPE, ODBC)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок OCI
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(OCI, WPP_LOG_CPPNAME, const oci_error&, ItemString, "s", oci, 0);
// FUNC AE_CHECK_OCI{TRACELEVEL=TRACE_LEVEL_ERROR}(CAT, OCI, ERROR);
// USESUFFIX(AE_CHECK_OCI, "ERROR %!OCI!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_CAT_OCI_ERROR(LEVEL, CAT, OCI, ERROR)       	(oci_error, oci_error(CAT, OCI), is_oci_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_CAT_OCI_ERROR_PRE(LEVEL, CAT, OCI, ERROR)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(LEVEL, CAT, OCI, ERROR)        \
    is_oci_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_CAT_OCI_ERROR_RAISE(ERROR, FILE, LINE)    	        \
    oci_exception(WPP_VAR(LINE), ERROR, FILE, LINE).raise();

// Проверка наличия ошибки
#define WPP_TRACELEVEL_CAT_OCI_ERROR_POST(LEVEL, CAT, OCI, ERROR)           \
    ; if (WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(LEVEL, CAT, OCI, ERROR)) {   \
         WPP_TRACELEVEL_CAT_OCI_ERROR_RAISE(ERROR, __FILE__, __LINE__)  	\
    }}
// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_CAT_OCI_ERROR_LOGGER(LEVEL, CAT, OCI, ERROR)   	WppGetLogger(),
#else
#define AE_CHECK_OCI(CAT, OCI, ERROR)                                                                           			\
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_CAT_OCI_ERROR(TRACE_LEVEL_ERROR, CAT, OCI, ERROR), "ERROR %!OCI!", WPP_VAR(__LINE__))  \
    WPP_TRACELEVEL_CAT_OCI_ERROR_PRE(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                               	        			\
    (void)((                                                                                                          		\
        WPP_TRACELEVEL_CAT_OCI_ERROR_ENABLED(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                       	        			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!OCI!", WPP_VAR(__LINE__))), 1 : 0                                		            \
    ))                                                                                                          			\
    WPP_TRACELEVEL_CAT_OCI_ERROR_POST(TRACE_LEVEL_ERROR, CAT, OCI, ERROR)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок LIBPQ
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(LIBPQ, WPP_LOG_CPPNAME, const libpq_error&, ItemString, "s", libpq, 0);
// FUNC AE_CHECK_LIBPQ{TRACELEVEL=TRACE_LEVEL_ERROR}(LIBPQ);
// USESUFFIX(AE_CHECK_LIBPQ, "ERROR %!LIBPQ!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_LIBPQ(LEVEL, RESULT)        (PGresult*, RESULT, is_libpq_error, LEVEL)

// Сохранение кода ошибки
#define WPP_TRACELEVEL_LIBPQ_PRE(LEVEL, RESULT)       

// Проверка наличия трассировки
#define WPP_TRACELEVEL_LIBPQ_ENABLED(LEVEL, RESULT)                     \
    is_libpq_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_LIBPQ_RAISE(FILE, LINE)                          \
    libpq_exception(WPP_VAR(LINE), FILE, LINE).raise();

// Проверка наличия ошибки
#define WPP_TRACELEVEL_LIBPQ_POST(LEVEL, RESULT)                        \
    ; if (WPP_TRACELEVEL_LIBPQ_ENABLED(LEVEL, RESULT)) {                \
         WPP_TRACELEVEL_LIBPQ_RAISE(__FILE__, __LINE__)                 \
    }}
// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_LIBPQ_LOGGER(LEVEL, RESULT)    WppGetLogger(),
#else 
#define AE_CHECK_LIBPQ(RESULT)                                                                          	    \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_LIBPQ(TRACE_LEVEL_ERROR, RESULT), "ERROR %!LIBPQ!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_LIBPQ_PRE(TRACE_LEVEL_ERROR, RESULT)                                               		    \
    (void)((                                                                                                  	\
        WPP_TRACELEVEL_LIBPQ_ENABLED(TRACE_LEVEL_ERROR, RESULT)                                         	    \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!LIBPQ!", WPP_VAR(__LINE__))), 1 : 0                                    \
    ))                                                                                                  	    \
    WPP_TRACELEVEL_LIBPQ_POST(TRACE_LEVEL_ERROR, RESULT)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок Python
///////////////////////////////////////////////////////////////////////////////
// begin_wpp config
// DEFINE_CPLX_TYPE(PYTHON, WPP_LOG_CPPNAME, const python_error&, ItemString, "s", python, 0);
// FUNC AE_CHECK_PYTHON{TRACELEVEL=TRACE_LEVEL_ERROR}(PYTHON);
// USESUFFIX(AE_CHECK_PYTHON, "ERROR %!PYTHON!", WPP_VAR(__LINE__));
// end_wpp

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_PYTHON(LEVEL, CAT)       	    (python_error, CAT, is_python_error, LEVEL)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_PYTHON_PRE(LEVEL, CAT)      

// Проверка наличия трассировки
#define WPP_TRACELEVEL_PYTHON_ENABLED(LEVEL, CAT)   	                \
    is_python_error(WPP_VAR(__LINE__))

// Возбуждение исключения
#define WPP_TRACELEVEL_PYTHON_RAISE(FILE, LINE)    	                    \
    python_exception(WPP_VAR(LINE), FILE, LINE).raise();    

// Проверка наличия ошибки
#define WPP_TRACELEVEL_PYTHON_POST(LEVEL, CAT)                          \
    ; if (WPP_TRACELEVEL_PYTHON_ENABLED(LEVEL, CAT)) {                  \
         WPP_TRACELEVEL_PYTHON_RAISE(__FILE__, __LINE__)	            \
    }}
// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_PYTHON_LOGGER(LEVEL, CAT)   	WppGetLogger(),
#else 
#define AE_CHECK_PYTHON(CAT)                                                               			            \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_PYTHON(TRACE_LEVEL_ERROR, CAT), "ERROR %!PYTHON!", WPP_VAR(__LINE__))  	\
    WPP_TRACELEVEL_PYTHON_PRE(TRACE_LEVEL_ERROR, CAT)                               	            			\
    (void)((                                                                                      			    \
        WPP_TRACELEVEL_PYTHON_ENABLED(TRACE_LEVEL_ERROR, CAT)                       	            			\
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!PYTHON!", WPP_VAR(__LINE__))), 1 : 0                                	\
    ))                                                                                      					\
    WPP_TRACELEVEL_PYTHON_POST(TRACE_LEVEL_ERROR, CAT)                                      
#endif 

///////////////////////////////////////////////////////////////////////////////
// Стандартные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (77921413, 5345, 4626, B028, C3AFB9DCBF05)
#if defined _NTDDK_
#include "TraceDriver.h"
#else 
#include "TraceUser.h"
#endif 
#else 
#if defined _NTDDK_
#define WPP_INIT_TRACING(pDriver, pRegPath) UNREFERENCED_PARAMETER(pRegPath)
#define WPP_CLEANUP(     pDriver)           UNREFERENCED_PARAMETER(pDriver) 
#else 
#define WPP_INIT_TRACING(Application)       ((void)0)
#define WPP_CLEANUP(                )       ((void)0)
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Найти описание провайдера трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
inline PWPP_TRACE_CONTROL_BLOCK WppGetControl(TRACEHANDLE hRegistrationHandle)
{
    // проверить наличие регистрации
    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB) return nullptr; 

    // перейти на блок первого компонента
    PWPP_TRACE_CONTROL_BLOCK pControl = &WPP_CB[0].Control;

    // для всех зарегистрированных компонентов
    for(; pControl; pControl = pControl->Next) 
    {
        // проверить наличие идентификатора
        if (!pControl->ControlGuid) continue; 
#if defined _NTDDK_
        // проверить совпадение идентификатора
        if (pControl->RegHandle == hRegistrationHandle) return pControl;
#else 
        // проверить совпадение идентификатора
        if (pControl->UmRegistrationHandle == hRegistrationHandle) return pControl;
#endif 
    }
    return nullptr; 
}

inline PWPP_TRACE_CONTROL_BLOCK WppGetControl(const GUID& componentGUID)
{
    // проверить наличие регистрации
    if (WPP_CB == (WPP_CB_TYPE*)&WPP_CB) return nullptr; 

    // перейти на блок первого компонента
    PWPP_TRACE_CONTROL_BLOCK pControl = &WPP_CB[0].Control;

    // для всех зарегистрированных компонентов
    for(; pControl; pControl = pControl->Next) 
    {
        // проверить наличие идентификатора
        if (!pControl->ControlGuid) continue; 

        // проверить совпадение идентификатора
        if (IsEqualGUID(*pControl->ControlGuid, componentGUID)) return pControl;
    }
    return nullptr; 
}

inline PWPP_TRACE_CONTROL_BLOCK WppGetControl()
{
    // указать идентификатор компонента
    GUID componentGUID = WPP_XGLUE4(WPP_, ThisDir, _CTLGUID_, WPP_EVAL(WPP_CONTROL_NAME)); 

    // найти блок компонента
    return WppGetControl(componentGUID); 
}

inline TRACEHANDLE WppGetLogger()
{
    // найти блок компонента
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(); 

#if !defined _NTDDK_
    // для специального случая
    if (pControl && pControl->Options == WPP_VER_WIN2K_CB_FORWARD_PTR)
    {
        // вернуть описатель сеанса
        if (pControl->Win2kCb) return pControl->Win2kCb->Logger; 
    }
    // для специального случая
    if (pControl && pControl->Options == WPP_VER_WHISTLER_CB_FORWARD_PTR)
    {
        // скорректировать блок компонента
        if (pControl->Cb) pControl = pControl->Cb; 
    }
#endif 
    // вернуть описатель сеанса
    return (pControl) ? pControl->Logger : 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Регистрация идентификаторов трассировки
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline ULONG WppRegisterTraceGuids(
    WMIDPREQUEST RequestAddress, PVOID RequestContext, 
    LPCGUID ControlGuid, ULONG GuidCount, PTRACE_GUID_REGISTRATION TraceGuidReg, 
    LPCWSTR MofImagePath, LPCWSTR MofResourceName, PTRACEHANDLE phRegistrationHandle)
{
    // вызвать базовую функцию
    ULONG ret = ::RegisterTraceGuidsW(RequestAddress, RequestContext, 
        ControlGuid, GuidCount, TraceGuidReg, 
        MofImagePath, MofResourceName, phRegistrationHandle
    ); 
    // проверить отсутствие ошибок
    if (ret != ERROR_SUCCESS) return ret; 

    // найти основной блок управления
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(*phRegistrationHandle); 

    // проверить корректность настроек
    if (!pControl || pControl->Options != 0) return ret; 

    // выделить память для дополнительного блока управления
    if (PWPP_TRACE_CONTROL_BLOCK pCB = new WPP_TRACE_CONTROL_BLOCK)
    {
        // выполнить инициализацию
        pCB->Options = 0; pCB->Logger = pControl->Logger; 

        // указать используемое перенаправление
        pControl->Options = WPP_VER_WHISTLER_CB_FORWARD_PTR; pControl->Cb = pCB; 

        // указать данные основного блока управления
        pCB->UmRegistrationHandle = pControl->UmRegistrationHandle; 

        // указать данные основного блока управления
        pCB->ControlGuid = ControlGuid; pCB->Level = pControl->Level; 
        
        // указать данные основного блока управления
        pCB->FlagsLen = pControl->FlagsLen; pCB->Flags[0] = pControl->Flags[0]; 

        // прочитать параметры трассировки
        trace::ControlParameters* pControlParameters = new(std::nothrow) trace::ControlParameters(); 

        // сохранить значения параметров трассировки
        pCB->Next = (PWPP_TRACE_CONTROL_BLOCK)pControlParameters; 
    }
    return ret; 
}

inline ULONG WppUnregisterTraceGuids(TRACEHANDLE hRegistrationHandle)
{
    // найти основной блок управления
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(hRegistrationHandle); 

    // проверить корректность настроек
    if (pControl && pControl->Options == WPP_VER_WHISTLER_CB_FORWARD_PTR) 
    {
        // получить адрес дополнительного блока
        if (PWPP_TRACE_CONTROL_BLOCK pCB = pControl->Cb)
        {        
            // восстановить исходные данные
            pControl->Options = 0; pControl->Logger = pCB->Logger; 

            // восстановить исходные данные
            pControl->UmRegistrationHandle = pCB->UmRegistrationHandle; 
            
            // восстановить исходные данные
            pControl->ControlGuid = pCB->ControlGuid; pControl->Level = pCB->Level; 

            // восстановить исходные данные
            pControl->FlagsLen = pCB->FlagsLen; pControl->Flags[0] = pCB->Flags[0];

            // освободить выделенную память
            if (pCB->Next) delete (trace::ControlParameters*)(pCB->Next); delete pCB; 
        }
    }
    // вызвать базовую функцию
    return ::UnregisterTraceGuids(hRegistrationHandle); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Обработка событий трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined _NTDDK_
inline void WppNotificationCallback(LPCGUID, TRACEHANDLE, BOOLEAN, ULONG, UCHAR) {}
#else 
inline void WppNotificationCallback(LPCGUID ControlGuid, 
    TRACEHANDLE hLogger, BOOLEAN enable, ULONG flags, UCHAR level) 
{
    // найти основной блок управления
    if (!enable) return; PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(*ControlGuid); 

    // проверить корректность настроек
    if (!pControl || pControl->Options != WPP_VER_WHISTLER_CB_FORWARD_PTR) return; 

    // получить адрес дополнительного блока
    if (PWPP_TRACE_CONTROL_BLOCK pCB = pControl->Cb)
    {
        // сохранить принятые данные
        pCB->Logger = hLogger; pCB->Level = level; pCB->Flags[0] = flags; 

        // обновить параметры трассировки
        ((trace::ControlParameters*)(pCB->Next))->Update(); 
    }
}
namespace trace {
inline const ControlParameters* GetControlParameters() 
{
    // найти блок компонента
    PWPP_TRACE_CONTROL_BLOCK pControl = WppGetControl(); if (!pControl) return nullptr; 
    
    // проверить наличие блока
    if (pControl->Options != WPP_VER_WHISTLER_CB_FORWARD_PTR || !pControl->Cb) return nullptr; 

    // выполнить преобразование типа
    return (const ControlParameters*)(pControl->Cb->Next); 
}
}
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
// Трассировка входа/выхода из функции. Функции класса не должны быть 
// встраиваемыми (inline) во избежание следующих проблем: 
// 1) неcоответствия принадлежности конструктора и деструктора класса 
// различным единицам трансляции и, следовательно, рассогласования при выводе 
// трассировки (различные значения __FILE__ и принадлежность номеров строк
// различным файлам); 
// 2) помещения в .TMF-файл для трассировочных сообщений Trace.h описания 
// сообщений, принадлежащих другим единицам трансляции (единицам трансляции, 
// в которые встраиваются вызовы конструктора и деструктора). 
///////////////////////////////////////////////////////////////////////////////
namespace trace { 
class scope { private: const char* szFunction; 

    // конструктор
    public: WPP_NOINLINE scope(const char* szFunc) : szFunction(szFunc)
    {
        // выполнить трассировку входа
        ATRACE(TRACE_LEVEL_VERBOSE, "--> %hs", szFunction);
    }
    // деструктор
    public: WPP_NOINLINE ~scope()
    {
        // выполнить трассировку выхода
        ATRACE(TRACE_LEVEL_VERBOSE, "<-- %hs", szFunction);
    }
};    
}
// встраивание трассировки стека
#define $ trace::scope WPP_VAR(__LINE__)(__FUNC__);

///////////////////////////////////////////////////////////////////////////////
// Трассировка строки фиксированного размера
///////////////////////////////////////////////////////////////////////////////
WPP_NOINLINE inline void WppTraceStringA(int level, const char* sz, size_t cch) 
{ 
    // определить размер строки
    if (!sz) { return; } if (cch == (size_t)(-1)) { cch = strlen(sz); } switch (level)
    {
    // вывести строку
    case TRACE_LEVEL_NONE       : ATRACE(TRACE_LEVEL_NONE       , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_CRITICAL   : ATRACE(TRACE_LEVEL_CRITICAL   , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_ERROR      : ATRACE(TRACE_LEVEL_ERROR      , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_WARNING    : ATRACE(TRACE_LEVEL_WARNING    , "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_INFORMATION: ATRACE(TRACE_LEVEL_INFORMATION, "%!.*hs!", trace::_str(sz, cch)); break;
    case TRACE_LEVEL_VERBOSE    : ATRACE(TRACE_LEVEL_VERBOSE    , "%!.*hs!", trace::_str(sz, cch)); break;
    }
}

WPP_NOINLINE inline void WppTraceStringW(int level, const wchar_t* sz, size_t cch) 
{ 
    // определить размер строки
    if (!sz) { return; } if (cch == (size_t)(-1)) { cch = wcslen(sz); } switch (level)
    {
    // вывести строку
    case TRACE_LEVEL_NONE       : ATRACE(TRACE_LEVEL_NONE       , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_CRITICAL   : ATRACE(TRACE_LEVEL_CRITICAL   , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_ERROR      : ATRACE(TRACE_LEVEL_ERROR      , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_WARNING    : ATRACE(TRACE_LEVEL_WARNING    , "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_INFORMATION: ATRACE(TRACE_LEVEL_INFORMATION, "%!.*ls!", trace::_wstr(sz, cch)); break;
    case TRACE_LEVEL_VERBOSE    : ATRACE(TRACE_LEVEL_VERBOSE    , "%!.*ls!", trace::_wstr(sz, cch)); break;
    }
}
inline void ATRACESTR(int level, const char   * sz, size_t cch = -1) { WppTraceStringA(level, sz, cch); }
inline void ATRACESTR(int level, const wchar_t* sz, size_t cch = -1) { WppTraceStringW(level, sz, cch); }

///////////////////////////////////////////////////////////////////////////////
// Выполнить трассировку содержимого буфера
///////////////////////////////////////////////////////////////////////////////
inline void ATRACEDUMP(int level, const void* pvBlock, size_t cbBlock)
{
    static const char DIGITS[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    // выполнить преобразование типа
    const unsigned char* pbBlock = (const unsigned char*)pvBlock; 

    // создать буфер требуемого размера
    char buffer[2 * sizeof(void*) + 2 + 64 + 1] = {0}; 

    // определить адрес для форматируемого значения
    char* szValue = buffer + 2 * sizeof(void*) + 2; 

    // для всех строк
    for (size_t i = 0; i < (cbBlock + 15) / 16; i++)
    {
        // вычислить базовый адрес
        const unsigned char* ptr = pbBlock + i * 16; memset(szValue, ' ', 64);

        // отформатировать адрес
        trace::snprintf_ptr(buffer, 2 * sizeof(void*) + 1, ptr); 

        // указать разделитель адреса и значения
        buffer[2 * sizeof(void*) + 0] = ':'; buffer[2 * sizeof(void*) + 1] = ' '; 

        // для всех байтов строки
        for (size_t j = 0; (j < 16) && (i * 16 + j < cbBlock); j++)
        {
            // извлечь отдельный байт
            unsigned char ch = ptr[j];

            // указать шестнадцатеричное представление
            szValue[j * 3 + 0] = DIGITS[ch / 16];
            szValue[j * 3 + 1] = DIGITS[ch % 16];

            // указать символьное представление
            szValue[48 + j] = (' ' <= ch && ch <= 127) ? ch : '.';
        }
        // выполнить трассировку
        ATRACESTR(level, buffer);
    }                                                                   
}

///////////////////////////////////////////////////////////////////////////////
// Выполнить многострочную трассировку ошибки
///////////////////////////////////////////////////////////////////////////////
inline void ATRACE_MULTILINE(int level, const char* szMessage)
{
    // для всех подстрок
    while (szMessage && *szMessage)
    {
        // найти завершение подстроки
        if (const char* szLast = strchr(szMessage, '\n')) 
        { 
            // указать позицию окончания вывода
            const char* szEnd = szLast; if (szLast != szMessage)
            {
                // указать позицию окончания вывода
                if (*(szLast - 1) == '\r') szEnd--; 
            }
            // вывести подстроку
            ATRACESTR(level, szMessage, szEnd - szMessage);

            // пропустить подстроку
            szMessage = szLast + 1; continue; 
        }
        // вывести оставшуюся строку
        ATRACESTR(level, szMessage); break; 
    }
}
inline void ATRACE_MULTILINE(int level, const wchar_t* szMessage)
{
    // для всех подстрок
    while (szMessage && *szMessage)
    {
        // найти завершение подстроки
        if (const wchar_t* szLast = wcschr(szMessage, L'\n')) 
        { 
            // указать позицию окончания вывода
            const wchar_t* szEnd = szLast; if (szLast != szMessage)
            {
                // указать позицию окончания вывода
                if (*(szLast - 1) == L'\r') szEnd--; 
            }
            // вывести подстроку
            ATRACESTR(level, szMessage, szEnd - szMessage);

            // пропустить подстроку
            szMessage = szLast + 1; continue; 
        }
        // вывести оставшуюся строку
        ATRACESTR(level, szMessage); break; 
    }
}

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение ошибок
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#include "TraceError.h"     // определение ошибок
#include "TracePosix.h"     // определение ошибок POSIX

#if defined _WIN32
#include "TraceWindows.h"   // определение ошибок Windows
#include "TraceCOM.h"       // определение ошибок COM
#endif 
#endif 
