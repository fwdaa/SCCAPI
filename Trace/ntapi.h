#pragma once
#if !defined _NTDDK_
#include <subauth.h>			
#endif 

///////////////////////////////////////////////////////////////////////////////
// Подключение требуемой библиотеки
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#pragma comment(lib, "ntdll.lib")
#endif 

///////////////////////////////////////////////////////////////////////////////
// Удаление избыточных предупреждений 
///////////////////////////////////////////////////////////////////////////////
#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

///////////////////////////////////////////////////////////////////////////////
// Псевдоописатели процесса и потока
///////////////////////////////////////////////////////////////////////////////
#ifndef NtCurrentProcess
#define NtCurrentProcess()	((HANDLE)(LONG_PTR)(-1))
#endif 

#ifndef NtCurrentThread
#define NtCurrentThread()	((HANDLE)(LONG_PTR)(-2))
#endif 

///////////////////////////////////////////////////////////////////////////////
// Обработка ошибок. Функция RtlNtStatusToDosError преобразует код ошибки 
// NTSTATUS в код ошибки Win32 (без указания подсистемы). При отсутствии 
// соответствия возвращается код ERROR_MR_MID_NOT_FOUND. 
///////////////////////////////////////////////////////////////////////////////

// признак отсутствия ошибок и предупреждений 
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)      (((NTSTATUS)(Status)) >= 0)
#endif

// признак наличия дополнительной информации 
#ifndef NT_INFORMATION
#define NT_INFORMATION(Status)  ((((ULONG)(Status)) >> 30) == 1)
#endif

// признак наличия предупреждения 
#ifndef NT_WARNING
#define NT_WARNING(Status)      ((((ULONG)(Status)) >> 30) == 2)
#endif

// признак наличия ошибки 
#ifndef NT_ERROR
#define NT_ERROR(Status)        ((((ULONG)(Status)) >> 30) == 3)
#endif

// преобразование кода NTSTATUS в код ошибки Win32
extern "C" NTSYSAPI ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);

///////////////////////////////////////////////////////////////////////////////
// Вспомогательные функции для замены CRT
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void RtlCopyBytes(void* pDest, const void* pSource, size_t cb)
{
	// скопировать данные
	for (size_t i = 0; i < cb; i++) ((char*)pDest)[i] = ((const char*)pSource)[i]; 
}
// обнулить данные
#define RtlZeroBytes RtlSecureZeroMemory
#endif 

///////////////////////////////////////////////////////////////////////////////
// Односвязный список. Функция PushEntryList добавляет элемент Entry в начало 
// списка с корнем ListHead. Функция PopEntryList удаляет первый элемент из 
// списка с корнем ListHead и возвращает удаленный элемент. 
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void PushEntryList(
    IN OUT PSINGLE_LIST_ENTRY ListHead, IN OUT PSINGLE_LIST_ENTRY Entry)
{
	// добавить элемент в начало списка
    Entry->Next = ListHead->Next; ListHead->Next = Entry; 
}

inline PSINGLE_LIST_ENTRY PopEntryList(IN OUT PSINGLE_LIST_ENTRY ListHead)
{
	// получить элемент из начала списка
    PSINGLE_LIST_ENTRY FirstEntry = ListHead->Next;

	// удалить первый элемент из списка 
    if (FirstEntry) ListHead->Next = FirstEntry->Next; return FirstEntry;
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Двусвязный список. Функция InitializeListHead инициализирует корень 
// ListHead списка. Функция IsListEmpty проверяет наличие элементов списка 
// с корнем ListHead. Функция InsertHeadList добавляет элемент Entry в начало 
// списка с корнем ListHead. Функция InsertTailList добавляет элемент Entry 
// в конец списка с корнем ListHead. Функция AppendTailList добавляет в конец 
// списка с корнем в ListHead все элементы второго безкорневого списка с 
// начальным элементом ListToAppend. Функция RemoveEntryList удаляет элемент
// Entry из списка, его содержащего. Функция RemoveHeadList удаляет первый 
// элемент из списка с корнем ListHead и возвращает удаленный элемент. Функция 
// RemoveTailList даляет последний элемент из списка с корнем ListHead и 
// возвращает удаленный элемент.
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void InitializeListHead(OUT PLIST_ENTRY ListHead)
{
	// инициализировать двусвязный список
    ListHead->Flink = ListHead->Blink = ListHead;
}

inline BOOL IsListEmpty(IN const LIST_ENTRY* ListHead)
{
	// признак пустого списка
    return (ListHead->Flink == ListHead);
}

inline void InsertHeadList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY Entry)
{
	// сохранить адрес первого элемента
    PLIST_ENTRY Flink = ListHead->Flink;

	// настроить связи в новом элементе
    Entry->Flink = Flink; Entry->Blink = ListHead;

	// настроить связи на новый элемент
    Flink->Blink = Entry; ListHead->Flink = Entry; 
}

inline void InsertTailList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY Entry)
{
	// сохранить адрес последнего элемента
    PLIST_ENTRY Blink = ListHead->Blink;

	// настроить связи в новом элементе
    Entry->Flink = ListHead; Entry->Blink = Blink;

	// настроить связи на новый элемент
    Blink->Flink = Entry; ListHead->Blink = Entry;
}

inline void AppendTailList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY ListToAppend)
{
	// сохранить адрес последних элементов
    PLIST_ENTRY ListEnd         = ListHead    ->Blink;
    PLIST_ENTRY ListToAppendEnd = ListToAppend->Blink;

	// связать последний элемент первого списка и первый элемент второго
    ListEnd->Flink = ListToAppend; ListToAppend->Blink = ListEnd;

	// переустановить последний элемент списка
    ListHead->Blink = ListToAppendEnd; ListToAppendEnd->Flink = ListHead;
}

inline BOOL RemoveEntryList(IN PLIST_ENTRY Entry)
{
	// сохранить адрес следующего и предыдущего элементов
    PLIST_ENTRY Flink = Entry->Flink;
    PLIST_ENTRY Blink = Entry->Blink;

	// убрать связь с удаляемым элементом
    Blink->Flink = Flink; Flink->Blink = Blink;

	// вернуть признак пустого списка
    return (Flink == Blink); 
}

inline PLIST_ENTRY RemoveHeadList(IN OUT PLIST_ENTRY ListHead)
{
	// получить адрес первого элемента
    PLIST_ENTRY Entry = ListHead->Flink; PLIST_ENTRY Flink = Entry->Flink; 

	// указать второй элемент в качестве первого
    ListHead->Flink = Flink; Flink->Blink = ListHead; return Entry;
}

inline PLIST_ENTRY RemoveTailList(IN OUT PLIST_ENTRY ListHead)
{
	// получить адрес последнего элемента
    PLIST_ENTRY Entry = ListHead->Blink; PLIST_ENTRY Blink = Entry->Blink;

	// указать предпоследний элемент в качестве последнего
    ListHead->Blink = Blink; Blink->Flink = ListHead; return Entry;
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Работа со строками. Функции RtlCopyString - это реализация функций strcpy_s 
// и wcscpy_s стандартной библиотеки С. Указание недопустимости оптимизации 
// необходимо для того, чтобы компилятор не заменил копирование после 
// основного цикла на вызов функции memset стандартной библиотеки C. 
// 
// Функция RtlCopyUnicodeString копирует Unicode-строку из одного буфера в 
// другой. При этом учитывается максимальный размер буфера и исходная строка 
// может быть скопирована неполностью. Функции RtlAppendUnicodeStringToString
// и RtlAppendUnicodeToString добавляют вторую строку к первой. При этом 
// учитывается максимальный размер буфера и в случае его нехватки возвращается 
// ошибка STATUS_BUFFER_TOO_SMALL. 
// 
// Функция RtlMultiByteToUnicodeSize вычисляет требуемый размер в байтах для 
// буфера, в котором функция RtlMultiByteToUnicodeN может разместить 
// преобразованную Unicode-строку. При этом учитываются только 
// BytesInMultiByteString байтов исходной ANSI-строки, в которые может не 
// входить нулевой символ. Аналогично функция RtlUnicodeToMultiByteSize 
// вычисляет требуемый размер в байтах для буфера, в котором функция 
// RtlUnicodeToMultiByteN может разместить преобразованную ANSI-строку. При 
// этом учитываются только BytesInUnicodeString байтов исходной Unicode-строки, 
// в которые может не входить нулевой символ. Функции RtlAnsiStringToUnicodeSize и 
// RtlUnicodeStringToAnsiSize аналогичны функциям RtlMultiByteToUnicodeSize и 
// RtlUnicodeToMultiByteSize, за исключением того, что они принимают структуры 
// ANSI_STRING и UNICODE_STRING и в результирующем размере учитывают наличие 
// завершающего нулевого символа. 
// 
// Функция RtlAnsiStringToUnicodeString преобразовывает ANSI-строку в
// Unicode-строку. При этом при указании AllocateDestinationString = TRUE 
// выделяется память требуемого размера (с учетом завершающего '\0'), которую 
// необходимо освободить последующим вызовом RtlFreeAnsiString. Если 
// AllocateDestinationString = FALSE, то преобразование учитывает максимальный 
// размер буфера и в случае его нехватки возвращается ошибка 
// STATUS_BUFFER_TOO_SMALL. Аналогично, функция RtlUicodeStringToAnsiString 
// преобразовывает Unicode-строку в ANSI-строку. При этом при указании 
// AllocateDestinationString = TRUE выделяется память требуемого размера (с 
// учетом завершающего '\0'), которую необходимо освободить последующим вызовом 
// RtlFreeUnicodeString. Если AllocateDestinationString = FALSE, то 
// преобразование учитывает максимальный размер буфера и в случае его нехватки 
// возвращается ошибка STATUS_BUFFER_TOO_SMALL.
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
typedef STRING ANSI_STRING, * PANSI_STRING; 
typedef CONST ANSI_STRING   * PCANSI_STRING;
typedef CONST UNICODE_STRING* PCUNICODE_STRING;
#endif 

#pragma optimize("", off)
template <typename T>
inline void RtlCopyString(T* szDest, size_t size, const T* szSource, size_t cch = -1)
{
	// для всех символов буфера
	size_t i = 0; for (; i + 1 < size; i++, szDest++)
	{
		// проверить скопированный размер
		if (cch != (size_t)(-1) && i == cch) break; 

		// скопировать символ
		*szDest = *szSource; if (!*szSource++) break; 
	}
	// обнулить буфер (для char подставится memset)
	for (; i < size; i++, szDest++) *szDest = 0;  
}
#pragma optimize("", on)

inline void RtlCopyString(char* szDest, size_t size, const ANSI_STRING& astSource)
{
	// определить размер строки в символах
	SIZE_T cch = (astSource.Length) / sizeof(CHAR); 

	// скопировать строку
	RtlCopyString(szDest, size, astSource.Buffer, cch); 
}
inline void RtlCopyString(wchar_t* szDest, size_t size, const UNICODE_STRING& ustSource)
{
	// определить размер строки в символах
	SIZE_T cch = (ustSource.Length) / sizeof(WCHAR); 

	// скопировать строку
	RtlCopyString(szDest, size, ustSource.Buffer, cch); 
}

#if !defined _NTDDK_
// скопировать строку (усечение при необходимости)
extern "C" NTSYSAPI VOID NTAPI RtlCopyUnicodeString(
	IN OUT	PUNICODE_STRING		Destination,	// результирующая строка
    IN		PCUNICODE_STRING	Source			// копируемая строка
);
// конкатенировать строки
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeStringToString(
    IN OUT	PUNICODE_STRING		Destination,	// результирующая строка
    IN		PCUNICODE_STRING	Source			// добавляемая строка
);
// конкатенировать строки
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeToString(
    IN OUT PUNICODE_STRING		Destination,	// результирующая строка
    IN     PCWSTR				Source			// добавляемая строка
);

// сравнить строки
extern "C" NTSYSAPI LONG NTAPI RtlCompareUnicodeStrings(
    IN PCWSTR			String1,				// первая сравниваемая строка
    IN SIZE_T			String1Length,			// размер первой строки
    IN PCWSTR			String2,				// вторая сравниваемая строка
    IN SIZE_T			String2Length,			// размер второй строки
    IN BOOLEAN			CaseInSensitive			// признак учета регистра
);
// сравнить строки
extern "C" NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
    IN PCUNICODE_STRING	String1,				// первая сравниваемая строка
    IN PCUNICODE_STRING	String2,				// вторая сравниваемая строка
    IN BOOLEAN			CaseInSensitive			// признак учета регистра
);
// сравнить строки
extern "C" NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
    IN PCUNICODE_STRING	String1,				// первая сравниваемая строка
    IN PCUNICODE_STRING	String2,				// вторая сравниваемая строка
    IN BOOLEAN			CaseInSensitive			// признак учета регистра
);

// определить требуемый размер для Unicode-строки
extern "C" NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeSize(
    OUT PULONG BytesInUnicodeString,			// размер Unicode-строки в байтах
    IN  PCSTR  MultiByteString,					// преобразуемая ANSI-строка
    IN  ULONG  BytesInMultiByteString			// размер ANSI-строки в байтах
);
// определить требуемый размер для ANSI-строки
extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteSize(
	OUT PULONG BytesInMultiByteString,			// размер ANSI-строки в байтах
	IN  PCWSTR UnicodeString,					// преобразуемая Unicode-строка
	IN  ULONG  BytesInUnicodeString				// размер Unicode-строки в байтах
);
// преобразовать ANSI-строку в Unicode
extern "C" NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeN(
    OUT PWSTR	UnicodeString,					// буфер для Unicode-строки
    IN	ULONG	MaxBytesInUnicodeString,		// размер буфера для Unicode-строки
    OUT PULONG	BytesInUnicodeString OPTIONAL,	// размер Unicode-строки в байтах
    IN	PCSTR	MultiByteString,				// преобразуемая ANSI-строка
    IN	ULONG	BytesInMultiByteString			// размер ANSI-строки в байтах
);
// преобразовать Unicode-строку в ANSI
extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteN(
    OUT PCSTR	MultiByteString,				// буфер для ANSI-строки
    IN	ULONG	MaxBytesInMultiByteString,		// размер буфера для ANSI-строки
    OUT PULONG	BytesInMultiByteString OPTIONAL,// размер ANSI-строки в байтах
    IN	PCWSTR	UnicodeString,					// преобразуемая Unicode-строка 
    IN	ULONG	BytesInUnicodeString			// размер Unicode-строки в байтах 
);

extern "C" NTSYSAPI NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN     PCANSI_STRING   SourceString,
    IN     BOOLEAN         AllocateDestinationString
);
extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
    IN OUT PANSI_STRING     DestinationString,
    IN     PCUNICODE_STRING SourceString,
    IN     BOOLEAN          AllocateDestinationString
);
extern "C" NTSYSAPI VOID NTAPI RtlFreeAnsiString   (IN OUT PANSI_STRING    AnsiString   );
extern "C" NTSYSAPI VOID NTAPI RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
#endif 

///////////////////////////////////////////////////////////////////////////////
// Системная информация 
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation                          = 0x00,
    SystemProcessorInformation                      = 0x01,
    SystemPerformanceInformation                    = 0x02,
    SystemTimeOfDayInformation                      = 0x03,
    SystemPathInformation                           = 0x04,
    SystemProcessInformation                        = 0x05,
    SystemCallCountInformation                      = 0x06,
    SystemDeviceInformation                         = 0x07,
    SystemProcessorPerformanceInformation           = 0x08,
    SystemFlagsInformation                          = 0x09,
    SystemCallTimeInformation                       = 0x0A,
    SystemModuleInformation                         = 0x0B,
    SystemLocksInformation                          = 0x0C,
    SystemStackTraceInformation                     = 0x0D,
    SystemPagedPoolInformation                      = 0x0E,
    SystemNonPagedPoolInformation                   = 0x0F,
    SystemHandleInformation                         = 0x10,
    SystemObjectInformation                         = 0x11,
    SystemPageFileInformation                       = 0x12,
    SystemVdmInstemulInformation                    = 0x13,
    SystemVdmBopInformation                         = 0x14,
    SystemFileCacheInformation                      = 0x15,
    SystemPoolTagInformation                        = 0x16,
    SystemInterruptInformation                      = 0x17,
    SystemDpcBehaviorInformation                    = 0x18,
    SystemFullMemoryInformation                     = 0x19,
    SystemLoadGdiDriverInformation                  = 0x1A,
    SystemUnloadGdiDriverInformation                = 0x1B,
    SystemTimeAdjustmentInformation                 = 0x1C,
    SystemSummaryMemoryInformation                  = 0x1D,
    SystemMirrorMemoryInformation                   = 0x1E,
    SystemPerformanceTraceInformation               = 0x1F,
    SystemObsolete0                                 = 0x20,
    SystemExceptionInformation                      = 0x21,
    SystemCrashDumpStateInformation                 = 0x22,
    SystemKernelDebuggerInformation                 = 0x23,
    SystemContextSwitchInformation                  = 0x24,
    SystemRegistryQuotaInformation                  = 0x25,
    SystemExtendServiceTableInformation             = 0x26,
    SystemPrioritySeperation                        = 0x27,
    SystemVerifierAddDriverInformation              = 0x28,
    SystemVerifierRemoveDriverInformation           = 0x29,
    SystemProcessorIdleInformation                  = 0x2A,
    SystemLegacyDriverInformation                   = 0x2B,
    SystemCurrentTimeZoneInformation                = 0x2C,
    SystemLookasideInformation                      = 0x2D,
    SystemTimeSlipNotification                      = 0x2E,
    SystemSessionCreate                             = 0x2F,
    SystemSessionDetach                             = 0x30,
    SystemSessionInformation                        = 0x31,
    SystemRangeStartInformation                     = 0x32,
    SystemVerifierInformation                       = 0x33,
    SystemVerifierThunkExtend                       = 0x34,
    SystemSessionProcessInformation                 = 0x35,
    SystemLoadGdiDriverInSystemSpace                = 0x36,
    SystemNumaProcessorMap                          = 0x37,
    SystemPrefetcherInformation                     = 0x38,
    SystemExtendedProcessInformation                = 0x39,
    SystemRecommendedSharedDataAlignment            = 0x3A,
    SystemComPlusPackage                            = 0x3B,
    SystemNumaAvailableMemory                       = 0x3C,
    SystemProcessorPowerInformation                 = 0x3D,
    SystemEmulationBasicInformation                 = 0x3E,
    SystemEmulationProcessorInformation             = 0x3F,
    SystemExtendedHandleInformation                 = 0x40,
    SystemLostDelayedWriteInformation               = 0x41,
    SystemBigPoolInformation                        = 0x42,
    SystemSessionPoolTagInformation                 = 0x43,
    SystemSessionMappedViewInformation              = 0x44,
    SystemHotpatchInformation                       = 0x45,
    SystemObjectSecurityMode                        = 0x46,
    SystemWatchdogTimerHandler                      = 0x47,
    SystemWatchdogTimerInformation                  = 0x48,
    SystemLogicalProcessorInformation               = 0x49,
    SystemWow64SharedInformation                    = 0x4A,
    SystemRegisterFirmwareTableInformationHandler   = 0x4B,
    SystemFirmwareTableInformation                  = 0x4C,
    SystemModuleInformationEx                       = 0x4D,
    SystemVerifierTriageInformation                 = 0x4E,
    SystemSuperfetchInformation                     = 0x4F,
    SystemMemoryListInformation                     = 0x50,
    SystemFileCacheInformationEx                    = 0x51
}; 

// получить системную информацию 
extern "C" NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
	IN     SYSTEM_INFORMATION_CLASS SystemInformationClass,		// тип информации
	IN OUT PVOID					SystemInformation,			// буфер для приема данных
	IN     ULONG					SystemInformationLength,	// размер буфера
	OUT    PULONG					ReturnLength OPTIONAL		// возвращаемый размер
);
// установить системную информацию
extern "C" NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(		
	IN SYSTEM_INFORMATION_CLASS		SystemInformationClass,		// тип информации
	IN PVOID						SystemInformation,			// буфер передаваемых данных
	IN ULONG						SystemInformationLength		// размер буфера данных
);
#endif 

///////////////////////////////////////////////////////////////////////////////
// SystemPerformanceTraceInformation
///////////////////////////////////////////////////////////////////////////////
enum EVENT_TRACE_INFORMATION_CLASS {
    EventTraceKernelVersionInformation                  =  0,
    EventTraceGroupMaskInformation                      =  1,
    EventTracePerformanceInformation                    =  2,
    EventTraceTimeProfileInformation                    =  3,
    EventTraceSessionSecurityInformation                =  4,
    EventTraceSpinlockInformation                       =  5,
    EventTraceStackTracingInformation                   =  6,
    EventTraceExecutiveResourceInformation              =  7,
    EventTraceHeapTracingInformation                    =  8,
    EventTraceHeapSummaryTracingInformation             =  9,
    EventTracePoolTagFilterInformation                  = 10,
    EventTracePebsTracingInformation                    = 11,
    EventTraceProfileConfigInformation                  = 12,
    EventTraceProfileSourceListInformation              = 13,
    EventTraceProfileEventListInformation               = 14,
    EventTraceProfileCounterListInformation             = 15,
    EventTraceStackCachingInformation                   = 16,
    EventTraceObjectTypeFilterInformation               = 17,
    EventTraceSoftRestartInformation                    = 18,
    EventTraceLastBranchConfigurationInformation        = 19,
    EventTraceLastBranchEventListInformation            = 20,
    EventTraceProfileSourceAddInformation               = 21,
    EventTraceProfileSourceRemoveInformation            = 22,
    EventTraceProcessorTraceConfigurationInformation    = 23,
    EventTraceProcessorTraceEventListInformation        = 24,
    EventTraceCoverageSamplerInformation                = 25,
    EventTraceUnifiedStackCachingInformation            = 26,
    MaxEventTraceInfoClass                              = 27
}; 

///////////////////////////////////////////////////////////////////////////////
// SystemPerformanceTraceInformation + EventTraceGroupMaskInformation
///////////////////////////////////////////////////////////////////////////////
struct PERFINFO_GROUPMASK { ULONG Masks[8]; };
struct EVENT_TRACE_GROUPMASK_INFORMATION {
    EVENT_TRACE_INFORMATION_CLASS   EventTraceInformationClass;
    TRACEHANDLE                     TraceHandle;
    PERFINFO_GROUPMASK              EventTraceGroupMasks;
}; 
#pragma warning(pop)


///////////////////////////////////////////////////////////////////////////////
// Блокировка LoaderLock
///////////////////////////////////////////////////////////////////////////////
 
// захвать блокировку LoaderLock
extern "C" NTSYSAPI NTSTATUS NTAPI LdrLockLoaderLock(
	IN  ULONG		Flags,					// флаги захвата блокировки
    OUT PULONG		Disposition OPTIONAL,	// результат захвата блокировки 
    OUT PULONG_PTR	Cookie					// значение, используемое при разблокировке
); 
// освободить блокировку LoaderLock
extern "C" NTSYSAPI NTSTATUS NTAPI LdrUnlockLoaderLock(
	IN ULONG		Flags,					// флаги освобождения блокировки
	IN ULONG_PTR	Cookie 					// значение, возвращенное функцией блокировки
);
///////////////////////////////////////////////////////////////////////////////
// Данные блоков окружения текущего процесса и потока
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
typedef struct _PEB_LDR_DATA {
    BYTE        Reserved1[8];
    PVOID       Reserved2[3];
    LIST_ENTRY  InMemoryOrderModuleList;
}
PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID           Reserved1[2];
    LIST_ENTRY      InMemoryOrderLinks;
    PVOID           Reserved2[2];
    PVOID           DllBase;
    PVOID           Reserved3[2];
    UNICODE_STRING  FullDllName;
    BYTE            Reserved4[8];
    PVOID           Reserved5[3];
    union {
        ULONG       CheckSum;
        PVOID       Reserved6;
    } DUMMYUNIONNAME;
    ULONG           TimeDateStamp;
}
LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE            Reserved1[16];
    PVOID           Reserved2[10];
    UNICODE_STRING  ImagePathName;
    UNICODE_STRING  CommandLine;
}
RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)();

typedef struct _PEB {
    BYTE                            Reserved1[2];
    BYTE                            BeingDebugged;
    BYTE                            Reserved2[1];
    PVOID                           Reserved3[2];
    PPEB_LDR_DATA                   Ldr;
    PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;
    PVOID                           Reserved4[3];
    PVOID                           AtlThunkSListPtr;
    PVOID                           Reserved5;
    ULONG                           Reserved6;
    PVOID                           Reserved7;
    ULONG                           Reserved8;
    ULONG                           AtlThunkSListPtr32;
    PVOID                           Reserved9[45];
    BYTE                            Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE   PostProcessInitRoutine;
    BYTE                            Reserved11[128];
    PVOID                           Reserved12[1];
    ULONG                           SessionId;
}
PEB, *PPEB;

typedef struct _TEB {
    PVOID                           Reserved1[12];
    PPEB                            ProcessEnvironmentBlock;
    PVOID                           Reserved2[399];
    BYTE                            Reserved3[1952];
    PVOID                           TlsSlots[64];
    BYTE                            Reserved4[8];
    PVOID                           Reserved5[26];
    PVOID                           ReservedForOle;  // Windows 2000 only
    PVOID                           Reserved6[4];
    PVOID                           TlsExpansionSlots;
}
TEB, *PTEB;

// блок переменных текущего процесса
inline const PEB* NtCurrentPeb() noexcept
{
#ifdef _MSC_VER
	// получить блок переменных процесса
	return NtCurrentTeb()->ProcessEnvironmentBlock;  
#else 
	// получить блок переменных процесса
	return (CONST PEB*)((PVOID*)NtCurrentTeb())[12];  
#endif 
}

// идентификатор текущего процесса
inline HANDLE NtCurrentProcessId() noexcept
{
	// получить блок переменных процесса
	return (HANDLE)((PVOID*)NtCurrentTeb())[8];  
}
// идентификатор текущего потока
inline HANDLE NtCurrentThreadId() noexcept 
{ 
	// идентификатор текущего потока
	return (HANDLE)((PVOID*)NtCurrentTeb())[9]; 
}
#endif 

