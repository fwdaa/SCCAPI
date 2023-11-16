#pragma once
#if !defined _NTDDK_
#include <subauth.h>			
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ����������
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
#pragma comment(lib, "ntdll.lib")
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �������������� 
///////////////////////////////////////////////////////////////////////////////
#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

///////////////////////////////////////////////////////////////////////////////
// ��������������� �������� � ������
///////////////////////////////////////////////////////////////////////////////
#ifndef NtCurrentProcess
#define NtCurrentProcess()	((HANDLE)(LONG_PTR)(-1))
#endif 

#ifndef NtCurrentThread
#define NtCurrentThread()	((HANDLE)(LONG_PTR)(-2))
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������. ������� RtlNtStatusToDosError ����������� ��� ������ 
// NTSTATUS � ��� ������ Win32 (��� �������� ����������). ��� ���������� 
// ������������ ������������ ��� ERROR_MR_MID_NOT_FOUND. 
///////////////////////////////////////////////////////////////////////////////

// ������� ���������� ������ � �������������� 
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)      (((NTSTATUS)(Status)) >= 0)
#endif

// ������� ������� �������������� ���������� 
#ifndef NT_INFORMATION
#define NT_INFORMATION(Status)  ((((ULONG)(Status)) >> 30) == 1)
#endif

// ������� ������� �������������� 
#ifndef NT_WARNING
#define NT_WARNING(Status)      ((((ULONG)(Status)) >> 30) == 2)
#endif

// ������� ������� ������ 
#ifndef NT_ERROR
#define NT_ERROR(Status)        ((((ULONG)(Status)) >> 30) == 3)
#endif

// �������������� ���� NTSTATUS � ��� ������ Win32
extern "C" NTSYSAPI ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);

///////////////////////////////////////////////////////////////////////////////
// ��������������� ������� ��� ������ CRT
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void RtlCopyBytes(void* pDest, const void* pSource, size_t cb)
{
	// ����������� ������
	for (size_t i = 0; i < cb; i++) ((char*)pDest)[i] = ((const char*)pSource)[i]; 
}
// �������� ������
#define RtlZeroBytes RtlSecureZeroMemory
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������. ������� PushEntryList ��������� ������� Entry � ������ 
// ������ � ������ ListHead. ������� PopEntryList ������� ������ ������� �� 
// ������ � ������ ListHead � ���������� ��������� �������. 
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void PushEntryList(
    IN OUT PSINGLE_LIST_ENTRY ListHead, IN OUT PSINGLE_LIST_ENTRY Entry)
{
	// �������� ������� � ������ ������
    Entry->Next = ListHead->Next; ListHead->Next = Entry; 
}

inline PSINGLE_LIST_ENTRY PopEntryList(IN OUT PSINGLE_LIST_ENTRY ListHead)
{
	// �������� ������� �� ������ ������
    PSINGLE_LIST_ENTRY FirstEntry = ListHead->Next;

	// ������� ������ ������� �� ������ 
    if (FirstEntry) ListHead->Next = FirstEntry->Next; return FirstEntry;
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������. ������� InitializeListHead �������������� ������ 
// ListHead ������. ������� IsListEmpty ��������� ������� ��������� ������ 
// � ������ ListHead. ������� InsertHeadList ��������� ������� Entry � ������ 
// ������ � ������ ListHead. ������� InsertTailList ��������� ������� Entry 
// � ����� ������ � ������ ListHead. ������� AppendTailList ��������� � ����� 
// ������ � ������ � ListHead ��� �������� ������� ������������ ������ � 
// ��������� ��������� ListToAppend. ������� RemoveEntryList ������� �������
// Entry �� ������, ��� �����������. ������� RemoveHeadList ������� ������ 
// ������� �� ������ � ������ ListHead � ���������� ��������� �������. ������� 
// RemoveTailList ������ ��������� ������� �� ������ � ������ ListHead � 
// ���������� ��������� �������.
///////////////////////////////////////////////////////////////////////////////
#if !defined _NTDDK_
inline void InitializeListHead(OUT PLIST_ENTRY ListHead)
{
	// ���������������� ���������� ������
    ListHead->Flink = ListHead->Blink = ListHead;
}

inline BOOL IsListEmpty(IN const LIST_ENTRY* ListHead)
{
	// ������� ������� ������
    return (ListHead->Flink == ListHead);
}

inline void InsertHeadList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY Entry)
{
	// ��������� ����� ������� ��������
    PLIST_ENTRY Flink = ListHead->Flink;

	// ��������� ����� � ����� ��������
    Entry->Flink = Flink; Entry->Blink = ListHead;

	// ��������� ����� �� ����� �������
    Flink->Blink = Entry; ListHead->Flink = Entry; 
}

inline void InsertTailList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY Entry)
{
	// ��������� ����� ���������� ��������
    PLIST_ENTRY Blink = ListHead->Blink;

	// ��������� ����� � ����� ��������
    Entry->Flink = ListHead; Entry->Blink = Blink;

	// ��������� ����� �� ����� �������
    Blink->Flink = Entry; ListHead->Blink = Entry;
}

inline void AppendTailList(
    IN OUT PLIST_ENTRY ListHead, IN OUT PLIST_ENTRY ListToAppend)
{
	// ��������� ����� ��������� ���������
    PLIST_ENTRY ListEnd         = ListHead    ->Blink;
    PLIST_ENTRY ListToAppendEnd = ListToAppend->Blink;

	// ������� ��������� ������� ������� ������ � ������ ������� �������
    ListEnd->Flink = ListToAppend; ListToAppend->Blink = ListEnd;

	// �������������� ��������� ������� ������
    ListHead->Blink = ListToAppendEnd; ListToAppendEnd->Flink = ListHead;
}

inline BOOL RemoveEntryList(IN PLIST_ENTRY Entry)
{
	// ��������� ����� ���������� � ����������� ���������
    PLIST_ENTRY Flink = Entry->Flink;
    PLIST_ENTRY Blink = Entry->Blink;

	// ������ ����� � ��������� ���������
    Blink->Flink = Flink; Flink->Blink = Blink;

	// ������� ������� ������� ������
    return (Flink == Blink); 
}

inline PLIST_ENTRY RemoveHeadList(IN OUT PLIST_ENTRY ListHead)
{
	// �������� ����� ������� ��������
    PLIST_ENTRY Entry = ListHead->Flink; PLIST_ENTRY Flink = Entry->Flink; 

	// ������� ������ ������� � �������� �������
    ListHead->Flink = Flink; Flink->Blink = ListHead; return Entry;
}

inline PLIST_ENTRY RemoveTailList(IN OUT PLIST_ENTRY ListHead)
{
	// �������� ����� ���������� ��������
    PLIST_ENTRY Entry = ListHead->Blink; PLIST_ENTRY Blink = Entry->Blink;

	// ������� ������������� ������� � �������� ����������
    ListHead->Blink = Blink; Blink->Flink = ListHead; return Entry;
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ �� ��������. ������� RtlCopyString - ��� ���������� ������� strcpy_s 
// � wcscpy_s ����������� ���������� �. �������� �������������� ����������� 
// ���������� ��� ����, ����� ���������� �� ������� ����������� ����� 
// ��������� ����� �� ����� ������� memset ����������� ���������� C. 
// 
// ������� RtlCopyUnicodeString �������� Unicode-������ �� ������ ������ � 
// ������. ��� ���� ����������� ������������ ������ ������ � �������� ������ 
// ����� ���� ����������� �����������. ������� RtlAppendUnicodeStringToString
// � RtlAppendUnicodeToString ��������� ������ ������ � ������. ��� ���� 
// ����������� ������������ ������ ������ � � ������ ��� �������� ������������ 
// ������ STATUS_BUFFER_TOO_SMALL. 
// 
// ������� RtlMultiByteToUnicodeSize ��������� ��������� ������ � ������ ��� 
// ������, � ������� ������� RtlMultiByteToUnicodeN ����� ���������� 
// ��������������� Unicode-������. ��� ���� ����������� ������ 
// BytesInMultiByteString ������ �������� ANSI-������, � ������� ����� �� 
// ������� ������� ������. ���������� ������� RtlUnicodeToMultiByteSize 
// ��������� ��������� ������ � ������ ��� ������, � ������� ������� 
// RtlUnicodeToMultiByteN ����� ���������� ��������������� ANSI-������. ��� 
// ���� ����������� ������ BytesInUnicodeString ������ �������� Unicode-������, 
// � ������� ����� �� ������� ������� ������. ������� RtlAnsiStringToUnicodeSize � 
// RtlUnicodeStringToAnsiSize ���������� �������� RtlMultiByteToUnicodeSize � 
// RtlUnicodeToMultiByteSize, �� ����������� ����, ��� ��� ��������� ��������� 
// ANSI_STRING � UNICODE_STRING � � �������������� ������� ��������� ������� 
// ������������ �������� �������. 
// 
// ������� RtlAnsiStringToUnicodeString ��������������� ANSI-������ �
// Unicode-������. ��� ���� ��� �������� AllocateDestinationString = TRUE 
// ���������� ������ ���������� ������� (� ������ ������������ '\0'), ������� 
// ���������� ���������� ����������� ������� RtlFreeAnsiString. ���� 
// AllocateDestinationString = FALSE, �� �������������� ��������� ������������ 
// ������ ������ � � ������ ��� �������� ������������ ������ 
// STATUS_BUFFER_TOO_SMALL. ����������, ������� RtlUicodeStringToAnsiString 
// ��������������� Unicode-������ � ANSI-������. ��� ���� ��� �������� 
// AllocateDestinationString = TRUE ���������� ������ ���������� ������� (� 
// ������ ������������ '\0'), ������� ���������� ���������� ����������� ������� 
// RtlFreeUnicodeString. ���� AllocateDestinationString = FALSE, �� 
// �������������� ��������� ������������ ������ ������ � � ������ ��� �������� 
// ������������ ������ STATUS_BUFFER_TOO_SMALL.
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
	// ��� ���� �������� ������
	size_t i = 0; for (; i + 1 < size; i++, szDest++)
	{
		// ��������� ������������� ������
		if (cch != (size_t)(-1) && i == cch) break; 

		// ����������� ������
		*szDest = *szSource; if (!*szSource++) break; 
	}
	// �������� ����� (��� char ����������� memset)
	for (; i < size; i++, szDest++) *szDest = 0;  
}
#pragma optimize("", on)

inline void RtlCopyString(char* szDest, size_t size, const ANSI_STRING& astSource)
{
	// ���������� ������ ������ � ��������
	SIZE_T cch = (astSource.Length) / sizeof(CHAR); 

	// ����������� ������
	RtlCopyString(szDest, size, astSource.Buffer, cch); 
}
inline void RtlCopyString(wchar_t* szDest, size_t size, const UNICODE_STRING& ustSource)
{
	// ���������� ������ ������ � ��������
	SIZE_T cch = (ustSource.Length) / sizeof(WCHAR); 

	// ����������� ������
	RtlCopyString(szDest, size, ustSource.Buffer, cch); 
}

#if !defined _NTDDK_
// ����������� ������ (�������� ��� �������������)
extern "C" NTSYSAPI VOID NTAPI RtlCopyUnicodeString(
	IN OUT	PUNICODE_STRING		Destination,	// �������������� ������
    IN		PCUNICODE_STRING	Source			// ���������� ������
);
// ��������������� ������
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeStringToString(
    IN OUT	PUNICODE_STRING		Destination,	// �������������� ������
    IN		PCUNICODE_STRING	Source			// ����������� ������
);
// ��������������� ������
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeToString(
    IN OUT PUNICODE_STRING		Destination,	// �������������� ������
    IN     PCWSTR				Source			// ����������� ������
);

// �������� ������
extern "C" NTSYSAPI LONG NTAPI RtlCompareUnicodeStrings(
    IN PCWSTR			String1,				// ������ ������������ ������
    IN SIZE_T			String1Length,			// ������ ������ ������
    IN PCWSTR			String2,				// ������ ������������ ������
    IN SIZE_T			String2Length,			// ������ ������ ������
    IN BOOLEAN			CaseInSensitive			// ������� ����� ��������
);
// �������� ������
extern "C" NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
    IN PCUNICODE_STRING	String1,				// ������ ������������ ������
    IN PCUNICODE_STRING	String2,				// ������ ������������ ������
    IN BOOLEAN			CaseInSensitive			// ������� ����� ��������
);
// �������� ������
extern "C" NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
    IN PCUNICODE_STRING	String1,				// ������ ������������ ������
    IN PCUNICODE_STRING	String2,				// ������ ������������ ������
    IN BOOLEAN			CaseInSensitive			// ������� ����� ��������
);

// ���������� ��������� ������ ��� Unicode-������
extern "C" NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeSize(
    OUT PULONG BytesInUnicodeString,			// ������ Unicode-������ � ������
    IN  PCSTR  MultiByteString,					// ������������� ANSI-������
    IN  ULONG  BytesInMultiByteString			// ������ ANSI-������ � ������
);
// ���������� ��������� ������ ��� ANSI-������
extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteSize(
	OUT PULONG BytesInMultiByteString,			// ������ ANSI-������ � ������
	IN  PCWSTR UnicodeString,					// ������������� Unicode-������
	IN  ULONG  BytesInUnicodeString				// ������ Unicode-������ � ������
);
// ������������� ANSI-������ � Unicode
extern "C" NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeN(
    OUT PWSTR	UnicodeString,					// ����� ��� Unicode-������
    IN	ULONG	MaxBytesInUnicodeString,		// ������ ������ ��� Unicode-������
    OUT PULONG	BytesInUnicodeString OPTIONAL,	// ������ Unicode-������ � ������
    IN	PCSTR	MultiByteString,				// ������������� ANSI-������
    IN	ULONG	BytesInMultiByteString			// ������ ANSI-������ � ������
);
// ������������� Unicode-������ � ANSI
extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteN(
    OUT PCSTR	MultiByteString,				// ����� ��� ANSI-������
    IN	ULONG	MaxBytesInMultiByteString,		// ������ ������ ��� ANSI-������
    OUT PULONG	BytesInMultiByteString OPTIONAL,// ������ ANSI-������ � ������
    IN	PCWSTR	UnicodeString,					// ������������� Unicode-������ 
    IN	ULONG	BytesInUnicodeString			// ������ Unicode-������ � ������ 
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
// ��������� ���������� 
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

// �������� ��������� ���������� 
extern "C" NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
	IN     SYSTEM_INFORMATION_CLASS SystemInformationClass,		// ��� ����������
	IN OUT PVOID					SystemInformation,			// ����� ��� ������ ������
	IN     ULONG					SystemInformationLength,	// ������ ������
	OUT    PULONG					ReturnLength OPTIONAL		// ������������ ������
);
// ���������� ��������� ����������
extern "C" NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(		
	IN SYSTEM_INFORMATION_CLASS		SystemInformationClass,		// ��� ����������
	IN PVOID						SystemInformation,			// ����� ������������ ������
	IN ULONG						SystemInformationLength		// ������ ������ ������
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
// ���������� LoaderLock
///////////////////////////////////////////////////////////////////////////////
 
// ������� ���������� LoaderLock
extern "C" NTSYSAPI NTSTATUS NTAPI LdrLockLoaderLock(
	IN  ULONG		Flags,					// ����� ������� ����������
    OUT PULONG		Disposition OPTIONAL,	// ��������� ������� ���������� 
    OUT PULONG_PTR	Cookie					// ��������, ������������ ��� �������������
); 
// ���������� ���������� LoaderLock
extern "C" NTSYSAPI NTSTATUS NTAPI LdrUnlockLoaderLock(
	IN ULONG		Flags,					// ����� ������������ ����������
	IN ULONG_PTR	Cookie 					// ��������, ������������ �������� ����������
);
///////////////////////////////////////////////////////////////////////////////
// ������ ������ ��������� �������� �������� � ������
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

// ���� ���������� �������� ��������
inline const PEB* NtCurrentPeb() noexcept
{
#ifdef _MSC_VER
	// �������� ���� ���������� ��������
	return NtCurrentTeb()->ProcessEnvironmentBlock;  
#else 
	// �������� ���� ���������� ��������
	return (CONST PEB*)((PVOID*)NtCurrentTeb())[12];  
#endif 
}

// ������������� �������� ��������
inline HANDLE NtCurrentProcessId() noexcept
{
	// �������� ���� ���������� ��������
	return (HANDLE)((PVOID*)NtCurrentTeb())[8];  
}
// ������������� �������� ������
inline HANDLE NtCurrentThreadId() noexcept 
{ 
	// ������������� �������� ������
	return (HANDLE)((PVOID*)NtCurrentTeb())[9]; 
}
#endif 

