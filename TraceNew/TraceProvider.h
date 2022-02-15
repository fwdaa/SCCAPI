#pragma once
#include <evntrace.h>
#include <evntprov.h>

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// Каждое системное событие представляется отдельным флагом в 256-битовой 
// маске PERFINFO_GROUPMASK (8 слов типа ULONG). Внутри операционной системы 
// указанная маска иногда называется SystemTraceEnableFlags. В параметры 
// сеанса такую маску можно установить либо через вызов TraceSetInformation 
// с указанием кода TraceSystemTraceEnableFlagsInfo, либо через функцию 
// ControlTrace с кодом EVENT_TRACE_CONTROL_UPDATE в структуре 
// EVENT_TRACE_PROPERTIES. В последнем случае, маска PERFINFO_GROUPMASK должна 
// следовать за структурой EVENT_TRACE_PROPERTIES, а поле EnableFlags 
// указанной структуры должно иметь формат TRACE_ENABLE_FLAG_EXTENSION: 
// первые два байта - смещение маски PERFINFO_GROUPMASK от начала структуры 
// EVENT_TRACE_PROPERTIES, третий байт - размер PERFINFO_GROUPMASK в 
// ULONG-словах (может быть меньше восьми), а в последнем байте должен 
// быть установлен старший бит (при интерпретации поля EnableFlags как 
// ULONG указанный бит адресуется маской EVENT_TRACE_FLAG_EXTENSION). 
///////////////////////////////////////////////////////////////////////////////
struct PERFINFO_GROUPMASK { ULONG Masks[8]; };

///////////////////////////////////////////////////////////////////////////////
// Без использования недокумментированных возможностей при использовании 
// системного провайдера в ETW ему передается 32-битная маска EnableFlags, 
// которая покрывает только отдельные события PERFINFO_GROUPMASK. Биты 
// 32-битной маски EnableFlags именуются EVENT_TRACE_FLAG_*. Функция 
// GetSystemLegacyEnableFlags преобразует маску PERFINFO_GROUPMASK 
// в 32-битную маску EnableFlags (при этом будут отброшены события, 
// не имеющие соответствующего бита EVENT_TRACE_FLAG_*). 
///////////////////////////////////////////////////////////////////////////////
ULONG GetSystemLegacyEnableFlags(CONST DWORD*, ULONG); 

inline ULONG GetSystemLegacyEnableFlags(const PERFINFO_GROUPMASK& mask)
{
    // выполнить преобразование PERFINFO_GROUPMASK -> EnableFlags
    return GetSystemLegacyEnableFlags(mask.Masks, _countof(mask.Masks)); 
}

///////////////////////////////////////////////////////////////////////////////
// Начиная с Windows 10, системный провайдер разделен на отдельные компоненты,  
// которые можно напрямую передавать функции EnableTrace. Каждый компонентный
// провайдер использует 32-разрядную маску системных событий, которая 
// однозначно проецируется на PERFINFO_GROUPMASK. Функции GetSystemTraceEnableFlags
// получают 256-битовую маску PERFINFO_GROUPMASK на основе GUID провайдера 
// и его 32-разрядной маски (при отсутствии 32-разрядной маски возвращается 
// 256-битовая маска, описывающая все события провайдера). 
///////////////////////////////////////////////////////////////////////////////
PERFINFO_GROUPMASK GetSystemTraceEnableFlags(const GUID& guid, ULONG mask = 0);

///////////////////////////////////////////////////////////////////////////////
// System ALPC Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemAlpcProviderGuid; 

const ULONG SYSTEM_ALPC_KW_GENERAL				= 0x0001; // EVENT_TRACE_FLAG_ALPC

///////////////////////////////////////////////////////////////////////////////
// System Config Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemConfigProviderGuid; 

const ULONG SYSTEM_CONFIG_KW_SYSTEM				= 0x0001; // 
const ULONG SYSTEM_CONFIG_KW_GRAPHICS	        = 0x0002; // 
const ULONG SYSTEM_CONFIG_KW_STORAGE	        = 0x0004; // 
const ULONG SYSTEM_CONFIG_KW_NETWORK	        = 0x0008; // 
const ULONG SYSTEM_CONFIG_KW_SERVICES	        = 0x0010; // 
const ULONG SYSTEM_CONFIG_KW_PNP	            = 0x0020; // 
const ULONG SYSTEM_CONFIG_KW_OPTICAL	        = 0x0040; // 

///////////////////////////////////////////////////////////////////////////////
// System CPU Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemCpuProviderGuid; 

const ULONG SYSTEM_CPU_KW_CONFIG	            = 0x0001; // 
const ULONG SYSTEM_CPU_KW_CACHE_FLUSH	        = 0x0002; // 
const ULONG SYSTEM_CPU_KW_SPEC_CONTROL			= 0x0004; // 

///////////////////////////////////////////////////////////////////////////////
// System Hypervisor Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemHypervisorProviderGuid; 

const ULONG SYSTEM_HYPERVISOR_KW_PROFILE	    = 0x0001; // 
const ULONG SYSTEM_HYPERVISOR_KW_CALLOUTS	    = 0x0002; // 
const ULONG SYSTEM_HYPERVISOR_KW_VTL_CHANGE		= 0x0004; // 

///////////////////////////////////////////////////////////////////////////////
// System Interrupt Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemInterruptProviderGuid; 

const ULONG SYSTEM_INTERRUPT_KW_GENERAL	        = 0x0001; // EVENT_TRACE_FLAG_INTERRUPT
const ULONG SYSTEM_INTERRUPT_KW_CLOCK_INTERRUPT	= 0x0002; // 
const ULONG SYSTEM_INTERRUPT_KW_DPC	            = 0x0004; // EVENT_TRACE_FLAG_DPC
const ULONG SYSTEM_INTERRUPT_KW_DPC_QUEUE	    = 0x0008; // 
const ULONG SYSTEM_INTERRUPT_KW_WDF_DPC	        = 0x0010; // 
const ULONG SYSTEM_INTERRUPT_KW_WDF_INTERRUPT	= 0x0020; // 
const ULONG SYSTEM_INTERRUPT_KW_IPI	            = 0x0040; // 

///////////////////////////////////////////////////////////////////////////////
// System IO Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemIoProviderGuid; 

const ULONG SYSTEM_IO_KW_DISK					= 0x0001; // EVENT_TRACE_FLAG_DISK_IO
const ULONG SYSTEM_IO_KW_DISK_INIT	            = 0x0002; // EVENT_TRACE_FLAG_DISK_IO_INIT
const ULONG SYSTEM_IO_KW_FILENAME	            = 0x0004; // EVENT_TRACE_FLAG_DISK_FILE_IO
const ULONG SYSTEM_IO_KW_SPLIT	                = 0x0008; // EVENT_TRACE_FLAG_SPLIT_IO
const ULONG SYSTEM_IO_KW_FILE	                = 0x0010; // EVENT_TRACE_FLAG_FILE_IO
const ULONG SYSTEM_IO_KW_OPTICAL	            = 0x0020; // 
const ULONG SYSTEM_IO_KW_OPTICAL_INIT	        = 0x0040; // 
const ULONG SYSTEM_IO_KW_DRIVERS	            = 0x0080; // EVENT_TRACE_FLAG_DRIVER
const ULONG SYSTEM_IO_KW_CC	                    = 0x0100; // 
const ULONG SYSTEM_IO_KW_NETWORK	            = 0x0200; // EVENT_TRACE_FLAG_NETWORK_TCPIP

///////////////////////////////////////////////////////////////////////////////
// System IO Filter Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemIoFilterProviderGuid; 

const ULONG SYSTEM_IOFILTER_KW_GENERAL			= 0x0001; //
const ULONG SYSTEM_IOFILTER_KW_INIT	            = 0x0002; //
const ULONG SYSTEM_IOFILTER_KW_FASTIO	        = 0x0004; //
const ULONG SYSTEM_IOFILTER_KW_FAILURE	        = 0x0008; //

///////////////////////////////////////////////////////////////////////////////
// System Lock Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemLockProviderGuid; 

const ULONG SYSTEM_LOCK_KW_SPINLOCK				= 0x0001; // 
const ULONG SYSTEM_LOCK_KW_SPINLOCK_COUNTERS	= 0x0002; // 
const ULONG SYSTEM_LOCK_KW_SYNC_OBJECTS	        = 0x0004; // 

///////////////////////////////////////////////////////////////////////////////
// System Memory Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemMemoryProviderGuid; 

const ULONG SYSTEM_MEMORY_KW_GENERAL			= 0x0001; // 
const ULONG SYSTEM_MEMORY_KW_HARD_FAULTS	    = 0x0002; // EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS
const ULONG SYSTEM_MEMORY_KW_ALL_FAULTS	        = 0x0004; // EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS
const ULONG SYSTEM_MEMORY_KW_POOL	            = 0x0008; // 
const ULONG SYSTEM_MEMORY_KW_MEMINFO	        = 0x0010; // 
const ULONG SYSTEM_MEMORY_KW_PFSECTION	        = 0x0020; // 
const ULONG SYSTEM_MEMORY_KW_MEMINFO_WS	        = 0x0040; // 
const ULONG SYSTEM_MEMORY_KW_HEAP	            = 0x0080; // 
const ULONG SYSTEM_MEMORY_KW_WS	                = 0x0100; // 
const ULONG SYSTEM_MEMORY_KW_CONTMEM_GEN	    = 0x0200; // 
const ULONG SYSTEM_MEMORY_KW_VIRTUAL_ALLOC	    = 0x0400; // EVENT_TRACE_FLAG_VIRTUAL_ALLOC
const ULONG SYSTEM_MEMORY_KW_FOOTPRINT	        = 0x0800; // 
const ULONG SYSTEM_MEMORY_KW_SESSION	        = 0x1000; // 
const ULONG SYSTEM_MEMORY_KW_REFSET	            = 0x2000; // 
const ULONG SYSTEM_MEMORY_KW_VAMAP	            = 0x4000; // EVENT_TRACE_FLAG_VAMAP

///////////////////////////////////////////////////////////////////////////////
// System Object Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemObjectProviderGuid; 

const ULONG SYSTEM_OBJECT_KW_HANDLE				= 0x0001; // 
const ULONG SYSTEM_OBJECT_KW_OBJECT	            = 0x0002; // 

///////////////////////////////////////////////////////////////////////////////
// System Power Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemPowerProviderGuid; 

const ULONG SYSTEM_POWER_KW_GENERAL				= 0x0001; // 
const ULONG SYSTEM_POWER_KW_HIBER_RUNDOWN	    = 0x0002; // 
const ULONG SYSTEM_POWER_KW_PROCESSOR_IDLE	    = 0x0004; // 
const ULONG SYSTEM_POWER_KW_IDLE_SELECTION	    = 0x0008; // 
const ULONG SYSTEM_POWER_KW_PPM_EXIT_LATENCY	= 0x0010; // 

///////////////////////////////////////////////////////////////////////////////
// System Process Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemProcessProviderGuid; 

const ULONG SYSTEM_PROCESS_KW_GENERAL			= 0x0001; // EVENT_TRACE_FLAG_PROCESS
const ULONG SYSTEM_PROCESS_KW_INSWAP	        = 0x0002; // 
const ULONG SYSTEM_PROCESS_KW_FREEZE	        = 0x0004; // 
const ULONG SYSTEM_PROCESS_KW_PERF_COUNTER	    = 0x0008; // EVENT_TRACE_FLAG_PROCESS_COUNTERS
const ULONG SYSTEM_PROCESS_KW_WAKE_COUNTER	    = 0x0010; // 
const ULONG SYSTEM_PROCESS_KW_WAKE_DROP	        = 0x0020; // 
const ULONG SYSTEM_PROCESS_KW_WAKE_EVENT	    = 0x0040; // 
const ULONG SYSTEM_PROCESS_KW_DEBUG_EVENTS	    = 0x0080; // EVENT_TRACE_FLAG_DEBUG_EVENTS
const ULONG SYSTEM_PROCESS_KW_DBGPRINT	        = 0x0100; // EVENT_TRACE_FLAG_DBGPRINT
const ULONG SYSTEM_PROCESS_KW_JOB	            = 0x0200; // EVENT_TRACE_FLAG_JOB
const ULONG SYSTEM_PROCESS_KW_WORKER_THREAD	    = 0x0400; // 
const ULONG SYSTEM_PROCESS_KW_THREAD	        = 0x0800; // EVENT_TRACE_FLAG_THREAD
const ULONG SYSTEM_PROCESS_KW_LOADER	        = 0x1000; // EVENT_TRACE_FLAG_IMAGE_LOAD

///////////////////////////////////////////////////////////////////////////////
// System Profile Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemProfileProviderGuid; 

const ULONG SYSTEM_PROFILE_KW_GENERAL			= 0x0001; // EVENT_TRACE_FLAG_PROFILE
const ULONG SYSTEM_PROFILE_KW_PMC_PROFILE	    = 0x0002; // 

///////////////////////////////////////////////////////////////////////////////
// System Registry Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemRegistryProviderGuid; 

const ULONG SYSTEM_REGISTRY_KW_GENERAL			= 0x0001; // EVENT_TRACE_FLAG_REGISTRY
const ULONG SYSTEM_REGISTRY_KW_HIVE	            = 0x0002; // 
const ULONG SYSTEM_REGISTRY_KW_NOTIFICATION	    = 0x0004; // 

///////////////////////////////////////////////////////////////////////////////
// System Scheduler Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemSchedulerProviderGuid; 

const ULONG SYSTEM_SCHEDULER_KW_XSCHEDULER		= 0x0001; // 
const ULONG SYSTEM_SCHEDULER_KW_DISPATCHER	    = 0x0002; // EVENT_TRACE_FLAG_DISPATCHER
const ULONG SYSTEM_SCHEDULER_KW_KERNEL_QUEUE	= 0x0004; // 
const ULONG SYSTEM_SCHEDULER_KW_SHOULD_YIELD	= 0x0008; // 
const ULONG SYSTEM_SCHEDULER_KW_ANTI_STARVATION	= 0x0010; // 
const ULONG SYSTEM_SCHEDULER_KW_LOAD_BALANCER	= 0x0020; // 
const ULONG SYSTEM_SCHEDULER_KW_AFFINITY	    = 0x0040; // 
const ULONG SYSTEM_SCHEDULER_KW_PRIORITY	    = 0x0080; // 
const ULONG SYSTEM_SCHEDULER_KW_IDEAL_PROCESSOR	= 0x0100; // 
const ULONG SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH	= 0x0200; // EVENT_TRACE_FLAG_CSWITCH

///////////////////////////////////////////////////////////////////////////////
// System Syscall Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemSyscallProviderGuid; 

const ULONG SYSTEM_SYSCALL_KW_GENERAL			= 0x0001; // EVENT_TRACE_FLAG_SYSTEMCALL

///////////////////////////////////////////////////////////////////////////////
// System Timer Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemTimerProviderGuid; 

const ULONG SYSTEM_TIMER_KW_GENERAL				= 0x0001; // 
const ULONG SYSTEM_TIMER_KW_CLOCK_TIMER	        = 0x0002; // 

///////////////////////////////////////////////////////////////////////////////
// Провайдер трассировки
///////////////////////////////////////////////////////////////////////////////
struct IProvider { virtual ~IProvider() {}

    // идентификатор провайдера
    virtual const GUID& ID() const = 0; 
};
}

namespace WMI 
{
///////////////////////////////////////////////////////////////////////////////
// Категория событий
///////////////////////////////////////////////////////////////////////////////
struct IEventCategory { virtual ~IEventCategory() {}

    // идентификатор категории
    virtual const GUID& Guid() const = 0; 

    // создать уникальный идентификатор для события
    virtual EVENT_INSTANCE_INFO CreateInstanceID() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Соединение с сеансом трассировки
///////////////////////////////////////////////////////////////////////////////
struct IConnection { virtual ~IConnection() {}

    // записать событие в сеанс
    virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const = 0; 
    // записать событие в сеанс
    virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const = 0; 

    // записать событие в сеанс
    virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const = 0; 
    // записать событие в сеанс
    virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Провайдер трассировки WMI
///////////////////////////////////////////////////////////////////////////////
class Provider : public ETW::IProvider
{
    // описатель и идентификатор провайдера
    private: TRACEHANDLE _hProvider; GUID _guid; 
    // описатель сеанса и параметры трассировки
    private: TRACEHANDLE _hLogger; UCHAR _level; ULONG _flags; 

    // конструктор
    public: Provider(const GUID& guid, const GUID* pCategories, size_t cntCategories); 
    // деструктор
    public: virtual ~Provider() { ::UnregisterTraceGuids(_hProvider); }

    // идентификатор провайдера
    public: virtual const GUID& ID() const override { return _guid; } 

    // соединение с сеансом
    public: TRACEHANDLE LoggerHandle() const { return _hLogger; } 

    // уровень важности и категории событий
    public: UCHAR Level() const { return _level; }
    public: ULONG Flags() const { return _flags; }

    // обработка уведомлений провайдеру
    public: void Enable(TRACEHANDLE hLogger, UCHAR level, ULONG flags) 
    {
        // обработать уведомление
        OnEnable(hLogger, level, flags); 

        // сохранить переданные параметры
        _hLogger = hLogger; _level = level; _flags = flags; 
    } 
    // обработка уведомлений провайдеру
    public: void Disable(TRACEHANDLE hLogger) 
    {
        // обработать уведомление
        OnDisable(hLogger); _hLogger = 0; _level = 0; _flags = 0; 
    } 
    // обработка уведомлений провайдеру
    protected: virtual void OnEnable(TRACEHANDLE, UCHAR, ULONG) {} 
    // обработка уведомлений провайдеру
    protected: virtual void OnDisable(TRACEHANDLE) {} 
};
}

namespace Manifest 
{
///////////////////////////////////////////////////////////////////////////////
// Провайдер трассировки с использованием манифеста
///////////////////////////////////////////////////////////////////////////////
class Provider : public ETW::IProvider
{
    // описатель и идентификатор провайдера
    private: REGHANDLE _hProvider; GUID _guid; 

    // конструктор
    public: Provider(const GUID& guid); 
    // деструктор
    public: virtual ~Provider() { ::EventUnregister(_hProvider); }

    // идентификатор провайдера
    public: virtual const GUID& ID() const override { return _guid; } 

    // обработка уведомлений провайдеру
    public: virtual void EnableCallback(const GUID&, UCHAR, ULONGLONG, ULONGLONG, PEVENT_FILTER_DESCRIPTOR) {}
    // обработка уведомлений провайдеру
    public: virtual void DisableCallback(const GUID&) {}
};
}
