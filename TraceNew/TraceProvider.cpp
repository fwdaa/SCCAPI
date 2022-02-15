#include "TraceProvider.hpp"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Системные события. Для сокращения кодирования групп битов из маски 
// PERFINFO_GROUPMASK используется укороченный 32-битный формат PERF_*, в 
// котором старшие три бита кодируют номер слова в маске PERFINFO_GROUPMASK, 
// а оставшиеся 29 битов - биты указанного слова. Таким образом, можно 
// адресовать (29 * 8) = 232 бита. 
///////////////////////////////////////////////////////////////////////////////
#define PERF_PROCESS	        0x00000001	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_GENERAL
#define PERF_THREAD	            0x00000002	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_THREAD
#define PERF_LOADER	            0x00000004	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_LOADER
#define PERF_PERF_COUNTER	    0x00000008	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_PERF_COUNTER
// 	                            0x00000100	// SystemIoProviderGuid             SYSTEM_IO_KW_DISK
#define PERF_FILENAME	        0x00000200	// SystemIoProviderGuid             SYSTEM_IO_KW_FILENAME
#define PERF_DISK_IO_INIT	    0x00000400	// SystemIoProviderGuid             SYSTEM_IO_KW_DISK_INIT
#define PERF_ALL_FAULTS	        0x00001000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_ALL_FAULTS
#define PERF_HARD_FAULTS	    0x00002000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_HARD_FAULTS
#define PERF_VAMAP	            0x00008000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_VAMAP
#define PERF_NETWORK	        0x00010000	// SystemIoProviderGuid             SYSTEM_IO_KW_NETWORK
#define PERF_REGISTRY	        0x00020000	// SystemRegistryProviderGuid       SYSTEM_REGISTRY_KW_GENERAL
#define PERF_DBGPRINT	        0x00040000	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_DBGPRINT
#define PERF_JOB	            0x00080000	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_JOB
#define PERF_ALPC	            0x00100000	// SystemAlpcProviderGuid           SYSTEM_ALPC_KW_GENERAL
#define PERF_SPLIT_IO	        0x00200000	// SystemIoProviderGuid             SYSTEM_IO_KW_SPLIT
#define PERF_DEBUG_EVENTS	    0x00400000	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_DEBUG_EVENTS
#define PERF_FILE_IO	        0x02000000	// SystemIoProviderGuid             SYSTEM_IO_KW_FILE
#define PERF_FILE_IO_INIT	    0x04000000	// 
#define PERF_NO_SYSCONFIG	    0x10000000	// 
#define PERF_MEMORY	            0x20000001	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_GENERAL
#define PERF_PROFILE	        0x20000002	// SystemProfileProviderGuid        SYSTEM_PROFILE_KW_GENERAL  
#define PERF_CONTEXT_SWITCH	    0x20000004	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH
#define PERF_FOOTPRINT	        0x20000008	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_FOOTPRINT
#define PERF_DRIVERS	        0x20000010	// SystemIoProviderGuid             SYSTEM_IO_KW_DRIVERS
#define PERF_REFSET	            0x20000020	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_REFSET
#define PERF_POOL	            0x20000040	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_POOL
#define PERF_DPC	            0x20000080	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_DPC
#define PERF_COMPACT_CSWITCH	0x20000100	//
#define PERF_DISPATCHER	        0x20000200	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_DISPATCHER
#define PERF_PMC_PROFILE	    0x20000400	// SystemProfileProviderGuid        SYSTEM_PROFILE_KW_PMC_PROFILE
#define PERF_PROCESS_INSWAP	    0x20000800	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_INSWAP
#define PERF_AFFINITY	        0x20001000	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_AFFINITY
#define PERF_PRIORITY	        0x20002000	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_PRIORITY
#define PERF_INTERRUPT	        0x20004000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_GENERAL
#define PERF_VIRTUAL_ALLOC      0x20008000	// SystemMemoryProviderGuid	        SYSTEM_MEMORY_KW_VIRTUAL_ALLOC
#define PERF_SPINLOCK	        0x20010000	// SystemLockProviderGuid           SYSTEM_LOCK_KW_SPINLOCK
#define PERF_SYNC_OBJECTS	    0x20020000	// SystemLockProviderGuid           SYSTEM_LOCK_KW_SYNC_OBJECTS
#define PERF_DPC_QUEUE	        0x20040000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_DPC_QUEUE
#define PERF_MEMINFO	        0x20080000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_MEMINFO
#define PERF_CONTMEM_GEN	    0x20100000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_CONTMEM_GEN
#define PERF_SPINLOCK_CNTRS	    0x20200000	// SystemLockProviderGuid           SYSTEM_LOCK_KW_SPINLOCK_COUNTERS
#define PERF_SECTION            0x20400000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_SESSION
#define PERF_PFSECTION          0x20400000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_PFSECTION
#define PERF_MEMINFO_WS	        0x20800000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_MEMINFO_WS
#define PERF_KERNEL_QUEUE	    0x21000000	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_KERNEL_QUEUE
#define PERF_INTERRUPT_STEER	0x22000000	// 
#define PERF_SHOULD_YIELD	    0x24000000	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_SHOULD_YIELD
#define PERF_WS	                0x28000000	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_WS
#define PERF_ANTI_STARVATION    0x40000001	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_ANTI_STARVATION
#define PERF_PROCESS_FREEZE     0x40000002	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_FREEZE
#define PERF_PFN_LIST	        0x40000004	//
#define PERF_WS_DETAIL	        0x40000008	//
#define PERF_WS_ENTRY	        0x40000010	//
#define PERF_HEAP	            0x40000020	// SystemMemoryProviderGuid         SYSTEM_MEMORY_KW_HEAP
#define PERF_SYSCALL	        0x40000040  // SystemSyscallProviderGuid        SYSTEM_SYSCALL_KW_GENERAL
#define PERF_UMS	            0x40000080	//
#define PERF_BACKTRACE	        0x40000100	//
#define PERF_VULCAN	            0x40000200	//
#define PERF_OBJECTS	        0x40000400	//
#define PERF_EVENTS	            0x40000800	//
#define PERF_FULLTRACE	        0x40001000	//
#define PERF_DFSS	            0x40002000	//
#define PERF_PREFETCH	        0x40004000	//
#define PERF_PROCESSOR_IDLE	    0x40008000	// SystemPowerProviderGuid          SYSTEM_POWER_KW_PROCESSOR_IDLE
#define PERF_CPU_CONFIG	        0x40010000	// SystemCpuProviderGuid            SYSTEM_CPU_KW_CONFIG
#define PERF_TIMER	            0x40020000	// SystemTimerProviderGuid          SYSTEM_TIMER_KW_GENERAL
#define PERF_CLOCK_INTERRUPT	0x40040000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_CLOCK_INTERRUPT
#define PERF_LOAD_BALANCER	    0x40080000	// SystemSchedulerProviderGuid      SYSTEM_SCHEDULER_KW_LOAD_BALANCER
#define PERF_CLOCK_TIMER	    0x40100000	// SystemTimerProviderGuid          SYSTEM_TIMER_KW_CLOCK_TIMER
#define PERF_IDLE_SELECTION	    0x40200000	// SystemPowerProviderGuid          SYSTEM_POWER_KW_IDLE_SELECTION
#define PERF_IPI	            0x40400000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_IPI
#define PERF_IO_TIMER	        0x40800000	//
#define PERF_REG_HIVE	        0x41000000	// SystemRegistryProviderGuid       SYSTEM_REGISTRY_KW_HIVE
#define PERF_REG_NOTIF	        0x42000000	// SystemRegistryProviderGuid       SYSTEM_REGISTRY_KW_NOTIFICATION
#define PERF_PPM_EXIT_LATENCY	0x44000000	// SystemPowerProviderGuid          SYSTEM_POWER_KW_PPM_EXIT_LATENCY
#define PERF_WORKER_THREAD	    0x48000000	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_WORKER_THREAD
#define PERF_OPTICAL_IO	        0x80000001	// SystemIoProviderGuid             SYSTEM_IO_KW_OPTICAL
#define PERF_OPTICAL_IO_INIT	0x80000002	// SystemIoProviderGuid             SYSTEM_IO_KW_OPTICAL_INIT
#define PERF_DLL_INFO	        0x80000008	//
#define PERF_DLL_FLUSH_WS	    0x80000010	//
#define PERF_OB_HANDLE	        0x80000040	// SystemObjectProviderGuid         SYSTEM_OBJECT_KW_HANDLE
#define PERF_OB_OBJECT	        0x80000080	// SystemObjectProviderGuid         SYSTEM_OBJECT_KW_OBJECT
#define PERF_WAKE_DROP	        0x80000200	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_WAKE_DROP
#define PERF_WAKE_EVENT	        0x80000400	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_WAKE_EVENT
#define PERF_DEBUGGER	        0x80000800	//
#define PERF_PROC_ATTACH	    0x80001000	//
#define PERF_WAKE_COUNTER	    0x80002000	// SystemProcessProviderGuid        SYSTEM_PROCESS_KW_WAKE_COUNTER
#define PERF_POWER	            0x80008000	// SystemPowerProviderGuid          SYSTEM_POWER_KW_GENERAL
#define PERF_SOFT_TRIM	        0x80010000	//
#define PERF_CC	                0x80020000	// SystemIoProviderGuid             SYSTEM_IO_KW_CC
#define PERF_FLT_IO_INIT	    0x80080000	// SystemIoFilterProviderGuid       SYSTEM_IOFILTER_KW_INIT
#define PERF_FLT_IO	            0x80100000	// SystemIoFilterProviderGuid       SYSTEM_IOFILTER_KW_GENERAL
#define PERF_FLT_FASTIO	        0x80200000	// SystemIoFilterProviderGuid       SYSTEM_IOFILTER_KW_FASTIO
#define PERF_FLT_IO_FAILURE	    0x80400000	// SystemIoFilterProviderGuid       SYSTEM_IOFILTER_KW_FAILURE
#define PERF_HV_PROFILE	        0x80800000	// SystemHypervisorProviderGuid     SYSTEM_HYPERVISOR_KW_PROFILE	
#define PERF_WDF_DPC	        0x81000000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_WDF_DPC
#define PERF_WDF_INTERRUPT	    0x82000000	// SystemInterruptProviderGuid      SYSTEM_INTERRUPT_KW_WDF_INTERRUPT
#define PERF_CACHE_FLUSH	    0x84000000	// SystemCpuProviderGuid            SYSTEM_CPU_KW_CACHE_FLUSH
#define PERF_HIBER_RUNDOWN      0xA0000001	// SystemPowerProviderGuid          SYSTEM_POWER_KW_HIBER_RUNDOWN
#define PERF_SYSCFG_SYSTEM      0xC0000001	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_SYSTEM		   
#define PERF_SYSCFG_GRAPHICS    0xC0000002	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_GRAPHICS	
#define PERF_SYSCFG_STORAGE     0xC0000004	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_STORAGE	
#define PERF_SYSCFG_NETWORK     0xC0000008	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_NETWORK	
#define PERF_SYSCFG_SERVICES    0xC0000010	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_SERVICES	
#define PERF_SYSCFG_PNP         0xC0000020	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_PNP	    
#define PERF_SYSCFG_OPTICAL     0xC0000040	// SystemConfigProviderGuid         SYSTEM_CONFIG_KW_OPTICAL	
#define PERF_CLUSTER_OFF	    0xE0000001	//
#define PERF_MEMORY_CONTROL	    0xE0000002	//

///////////////////////////////////////////////////////////////////////////////
// При использовании системного провайдера в ETW ему передается маска 
// EnableFlags из 32 битов, которая покрывает только отдельные события 
// PERFINFO_GROUPMASK. Таблица соответствия битов в PERFINFO_GROUPMASK и 
// битов EnableFlags ETW приведена ниже
///////////////////////////////////////////////////////////////////////////////
static ULONG Perf2LegacyMap[256] = {
    EVENT_TRACE_FLAG_PROCESS,               // PERF_PROCESS	         
    EVENT_TRACE_FLAG_THREAD,                // PERF_THREAD	     
    EVENT_TRACE_FLAG_IMAGE_LOAD,            // PERF_LOADER	     
    EVENT_TRACE_FLAG_PROCESS_COUNTERS,      // PERF_PERF_COUNTER
    0, /* EVENT_TRACE_FLAG_CSWITCH */       // 
    0, /* EVENT_TRACE_FLAG_DPC */           // 
    0, /* EVENT_TRACE_FLAG_INTERRUPT */     // 
    0, /* EVENT_TRACE_FLAG_SYSTEMCALL*/     // 
    EVENT_TRACE_FLAG_DISK_IO,               // 0x00000100
    EVENT_TRACE_FLAG_DISK_FILE_IO,          // PERF_FILENAME	 
    EVENT_TRACE_FLAG_DISK_IO_INIT,          // PERF_DISK_IO_INIT
    0, /* EVENT_TRACE_FLAG_DISPATCHER */    // 
    EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS,    // PERF_ALL_FAULTS	
    EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS,    // PERF_HARD_FAULTS
    0, /* EVENT_TRACE_FLAG_VIRTUAL_ALLOC */ // 
    EVENT_TRACE_FLAG_VAMAP,                 // PERF_VAMAP	     
    EVENT_TRACE_FLAG_NETWORK_TCPIP,         // PERF_NETWORK	 
    EVENT_TRACE_FLAG_REGISTRY,              // PERF_REGISTRY	    
    EVENT_TRACE_FLAG_DBGPRINT,              // PERF_DBGPRINT	    
    EVENT_TRACE_FLAG_JOB,                   // PERF_JOB	       
    EVENT_TRACE_FLAG_ALPC,                  // PERF_ALPC	        
    EVENT_TRACE_FLAG_SPLIT_IO,              // PERF_SPLIT_IO	   
    EVENT_TRACE_FLAG_DEBUG_EVENTS,          // PERF_DEBUG_EVENTS   
    0, /* EVENT_TRACE_FLAG_DRIVER */        // 
    0, /* EVENT_TRACE_FLAG_PROFILE */       // 
    EVENT_TRACE_FLAG_FILE_IO,               // PERF_FILE_IO	   
    EVENT_TRACE_FLAG_FILE_IO_INIT,          // PERF_FILE_IO_INIT
    0,                                      // 
    EVENT_TRACE_FLAG_NO_SYSCONFIG,          // PERF_NO_SYSCONFIG
    0, /* EVENT_TRACE_FLAG_ENABLE_RESERVE */// 
    0, /* EVENT_TRACE_FLAG_FORWARD_WMI */   // 
    0, /* EVENT_TRACE_FLAG_EXTENSION */     // 
    0,                                      // PERF_MEMORY
    EVENT_TRACE_FLAG_PROFILE,               // PERF_PROFILE
    EVENT_TRACE_FLAG_CSWITCH,               // PERF_CONTEXT_SWITCH
    0,                                      // PERF_FOOTPRINT	       
    EVENT_TRACE_FLAG_DRIVER,                // PERF_DRIVERS	    
    0,                                      // PERF_REFSET	           
    0,                                      // PERF_POOL	           
    EVENT_TRACE_FLAG_DPC,                   // PERF_DPC	        
    0,                                      // PERF_COMPACT_CSWITCH
    EVENT_TRACE_FLAG_DISPATCHER,            // PERF_DISPATCHER	    
    0,                                      // PERF_PMC_PROFILE	   
    0,                                      // PERF_PROCESS_INSWAP	   
    0,                                      // PERF_AFFINITY	       
    0,                                      // PERF_PRIORITY	       
    EVENT_TRACE_FLAG_INTERRUPT,             // PERF_INTERRUPT	    
    EVENT_TRACE_FLAG_VIRTUAL_ALLOC,         // PERF_VIRTUAL_ALLOC    
    0,                                      // PERF_SPINLOCK	        
    0,                                      // PERF_SYNC_OBJECTS	    
    0,                                      // PERF_DPC_QUEUE	        
    0,                                      // PERF_MEMINFO	        
    0,                                      // PERF_CONTMEM_GEN	    
    0,                                      // PERF_SPINLOCK_CNTRS	    
    0,                                      // PERF_SECTION            
    0,                                      // PERF_PFSECTION          
    0,                                      // PERF_MEMINFO_WS	        
    0,                                      // PERF_KERNEL_QUEUE	    
    0,                                      // PERF_INTERRUPT_STEER
    0,                                      // PERF_SHOULD_YIELD	    
    0,                                      // PERF_WS	                
    0,                                      // 
    0,                                      // 
    0,                                      // 
    0,                                      // 
    0,                                      // PERF_ANTI_STARVATION    
    0,                                      // PERF_PROCESS_FREEZE     
    0,                                      // PERF_PFN_LIST	    
    0,                                      // PERF_WS_DETAIL	    
    0,                                      // PERF_WS_ENTRY	    
    0,                                      // PERF_HEAP	        
    EVENT_TRACE_FLAG_SYSTEMCALL             // PERF_SYSCALL	    
}; 

///////////////////////////////////////////////////////////////////////////////
// Преобразовать PERFINFO_GROUPMASK в ETW-маску EnableFlags 
///////////////////////////////////////////////////////////////////////////////
ULONG ETW::GetSystemLegacyEnableFlags(CONST DWORD* pMasks, ULONG cntMasks)
{
    ULONG enableFlags = 0; 

    // для всех слов маски 
    for (ULONG i = 0; i < cntMasks; i++)
    {
        // для всех битов слова
        for (ULONG j = 0; j < sizeof(ULONG) * 8; j++)
        {
            // проверить наличие бита в маске
            if ((pMasks[i] & (1UL << j)) != 0)
            {
                // указать соответствующий бит
                enableFlags |= Perf2LegacyMap[32 * i + j]; 
            }
        }
    }
    return enableFlags; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразовать 32-битную маску отдельного провайдера в PERFINFO_GROUPMASK
///////////////////////////////////////////////////////////////////////////////
static ETW::PERFINFO_GROUPMASK GetGroupMask(ULONG mask, const ULONG* pMap, ULONG cntMap)
{
    ETW::PERFINFO_GROUPMASK groupMask = {0}; 

    // для всех элементов таблицы соответствия
    for (ULONG i = 0; i < cntMap; i++, mask >>= 1)
    {
        // проверить наличия бита в маске
        if ((mask & 0x1) == 0) continue; 

        // установить соответствующий бит 
        groupMask.Masks[pMap[i] >> 29] |= (pMap[i] & 0x1FFFFFFF); 
    }
    return groupMask; 
}

///////////////////////////////////////////////////////////////////////////////
// System ALPC Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemAlpcProviderGuid = { 
    0xfcb9baaf, 0xe529, 0x4980, { 0x92, 0xe9, 0xce, 0xd1, 0xa6, 0xaa, 0xdf, 0xdf } 
};
static ETW::PERFINFO_GROUPMASK GetSystemAlpcProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG AlpcProviderMap[] = { 
        PERF_ALPC               // SYSTEM_ALPC_KW_GENERAL
    };
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x1, AlpcProviderMap, _countof(AlpcProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Config Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemConfigProviderGuid = { 
    0xfef3a8b6, 0x318d, 0x4b67, { 0xa9, 0x6a, 0x3b, 0x0f, 0x6b, 0x8f, 0x18, 0xfe } 
};
static ETW::PERFINFO_GROUPMASK GetSystemConfigProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG ConfigProviderMap[] = { 
        PERF_SYSCFG_SYSTEM,      // SYSTEM_CONFIG_KW_SYSTEM	  
        PERF_SYSCFG_GRAPHICS,    // SYSTEM_CONFIG_KW_GRAPHICS	
        PERF_SYSCFG_STORAGE,     // SYSTEM_CONFIG_KW_STORAGE	  
        PERF_SYSCFG_NETWORK,     // SYSTEM_CONFIG_KW_NETWORK	  
        PERF_SYSCFG_SERVICES,    // SYSTEM_CONFIG_KW_SERVICES	
        PERF_SYSCFG_PNP,         // SYSTEM_CONFIG_KW_PNP	      
        PERF_SYSCFG_OPTICAL      // SYSTEM_CONFIG_KW_OPTICAL	  
    };
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x7F, ConfigProviderMap, _countof(ConfigProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System CPU Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemCpuProviderGuid = { 
    0xc6c5265f, 0xeae8, 0x4650, { 0xaa, 0xe4, 0x9d, 0x48, 0x60, 0x3d, 0x85, 0x10 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemCpuProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG CpuProviderMap[] = { 
        PERF_CPU_CONFIG,        // SYSTEM_CPU_KW_CONFIG	                
        PERF_CACHE_FLUSH,       // SYSTEM_CPU_KW_CACHE_FLUSH	            
        0                       // SYSTEM_CPU_KW_SPEC_CONTROL	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x07, CpuProviderMap, _countof(CpuProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Hypervisor Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemHypervisorProviderGuid = { 
    0xbafa072a, 0x918a, 0x4bed, { 0xb6, 0x22, 0xbc, 0x15, 0x20, 0x97, 0x09, 0x8f } 
};
static ETW::PERFINFO_GROUPMASK GetSystemHypervisorProviderGroupMask(ULONG mask)
{
    // соответствие битов маски провайдера
    static const ULONG HypervisorProviderMap[] = { 
        PERF_HV_PROFILE,        // SYSTEM_HYPERVISOR_KW_PROFILE	        
        0,                      // SYSTEM_HYPERVISOR_KW_CALLOUTS	        
        0                       // SYSTEM_HYPERVISOR_KW_VTL_CHANGE	        
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x07, HypervisorProviderMap, _countof(HypervisorProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Interrupt Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemInterruptProviderGuid = { 
    0xd4bbee17, 0xb545, 0x4888, { 0x85, 0x8b, 0x74, 0x41, 0x69, 0x01, 0x5b, 0x25 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemInterruptProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG InterruptProviderMap[] = { 
        PERF_INTERRUPT,         // SYSTEM_INTERRUPT_KW_GENERAL	            
        PERF_CLOCK_INTERRUPT,   // SYSTEM_INTERRUPT_KW_CLOCK_INTERRUPT	    
        PERF_DPC,               // SYSTEM_INTERRUPT_KW_DPC	                
        PERF_DPC_QUEUE,         // SYSTEM_INTERRUPT_KW_DPC_QUEUE	        
        PERF_WDF_DPC,           // SYSTEM_INTERRUPT_KW_WDF_DPC	            
        PERF_WDF_INTERRUPT,     // SYSTEM_INTERRUPT_KW_WDF_INTERRUPT	    
        PERF_IPI                // SYSTEM_INTERRUPT_KW_IPI	                
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x7F, InterruptProviderMap, _countof(InterruptProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System IO Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemIoProviderGuid = { 
    0x3d5c43e3, 0x0f1c, 0x4202, { 0xb8, 0x17, 0x17, 0x4c, 0x00, 0x70, 0xdc, 0x79 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemIoProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG IoProviderMap[] = { 
        0x00000100,             // SYSTEM_IO_KW_DISK	                    
        PERF_DISK_IO_INIT,      // SYSTEM_IO_KW_DISK_INIT	                
        PERF_FILENAME,          // SYSTEM_IO_KW_FILENAME	                
        PERF_SPLIT_IO,          // SYSTEM_IO_KW_SPLIT	                    
        PERF_FILE_IO,           // SYSTEM_IO_KW_FILE	                    
        PERF_OPTICAL_IO,        // SYSTEM_IO_KW_OPTICAL	                
        PERF_OPTICAL_IO_INIT,   // SYSTEM_IO_KW_OPTICAL_INIT	            
        PERF_DRIVERS,           // SYSTEM_IO_KW_DRIVERS	                
        PERF_CC,                // SYSTEM_IO_KW_CC	                        
        PERF_NETWORK            // SYSTEM_IO_KW_NETWORK	                
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x3FF, IoProviderMap, _countof(IoProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System IO Filter Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemIoFilterProviderGuid = { 
    0xfbd09363, 0x9e22, 0x4661, { 0xb8, 0xbf, 0xe7, 0xa3, 0x4b, 0x53, 0x5b, 0x8c } 
};
static ETW::PERFINFO_GROUPMASK GetSystemIoFilterProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG IoFilterProviderMap[] = { 
        PERF_FLT_IO,            // SYSTEM_IOFILTER_KW_GENERAL	            
        PERF_FLT_IO_INIT,       // SYSTEM_IOFILTER_KW_INIT	                
        PERF_FLT_FASTIO,        // SYSTEM_IOFILTER_KW_FASTIO	            
        PERF_FLT_IO_FAILURE     // SYSTEM_IOFILTER_KW_FAILURE	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x0F, IoFilterProviderMap, _countof(IoFilterProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Lock Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemLockProviderGuid = { 
    0x721ddfd3, 0xdacc, 0x4e1e, { 0xb2, 0x6a, 0xa2, 0xcb, 0x31, 0xd4, 0x70, 0x5a } 
};
static ETW::PERFINFO_GROUPMASK GetSystemLockProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG LockProviderMap[] = { 
        PERF_SPINLOCK,          // SYSTEM_LOCK_KW_SPINLOCK	                
        PERF_SPINLOCK_CNTRS,    // SYSTEM_LOCK_KW_SPINLOCK_COUNTERS	    
        PERF_SYNC_OBJECTS       // SYSTEM_LOCK_KW_SYNC_OBJECTS	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x07, LockProviderMap, _countof(LockProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Memory Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemMemoryProviderGuid = { 
    0x82958ca9, 0xb6cd, 0x47f8, { 0xa3, 0xa8, 0x03, 0xae, 0x85, 0xa4, 0xbc, 0x24 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemMemoryProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG MemoryProviderMap[] = { 
        PERF_MEMORY,            // SYSTEM_MEMORY_KW_GENERAL	      
        PERF_HARD_FAULTS,       // SYSTEM_MEMORY_KW_HARD_FAULTS	  
        PERF_ALL_FAULTS,        // SYSTEM_MEMORY_KW_ALL_FAULTS	  
        PERF_POOL,              // SYSTEM_MEMORY_KW_POOL	      
        PERF_MEMINFO,           // SYSTEM_MEMORY_KW_MEMINFO	      
        PERF_PFSECTION,         // SYSTEM_MEMORY_KW_PFSECTION	  
        PERF_MEMINFO_WS,        // SYSTEM_MEMORY_KW_MEMINFO_WS	  
        PERF_HEAP,              // SYSTEM_MEMORY_KW_HEAP	      
        PERF_WS,                // SYSTEM_MEMORY_KW_WS	          
        PERF_CONTMEM_GEN,       // SYSTEM_MEMORY_KW_CONTMEM_GEN	  
        PERF_VIRTUAL_ALLOC,     // SYSTEM_MEMORY_KW_VIRTUAL_ALLOC
        PERF_FOOTPRINT,         // SYSTEM_MEMORY_KW_FOOTPRINT	  
        PERF_SECTION,           // SYSTEM_MEMORY_KW_SESSION	      
        PERF_REFSET,            // SYSTEM_MEMORY_KW_REFSET	      
        PERF_VAMAP              // SYSTEM_MEMORY_KW_VAMAP	      
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x7FFF, MemoryProviderMap, _countof(MemoryProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Object Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemObjectProviderGuid = { 
    0xfebd7460, 0x3d1d, 0x47eb, { 0xaf, 0x49, 0xc9, 0xee, 0xb1, 0xe1, 0x46, 0xf2 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemObjectProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG ObjectProviderMap[] = { 
        PERF_OB_HANDLE,         // SYSTEM_OBJECT_KW_HANDLE	                
        PERF_OB_OBJECT          // SYSTEM_OBJECT_KW_OBJECT	                
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x03, ObjectProviderMap, _countof(ObjectProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Power Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemPowerProviderGuid = { 
    0xc134884a, 0x32d5, 0x4488, { 0x80, 0xe5, 0x14, 0xed, 0x7a, 0xbb, 0x82, 0x69 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemPowerProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG PowerProviderMap[] = { 
        PERF_POWER,             // SYSTEM_POWER_KW_GENERAL	                
        PERF_HIBER_RUNDOWN,     // SYSTEM_POWER_KW_HIBER_RUNDOWN	        
        PERF_PROCESSOR_IDLE,    // SYSTEM_POWER_KW_PROCESSOR_IDLE	        
        PERF_IDLE_SELECTION,    // SYSTEM_POWER_KW_IDLE_SELECTION	        
        PERF_PPM_EXIT_LATENCY   // SYSTEM_POWER_KW_PPM_EXIT_LATENCY	    
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x1F, PowerProviderMap, _countof(PowerProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Process Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemProcessProviderGuid = { 
    0x151f55dc, 0x467d, 0x471f, { 0x83, 0xb5, 0x5f, 0x88, 0x9d, 0x46, 0xff, 0x66 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemProcessProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG ProcessProviderMap[] = { 
        PERF_PROCESS,           // SYSTEM_PROCESS_KW_GENERAL	            
        PERF_PROCESS_INSWAP,    // SYSTEM_PROCESS_KW_INSWAP	            
        PERF_PROCESS_FREEZE,    // SYSTEM_PROCESS_KW_FREEZE	            
        PERF_PERF_COUNTER,      // SYSTEM_PROCESS_KW_PERF_COUNTER	        
        PERF_WAKE_COUNTER,      // SYSTEM_PROCESS_KW_WAKE_COUNTER	        
        PERF_WAKE_DROP,         // SYSTEM_PROCESS_KW_WAKE_DROP	            
        PERF_WAKE_EVENT,        // SYSTEM_PROCESS_KW_WAKE_EVENT	        
        PERF_DEBUG_EVENTS,      // SYSTEM_PROCESS_KW_DEBUG_EVENTS	        
        PERF_DBGPRINT,          // SYSTEM_PROCESS_KW_DBGPRINT	            
        PERF_JOB,               // SYSTEM_PROCESS_KW_JOB	                
        PERF_WORKER_THREAD,     // SYSTEM_PROCESS_KW_WORKER_THREAD	        
        PERF_THREAD,            // SYSTEM_PROCESS_KW_THREAD	            
        PERF_LOADER             // SYSTEM_PROCESS_KW_LOADER	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x1FFF, ProcessProviderMap, _countof(ProcessProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Profile Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemProfileProviderGuid = { 
    0xbfeb0324, 0x1cee, 0x496f, { 0xa4, 0x09, 0x2a, 0xc2, 0xb4, 0x8a, 0x63, 0x22 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemProfileProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG ProfileProviderMap[] = { 
        PERF_PROFILE,           // SYSTEM_PROFILE_KW_GENERAL	            
        PERF_PMC_PROFILE        // SYSTEM_PROFILE_KW_PMC_PROFILE	        
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x03, ProfileProviderMap, _countof(ProfileProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Registry Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemRegistryProviderGuid = { 
    0x16156bd9, 0xfab4, 0x4cfa, { 0xa2, 0x32, 0x89, 0xd1, 0x09, 0x90, 0x58, 0xe3 } 
};
static ETW::PERFINFO_GROUPMASK GetSystemRegistryProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG RegistryProviderMap[] = { 
        PERF_REGISTRY,          // SYSTEM_REGISTRY_KW_GENERAL	            
        PERF_REG_HIVE,          // SYSTEM_REGISTRY_KW_HIVE	                
        PERF_REG_NOTIF          // SYSTEM_REGISTRY_KW_NOTIFICATION	        
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x07, RegistryProviderMap, _countof(RegistryProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Scheduler Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemSchedulerProviderGuid = { 
    0x599a2a76, 0x4d91, 0x4910, { 0x9a, 0xc7, 0x7d, 0x33, 0xf2, 0xe9, 0x7a, 0x6c } 
};
static ETW::PERFINFO_GROUPMASK GetSystemSchedulerProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG SchedulerProviderMap[] = { 
        0,                      // SYSTEM_SCHEDULER_KW_XSCHEDULER	        
        PERF_DISPATCHER,        // SYSTEM_SCHEDULER_KW_DISPATCHER	        
        PERF_KERNEL_QUEUE,      // SYSTEM_SCHEDULER_KW_KERNEL_QUEUE	    
        PERF_SHOULD_YIELD,      // SYSTEM_SCHEDULER_KW_SHOULD_YIELD	    
        PERF_ANTI_STARVATION,   // SYSTEM_SCHEDULER_KW_ANTI_STARVATION	    
        PERF_LOAD_BALANCER,     // SYSTEM_SCHEDULER_KW_LOAD_BALANCER	    
        PERF_AFFINITY,          // SYSTEM_SCHEDULER_KW_AFFINITY	        
        PERF_PRIORITY,          // SYSTEM_SCHEDULER_KW_PRIORITY	        
        0,                      // SYSTEM_SCHEDULER_KW_IDEAL_PROCESSOR	    
        PERF_CONTEXT_SWITCH,    // SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH	    
    };
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x3FF, SchedulerProviderMap, _countof(SchedulerProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Syscall Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemSyscallProviderGuid = { 
    0x434286f7, 0x6f1b, 0x45bb, { 0xb3, 0x7e, 0x95, 0xf6, 0x23, 0x04, 0x6c, 0x7c } 
};
static ETW::PERFINFO_GROUPMASK GetSystemSyscallProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG SyscallProviderMap[] = { 
        PERF_SYSCALL            // SYSTEM_SYSCALL_KW_GENERAL	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x01, SyscallProviderMap, _countof(SyscallProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// System Timer Provider
///////////////////////////////////////////////////////////////////////////////
extern const GUID SystemTimerProviderGuid = { 
    0x4f061568, 0xe215, 0x499f, { 0xab, 0x2e, 0xed, 0xa0, 0xae, 0x89, 0x0a, 0x5b } 
};
static ETW::PERFINFO_GROUPMASK GetSystemTimerProviderGroupMask(ULONG mask = 0)
{
    // соответствие битов маски провайдера
    static const ULONG TimerProviderMap[] = { 
        PERF_TIMER,             // SYSTEM_TIMER_KW_GENERAL	                
        PERF_CLOCK_TIMER        // SYSTEM_TIMER_KW_CLOCK_TIMER	            
    }; 
    // преобразовать маску провайдера
    return GetGroupMask(mask ? mask : 0x03, TimerProviderMap, _countof(TimerProviderMap)); 
}
///////////////////////////////////////////////////////////////////////////////
// Объединение системных провайдеров
///////////////////////////////////////////////////////////////////////////////
ETW::PERFINFO_GROUPMASK ETW::GetSystemTraceEnableFlags(const GUID& guid, ULONG mask)
{
    // для системных провайдеров
    if (InlineIsEqualGUID(guid, SystemProcessProviderGuid   )) return GetSystemProcessProviderGroupMask     (mask); 
    if (InlineIsEqualGUID(guid, SystemIoProviderGuid        )) return GetSystemIoProviderGroupMask          (mask); 
    if (InlineIsEqualGUID(guid, SystemMemoryProviderGuid    )) return GetSystemMemoryProviderGroupMask      (mask); 
    if (InlineIsEqualGUID(guid, SystemSchedulerProviderGuid )) return GetSystemSchedulerProviderGroupMask   (mask); 
    if (InlineIsEqualGUID(guid, SystemInterruptProviderGuid )) return GetSystemInterruptProviderGroupMask   (mask); 
    if (InlineIsEqualGUID(guid, SystemRegistryProviderGuid  )) return GetSystemRegistryProviderGroupMask    (mask); 
    if (InlineIsEqualGUID(guid, SystemProfileProviderGuid   )) return GetSystemProfileProviderGroupMask     (mask); 
    if (InlineIsEqualGUID(guid, SystemAlpcProviderGuid      )) return GetSystemAlpcProviderGroupMask        (mask); 
    if (InlineIsEqualGUID(guid, SystemSyscallProviderGuid   )) return GetSystemSyscallProviderGroupMask     (mask); 
    if (InlineIsEqualGUID(guid, SystemConfigProviderGuid    )) return GetSystemConfigProviderGroupMask      (mask); 
    if (InlineIsEqualGUID(guid, SystemPowerProviderGuid     )) return GetSystemPowerProviderGroupMask       (mask); 
    if (InlineIsEqualGUID(guid, SystemIoFilterProviderGuid  )) return GetSystemIoFilterProviderGroupMask    (mask); 
    if (InlineIsEqualGUID(guid, SystemCpuProviderGuid       )) return GetSystemCpuProviderGroupMask         (mask); 
    if (InlineIsEqualGUID(guid, SystemHypervisorProviderGuid)) return GetSystemHypervisorProviderGroupMask  (mask); 
    if (InlineIsEqualGUID(guid, SystemLockProviderGuid      )) return GetSystemLockProviderGroupMask        (mask); 
    if (InlineIsEqualGUID(guid, SystemObjectProviderGuid    )) return GetSystemObjectProviderGroupMask      (mask); 
    if (InlineIsEqualGUID(guid, SystemTimerProviderGuid     )) return GetSystemTimerProviderGroupMask       (mask); 
    
    return {0}; 
}

///////////////////////////////////////////////////////////////////////////////
// Категория событий
///////////////////////////////////////////////////////////////////////////////
EVENT_INSTANCE_INFO WMI::EventCategory::CreateInstanceID() const
{
    // создать уникальный идентификатор для события
    EVENT_INSTANCE_INFO instanceID; ULONG code = ::CreateTraceInstanceId(_hCategory, &instanceID); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); return instanceID; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Соединение с сеансом трассировки
///////////////////////////////////////////////////////////////////////////////
EVENT_INSTANCE_INFO WMI::Connection::WriteEvent(const EVENT_INSTANCE_INFO* pParentID, 
    const IEventCategory& category, USHORT categoryVersion, 
    UCHAR eventType, UCHAR level, const MOF_FIELD* pFields, size_t countFields) const
{
    // создать уникальный идентификатор сеанса
    EVENT_INSTANCE_INFO instanceID = category.CreateInstanceID(); 

    // определить требуемый размер буфера
    size_t cb = sizeof(EVENT_INSTANCE_HEADER) + countFields * sizeof(MOF_FIELD); 

    // выделить память требуемого размера
    if (cb > USHRT_MAX) ETW::Exception::Throw(E_INVALIDARG); std::vector<BYTE> buffer(cb, 0); 

    // выполнить преобразование типа
    PEVENT_INSTANCE_HEADER pEvent = (PEVENT_INSTANCE_HEADER)&buffer[0]; 

    // указать размер структуры и тип данных события
    pEvent->Size = (USHORT)cb; pEvent->Flags =  WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR; 

    // указать информацию о событии
    pEvent->Class.Version = categoryVersion; pEvent->Class.Type = eventType; pEvent->Class.Level = level;

    // скопировать массив полей события
    memcpy(pEvent + 1, pFields, countFields * sizeof(MOF_FIELD)); 

    // записать событие в сеанс
    ULONG code = ::TraceEventInstance(_hTrace, pEvent, &instanceID, (PEVENT_INSTANCE_INFO)pParentID); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); return instanceID; 
}

EVENT_INSTANCE_INFO WMI::Connection::WriteEvent(const EVENT_INSTANCE_INFO* pParentID, 
    const IEventCategory& category, USHORT categoryVersion, 
    UCHAR eventType, UCHAR level, const void* pvData, size_t cbData) const
{
    // создать уникальный идентификатор сеанса
    EVENT_INSTANCE_INFO instanceID = category.CreateInstanceID(); 

    // определить требуемый размер буфера
    size_t cb = sizeof(EVENT_INSTANCE_HEADER) + cbData; 

    // выделить память требуемого размера
    if (cb > USHRT_MAX) ETW::Exception::Throw(E_INVALIDARG); std::vector<BYTE> buffer(cb, 0); 

    // выполнить преобразование типа
    PEVENT_INSTANCE_HEADER pEvent = (PEVENT_INSTANCE_HEADER)&buffer[0]; 

    // указать размер структуры и тип данных события
    pEvent->Size = (USHORT)cb; pEvent->Flags =  WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR; 

    // указать информацию о событии
    pEvent->Class.Version = categoryVersion; pEvent->Class.Type = eventType; pEvent->Class.Level = level;

    // скопировать данные события
    memcpy(pEvent + 1, pvData, cbData); 

    // записать событие в сеанс
    ULONG code = ::TraceEventInstance(_hTrace, pEvent, &instanceID, (PEVENT_INSTANCE_INFO)pParentID); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); return instanceID; 
}

void WMI::Connection::WriteEvent(
    const IEventCategory& category, USHORT categoryVersion, 
    UCHAR eventType, UCHAR level, const MOF_FIELD* pFields, size_t countFields) const
{
    // определить требуемый размер буфера
    size_t cb = sizeof(EVENT_TRACE_HEADER) + countFields * sizeof(MOF_FIELD); 

    // выделить память требуемого размера
    if (cb > USHRT_MAX) ETW::Exception::Throw(E_INVALIDARG); std::vector<BYTE> buffer(cb, 0); 

    // выполнить преобразование типа
    PEVENT_TRACE_HEADER pEvent = (PEVENT_TRACE_HEADER)&buffer[0]; 

    // указать размер структуры и тип данных события
    pEvent->Size = (USHORT)cb; pEvent->Flags =  WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR; 

    // указать информацию о категории события
    pEvent->Guid = category.Guid(); pEvent->Class.Version = categoryVersion; 

    // указать тип события и уровень важности
    pEvent->Class.Type = eventType; pEvent->Class.Level = level; 

    // скопировать массив полей события
    memcpy(pEvent + 1, pFields, countFields * sizeof(MOF_FIELD)); 

    // записать событие в сеанс
    ULONG code = ::TraceEvent(_hTrace, pEvent); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
}
void WMI::Connection::WriteEvent(
    const IEventCategory& category, USHORT categoryVersion, 
    UCHAR eventType, UCHAR level, const void* pvData, size_t cbData) const
{
    // определить требуемый размер буфера
    size_t cb = sizeof(EVENT_TRACE_HEADER) + cbData; 

    // выделить память требуемого размера
    if (cb > USHRT_MAX) ETW::Exception::Throw(E_INVALIDARG); std::vector<BYTE> buffer(cb, 0); 

    // выполнить преобразование типа
    PEVENT_TRACE_HEADER pEvent = (PEVENT_TRACE_HEADER)&buffer[0]; 

    // указать размер структуры и тип данных события
    pEvent->Size = (USHORT)cb; pEvent->Flags = WNODE_FLAG_TRACED_GUID; 

    // указать информацию о категории события
    pEvent->Guid = category.Guid(); pEvent->Class.Version = categoryVersion; 

    // указать тип события и уровень важности
    pEvent->Class.Type = eventType; pEvent->Class.Level = level; 

    // скопировать данные события
    memcpy(pEvent + 1, pvData, cbData); 

    // записать событие в сеанс
    ULONG code = ::TraceEvent(_hTrace, pEvent); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

///////////////////////////////////////////////////////////////////////////////
// Провайдер трассировки
///////////////////////////////////////////////////////////////////////////////
static ULONG WINAPI WMIEnableCallback(WMIDPREQUESTCODE requestCode,
    PVOID pRequestContext, PULONG pBufferSize, PVOID pBuffer)
{
    // выполнить преобразование типа
    WMI::Provider* pProvider = (WMI::Provider*)pRequestContext;

    switch (requestCode)
    {
    case WMI_ENABLE_EVENTS: 
    {
        // получить описатель сеанса
        TRACEHANDLE hLogger = GetTraceLoggerHandle(pBuffer); 

        // получить уровень доступа и категории ссобытий
        UCHAR level = GetTraceEnableLevel(hLogger); 
        ULONG flags = GetTraceEnableFlags(hLogger); 

        // обработать уведомление
        pProvider->Enable(hLogger, level, flags); break; 
    }
    case WMI_DISABLE_EVENTS: 
    {
        // получить описатель сеанса
        TRACEHANDLE hLogger = GetTraceLoggerHandle(pBuffer); 

        // обработать уведомление
        pProvider->Disable(hLogger); break; 
    }}
    return ERROR_SUCCESS; 
}

WMI::Provider::Provider(const GUID& guid, const GUID* pCategories, size_t cntCategories) 
    
    : _guid(guid), _hLogger(0), _level(0), _flags(0)
{
    // зарегистрировать провайдер
    ULONG code = ::RegisterTraceGuidsW(&WMIEnableCallback, this, &guid, 0, NULL, NULL, NULL, &_hProvider); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
} 

///////////////////////////////////////////////////////////////////////////////
// Провайдер трассировки
///////////////////////////////////////////////////////////////////////////////
static void NTAPI ManifestEnableCallback(LPCGUID loggerID, ULONG code,
    UCHAR level, ULONGLONG matchAnyKeyword, ULONGLONG matchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR filterData, PVOID pCallbackContext)
{
    // выполнить преобразование типа
    Manifest::Provider* pProvider = (Manifest::Provider*)pCallbackContext; 

    switch (code)
    {
    case EVENT_CONTROL_CODE_ENABLE_PROVIDER:

        // обработать уведомление
        pProvider->EnableCallback(*loggerID, level, matchAnyKeyword, matchAllKeyword, filterData); break; 

    case EVENT_CONTROL_CODE_DISABLE_PROVIDER:

        // обработать уведомление
        pProvider->DisableCallback(*loggerID); break; 
    }
}

Manifest::Provider::Provider(const GUID& guid) : _guid(guid) 
{
    // зарегистрировать провайдер
    ULONG code = ::EventRegister(&guid, &ManifestEnableCallback, this, &_hProvider); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
} 
