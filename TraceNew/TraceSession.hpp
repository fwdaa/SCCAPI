#include <windows.h>
#include "TraceSession.h"
#include <memory>

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// Сеанс трассировки
///////////////////////////////////////////////////////////////////////////////
class EventLogger : public IEventLogger
{
    // описатель и имя сеанса
    private: TRACEHANDLE _hTrace; BSTR _bstrName; GUID _guid; 
    // признак защиты по умолчанию
    private: TimestampType _timerType; BOOL _defaultSecurity; BOOL _system; 

    // создать сеанс трассировки
    public: static std::shared_ptr<IEventLogger> Create(
        PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
        ULONG mode, TimestampType timerType, ULONG bufferSize) 
    {
        // создать сеанс трассировки
        return std::shared_ptr<IEventLogger>(new EventLogger(
            pSecurityDescriptor, szName, mode, timerType, bufferSize
        )); 
    }
    // открыть сеанс трассировки
    public: static std::shared_ptr<IEventLogger> Open(PCWSTR); 

    // конструктор
    public: EventLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, const EVENT_LOGGER_PARAMS&, PCWSTR); 
    public: EventLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, ULONG); 
    // конструктор
    public: EventLogger(TRACEHANDLE, PCWSTR, ULONG, BOOL); 
    // деструктор
    public: virtual ~EventLogger(); 

    // описатель сеанса
    public: TRACEHANDLE Handle() const { return _hTrace; } 

    // идентификатор сеанса
    public: virtual const GUID& Guid() const override { return _guid; } 
    // имя сеанса
    public: virtual PCWSTR Name() const override { return _bstrName; } 

    // режим сеанса
    public: virtual ULONG Mode() const override { return EVENT_TRACE_BUFFERING_MODE; }  
    // тип отметки времени
    public: virtual TimestampType TimerType() const { return _timerType; }

    // получить параметры сеанса
    public: virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const override; 

    // подключить провайдер
    public: virtual void EnableProvider(const GUID&, UCHAR, ULONG) override;  
    public: virtual void EnableProvider(const GUID&, UCHAR, ULONG, ULONG, ULONG) override;  
    // отключить провайдер
    public: virtual void DisableProvider(const GUID&) override;  

    // закрыть сеанс трассировки
    public: virtual void Close() override; 
};

///////////////////////////////////////////////////////////////////////////////
// Сеанс трассировки, связанный с лог-файлами и/или потребителями
///////////////////////////////////////////////////////////////////////////////
class ConsumerLogger : public EventLogger, public IConsumerLogger
{
    // создать сеанс
    public: static std::shared_ptr<IConsumerLogger> Create(
        PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, ULONG mode, 
        TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile) 
    {
        // создать сеанс
        return std::shared_ptr<IConsumerLogger>(new ConsumerLogger(
            pSecurityDescriptor, szName, mode, timerType, parameters, szLogFile
        )); 
    }
    // конструктор
    public: ConsumerLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, const EVENT_LOGGER_PARAMS&, PCWSTR); 
    // конструктор
    public: ConsumerLogger(TRACEHANDLE, PCWSTR, ULONG, BOOL); private: ULONG _mode;  
        
    // имя сеанса
    public: virtual PCWSTR Name() const override { return EventLogger::Name(); } 
    // идентификатор сеанса
    public: virtual const GUID& Guid() const override { return EventLogger::Guid(); } 

    // режим сеанса
    public: virtual ULONG Mode() const override { return _mode; } 
    // тип отметки времени
    public: virtual TimestampType TimerType() const { return EventLogger::TimerType(); }

    // получить параметры сеанса
    public: virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const override 
    {
        // получить параметры сеанса
        EVENT_LOGGER_PARAMS parameters; GetParameters(&parameters); 

        // вернуть параметры сеанса
        pParameters->BufferSize     = parameters.BufferSize; 
        pParameters->MinimumBuffers = parameters.MinimumBuffers; 
        pParameters->MaximumBuffers = parameters.MaximumBuffers; 
    }
    // параметры сеанса
    public: virtual void GetParameters(EVENT_LOGGER_PARAMS* pParameters) const override;
    // получить статистику сеанса
    public: virtual void GetStatistics(EVENT_LOGGER_STATS* pStatistics) const override; 

    // подключить провайдер
    public: virtual void EnableProvider(const GUID& guid, UCHAR level, ULONG flags) override
    {
        // подключить провайдер
        EventLogger::EnableProvider(guid, level, flags); 
    }
    // подключить провайдер
    public: virtual void EnableProvider(const GUID& guid, 
        UCHAR level, ULONG matchAny, ULONG matchAll, ULONG properties) override
    {
        // подключить провайдер
        EventLogger::EnableProvider(guid, level, matchAny, matchAll, properties); 
    }
    // отключить провайдер
    public: virtual void DisableProvider(const GUID& guid) override
    {
        // отключить провайдер
        EventLogger::DisableProvider(guid); 
    }
    // изменить максимальное число буферов
    public: virtual void SetMaxBuffers(ULONG maxBuffers) override; 
    // изменить время сброса буферов
    public: virtual void SetFlushTimer(ULONG secTimer) override; 

    // признак допустимости потребителей
    public: virtual BOOL IsRealTimeMode() const override
    {
        // признак допустимости потребителей
        return (_mode & EVENT_TRACE_REAL_TIME_MODE) != 0; 
    }
    // изменить допустимость потребителей
    public: virtual void SetRealTimeMode(BOOL realTime) override; 

    // текущее имя лог-файла
    public: virtual BSTR GetLogFileName() const override; 
    // изменить имя лог-файла
    public: virtual void SetLogFileName(PCWSTR szFileName) override; 

    // сбросить буферы потребителям
    public: virtual void Flush() override; 
    // закрыть сеанс трассировки
    public: virtual void Close() override { EventLogger::Close(); }  
};

///////////////////////////////////////////////////////////////////////////////
// Создание и открытие сеансов
///////////////////////////////////////////////////////////////////////////////

// открыть сеанс Global Logger
inline std::shared_ptr<IEventLogger> OpenGlobalLogger()
{
    // открыть сеанс Global Logger
    return EventLogger::Open(GLOBAL_LOGGER_NAMEW); 
}

inline std::shared_ptr<IEventLogger> CreateKernelLogger(
    ULONG mode, TimestampType timerType, ULONG bufferSize)
{
    // создать сеанс NT Kernel Logger
    return EventLogger::Create(nullptr, 
        KERNEL_LOGGER_NAMEW, mode, timerType, bufferSize
    ); 
}
inline std::shared_ptr<IConsumerLogger> CreateKernelLogger(
    ULONG mode, TimestampType timerType, 
    const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)
{
    // создать сеанс NT Kernel Logger
    return ConsumerLogger::Create(nullptr, 
        KERNEL_LOGGER_NAMEW, mode, timerType, parameters, szLogFile
    ); 
}
inline std::shared_ptr<IEventLogger> OpenKernelLogger()
{
    // открыть сеанс NT Kernel Logger
    return EventLogger::Open(KERNEL_LOGGER_NAMEW); 
}

inline std::shared_ptr<IEventLogger> CreateLogger(
    PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, ULONG bufferSize)
{
    // создать сеанс
    return EventLogger::Create(pSecurityDescriptor, 
        szName, mode, timerType, bufferSize
    ); 
}
inline std::shared_ptr<IConsumerLogger> CreateLogger(
    PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, ULONG mode, 
    TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)
{
    // создать сеанс
    return ConsumerLogger::Create(pSecurityDescriptor, 
        szName, mode, timerType, parameters, szLogFile
    ); 
}
inline std::shared_ptr<IEventLogger> OpenLogger(PCWSTR szName)
{
    // открыть сеанс
    return EventLogger::Open(szName); 
}
}
