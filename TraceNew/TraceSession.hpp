#include <windows.h>
#include "TraceSession.h"
#include <memory>

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// ����� �����������
///////////////////////////////////////////////////////////////////////////////
class EventLogger : public IEventLogger
{
    // ��������� � ��� ������
    private: TRACEHANDLE _hTrace; BSTR _bstrName; GUID _guid; 
    // ������� ������ �� ���������
    private: TimestampType _timerType; BOOL _defaultSecurity; BOOL _system; 

    // ������� ����� �����������
    public: static std::shared_ptr<IEventLogger> Create(
        PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
        ULONG mode, TimestampType timerType, ULONG bufferSize) 
    {
        // ������� ����� �����������
        return std::shared_ptr<IEventLogger>(new EventLogger(
            pSecurityDescriptor, szName, mode, timerType, bufferSize
        )); 
    }
    // ������� ����� �����������
    public: static std::shared_ptr<IEventLogger> Open(PCWSTR); 

    // �����������
    public: EventLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, const EVENT_LOGGER_PARAMS&, PCWSTR); 
    public: EventLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, ULONG); 
    // �����������
    public: EventLogger(TRACEHANDLE, PCWSTR, ULONG, BOOL); 
    // ����������
    public: virtual ~EventLogger(); 

    // ��������� ������
    public: TRACEHANDLE Handle() const { return _hTrace; } 

    // ������������� ������
    public: virtual const GUID& Guid() const override { return _guid; } 
    // ��� ������
    public: virtual PCWSTR Name() const override { return _bstrName; } 

    // ����� ������
    public: virtual ULONG Mode() const override { return EVENT_TRACE_BUFFERING_MODE; }  
    // ��� ������� �������
    public: virtual TimestampType TimerType() const { return _timerType; }

    // �������� ��������� ������
    public: virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const override; 

    // ���������� ���������
    public: virtual void EnableProvider(const GUID&, UCHAR, ULONG) override;  
    public: virtual void EnableProvider(const GUID&, UCHAR, ULONG, ULONG, ULONG) override;  
    // ��������� ���������
    public: virtual void DisableProvider(const GUID&) override;  

    // ������� ����� �����������
    public: virtual void Close() override; 
};

///////////////////////////////////////////////////////////////////////////////
// ����� �����������, ��������� � ���-������� �/��� �������������
///////////////////////////////////////////////////////////////////////////////
class ConsumerLogger : public EventLogger, public IConsumerLogger
{
    // ������� �����
    public: static std::shared_ptr<IConsumerLogger> Create(
        PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, ULONG mode, 
        TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile) 
    {
        // ������� �����
        return std::shared_ptr<IConsumerLogger>(new ConsumerLogger(
            pSecurityDescriptor, szName, mode, timerType, parameters, szLogFile
        )); 
    }
    // �����������
    public: ConsumerLogger(PSECURITY_DESCRIPTOR, PCWSTR, ULONG, TimestampType, const EVENT_LOGGER_PARAMS&, PCWSTR); 
    // �����������
    public: ConsumerLogger(TRACEHANDLE, PCWSTR, ULONG, BOOL); private: ULONG _mode;  
        
    // ��� ������
    public: virtual PCWSTR Name() const override { return EventLogger::Name(); } 
    // ������������� ������
    public: virtual const GUID& Guid() const override { return EventLogger::Guid(); } 

    // ����� ������
    public: virtual ULONG Mode() const override { return _mode; } 
    // ��� ������� �������
    public: virtual TimestampType TimerType() const { return EventLogger::TimerType(); }

    // �������� ��������� ������
    public: virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const override 
    {
        // �������� ��������� ������
        EVENT_LOGGER_PARAMS parameters; GetParameters(&parameters); 

        // ������� ��������� ������
        pParameters->BufferSize     = parameters.BufferSize; 
        pParameters->MinimumBuffers = parameters.MinimumBuffers; 
        pParameters->MaximumBuffers = parameters.MaximumBuffers; 
    }
    // ��������� ������
    public: virtual void GetParameters(EVENT_LOGGER_PARAMS* pParameters) const override;
    // �������� ���������� ������
    public: virtual void GetStatistics(EVENT_LOGGER_STATS* pStatistics) const override; 

    // ���������� ���������
    public: virtual void EnableProvider(const GUID& guid, UCHAR level, ULONG flags) override
    {
        // ���������� ���������
        EventLogger::EnableProvider(guid, level, flags); 
    }
    // ���������� ���������
    public: virtual void EnableProvider(const GUID& guid, 
        UCHAR level, ULONG matchAny, ULONG matchAll, ULONG properties) override
    {
        // ���������� ���������
        EventLogger::EnableProvider(guid, level, matchAny, matchAll, properties); 
    }
    // ��������� ���������
    public: virtual void DisableProvider(const GUID& guid) override
    {
        // ��������� ���������
        EventLogger::DisableProvider(guid); 
    }
    // �������� ������������ ����� �������
    public: virtual void SetMaxBuffers(ULONG maxBuffers) override; 
    // �������� ����� ������ �������
    public: virtual void SetFlushTimer(ULONG secTimer) override; 

    // ������� ������������ ������������
    public: virtual BOOL IsRealTimeMode() const override
    {
        // ������� ������������ ������������
        return (_mode & EVENT_TRACE_REAL_TIME_MODE) != 0; 
    }
    // �������� ������������ ������������
    public: virtual void SetRealTimeMode(BOOL realTime) override; 

    // ������� ��� ���-�����
    public: virtual BSTR GetLogFileName() const override; 
    // �������� ��� ���-�����
    public: virtual void SetLogFileName(PCWSTR szFileName) override; 

    // �������� ������ ������������
    public: virtual void Flush() override; 
    // ������� ����� �����������
    public: virtual void Close() override { EventLogger::Close(); }  
};

///////////////////////////////////////////////////////////////////////////////
// �������� � �������� �������
///////////////////////////////////////////////////////////////////////////////

// ������� ����� Global Logger
inline std::shared_ptr<IEventLogger> OpenGlobalLogger()
{
    // ������� ����� Global Logger
    return EventLogger::Open(GLOBAL_LOGGER_NAMEW); 
}

inline std::shared_ptr<IEventLogger> CreateKernelLogger(
    ULONG mode, TimestampType timerType, ULONG bufferSize)
{
    // ������� ����� NT Kernel Logger
    return EventLogger::Create(nullptr, 
        KERNEL_LOGGER_NAMEW, mode, timerType, bufferSize
    ); 
}
inline std::shared_ptr<IConsumerLogger> CreateKernelLogger(
    ULONG mode, TimestampType timerType, 
    const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)
{
    // ������� ����� NT Kernel Logger
    return ConsumerLogger::Create(nullptr, 
        KERNEL_LOGGER_NAMEW, mode, timerType, parameters, szLogFile
    ); 
}
inline std::shared_ptr<IEventLogger> OpenKernelLogger()
{
    // ������� ����� NT Kernel Logger
    return EventLogger::Open(KERNEL_LOGGER_NAMEW); 
}

inline std::shared_ptr<IEventLogger> CreateLogger(
    PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, ULONG bufferSize)
{
    // ������� �����
    return EventLogger::Create(pSecurityDescriptor, 
        szName, mode, timerType, bufferSize
    ); 
}
inline std::shared_ptr<IConsumerLogger> CreateLogger(
    PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, ULONG mode, 
    TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)
{
    // ������� �����
    return ConsumerLogger::Create(pSecurityDescriptor, 
        szName, mode, timerType, parameters, szLogFile
    ); 
}
inline std::shared_ptr<IEventLogger> OpenLogger(PCWSTR szName)
{
    // ������� �����
    return EventLogger::Open(szName); 
}
}
