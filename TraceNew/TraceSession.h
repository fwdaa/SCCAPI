#pragma once
#include <evntrace.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� �������, �������� ������� ����� ������������� � ������ 
// ������������ ������ Windows
///////////////////////////////////////////////////////////////////////////////
#ifndef EVENT_TRACE_FILE_MODE_NEWFILE
#define EVENT_TRACE_FILE_MODE_NEWFILE       0x00000008
#endif 
#ifndef EVENT_TRACE_FILE_MODE_PREALLOCATE
#define EVENT_TRACE_FILE_MODE_PREALLOCATE   0x00000020
#endif 
#ifndef EVENT_TRACE_USE_KBYTES_FOR_SIZE
#define EVENT_TRACE_USE_KBYTES_FOR_SIZE     0x00002000
#endif 
#ifndef EVENT_TRACE_SYSTEM_LOGGER_MODE
#define EVENT_TRACE_SYSTEM_LOGGER_MODE      0x02000000
#endif 

namespace ETW {

// ��� ������� ������� �������
enum class TimestampType { QPC = 1, FileTime = 2, TSC = 3 }; 

///////////////////////////////////////////////////////////////////////////////
// ������ ������ ����������� � ������������ ��������� ��� �������� ������
///////////////////////////////////////////////////////////////////////////////
// EVENT_TRACE_BUFFERING_MODE       : BufferSize 
// EVENT_TRACE_REAL_TIME_MODE       : BufferSize, MinBuffers, MaxBuffers, FlushTimer 
// SESSION_MODE_FILE_CIRCULAR       : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize != 0, FileName
//      EVENT_TRACE_FILE_MODE_PREALLOCATE
// EVENT_TRACE_FILE_MODE_SEQUENTIAL : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize     , FileName
//      EVENT_TRACE_FILE_MODE_PREALLOCATE (��� MaxFileSize != 0)
//      EVENT_TRACE_FILE_MODE_APPEND      (��� ���������� EVENT_TRACE_REAL_TIME_MODE)
// EVENT_TRACE_FILE_MODE_NEWFILE    : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize != 0, FileName (� %d)
//      EVENT_TRACE_FILE_MODE_PREALLOCATE
///////////////////////////////////////////////////////////////////////////////
struct EVENT_BUFFER_PARAMS {
    ULONG BufferSize;       // ������ ������ � ������
    ULONG MinimumBuffers;   // ����������� ����� �������
    ULONG MaximumBuffers;   // ������������ ����� �������
}; 
struct IEventLogger { virtual ~IEventLogger() {}

    // ������������� ������
    virtual const GUID& Guid() const = 0; 
    // ��� ������
    virtual PCWSTR Name() const = 0; 

    // ����� ������
    virtual ULONG Mode() const = 0; 
    // ��� ������� �������
    virtual TimestampType TimerType() const = 0; 

    // �������� ��������� ������
    virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const = 0; 

    // ���������� ���������
    virtual void EnableProvider(const GUID&, UCHAR, ULONG) = 0;  
    virtual void EnableProvider(const GUID&, UCHAR, ULONG, ULONG, ULONG) = 0;  
    // ��������� ���������
    virtual void DisableProvider(const GUID&) = 0;  

    // ������� ����� �����������
    virtual void Close() = 0; 
}; 
///////////////////////////////////////////////////////////////////////////////
// ����� �����������, ��������� � ���-������� �/��� �������������
///////////////////////////////////////////////////////////////////////////////
struct EVENT_LOGGER_PARAMS : EVENT_BUFFER_PARAMS {
    ULONG FlushTimer;           // ����� ������ ������ ������������
    ULONG MaxLogFileSize;       // ������������ ������ ���-����� � ������
}; 
struct EVENT_LOGGER_STATS {
    ULONG NumberOfBuffers;              // no of buffers in use
    ULONG FreeBuffers;                  // no of buffers free
    ULONG EventsLost;                   // event records lost
    ULONG BuffersWritten;               // no of buffers written to file
    ULONG LogBuffersLost;               // no of logfile write failures
    ULONG RealTimeBuffersLost;          // no of rt delivery failures
}; 
struct IConsumerLogger : IEventLogger
{
    // �������� ��������� ������
    virtual void GetParameters(EVENT_LOGGER_PARAMS* pParameters) const = 0; 
    // �������� ���������� ������
    virtual void GetStatistics(EVENT_LOGGER_STATS* pStatistics) const = 0; 

    // �������� ������������ ����� �������
    virtual void SetMaxBuffers(ULONG maxBuffers) = 0; 
    // �������� ����� ������ �������
    virtual void SetFlushTimer(ULONG secTimer) = 0;  

    // ������� ������������ ������������
    virtual BOOL IsRealTimeMode() const = 0; 
    // �������� ������������ ������������
    virtual void SetRealTimeMode(BOOL realTime) = 0;  

    // ������� ��� ���-�����
    virtual BSTR GetLogFileName() const = 0; 
    // �������� ��� ���-�����
    virtual void SetLogFileName(PCWSTR szFileName) = 0; 

    // �������� ����� ������������
    virtual void Flush() = 0; 
};
}
