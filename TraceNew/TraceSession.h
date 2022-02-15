#pragma once
#include <evntrace.h>

///////////////////////////////////////////////////////////////////////////////
// Определение режимов, описание которых может отсутствовать в старых 
// заголовочных файлах Windows
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

// тип отметки времени события
enum class TimestampType { QPC = 1, FileTime = 2, TSC = 3 }; 

///////////////////////////////////////////////////////////////////////////////
// Режимы сеанса трассировки и передаваемые параметры при создании сеанса
///////////////////////////////////////////////////////////////////////////////
// EVENT_TRACE_BUFFERING_MODE       : BufferSize 
// EVENT_TRACE_REAL_TIME_MODE       : BufferSize, MinBuffers, MaxBuffers, FlushTimer 
// SESSION_MODE_FILE_CIRCULAR       : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize != 0, FileName
//      EVENT_TRACE_FILE_MODE_PREALLOCATE
// EVENT_TRACE_FILE_MODE_SEQUENTIAL : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize     , FileName
//      EVENT_TRACE_FILE_MODE_PREALLOCATE (при MaxFileSize != 0)
//      EVENT_TRACE_FILE_MODE_APPEND      (при отсутствии EVENT_TRACE_REAL_TIME_MODE)
// EVENT_TRACE_FILE_MODE_NEWFILE    : BufferSize, MinBuffers, MaxBuffers, FlushTimer, MaxFileSize != 0, FileName (с %d)
//      EVENT_TRACE_FILE_MODE_PREALLOCATE
///////////////////////////////////////////////////////////////////////////////
struct EVENT_BUFFER_PARAMS {
    ULONG BufferSize;       // размер буфера в байтах
    ULONG MinimumBuffers;   // минимальное число буферов
    ULONG MaximumBuffers;   // максимальное число буферов
}; 
struct IEventLogger { virtual ~IEventLogger() {}

    // идентификатор сеанса
    virtual const GUID& Guid() const = 0; 
    // имя сеанса
    virtual PCWSTR Name() const = 0; 

    // режим сеанса
    virtual ULONG Mode() const = 0; 
    // тип отметки времени
    virtual TimestampType TimerType() const = 0; 

    // получить параметры сеанса
    virtual void GetParameters(EVENT_BUFFER_PARAMS* pParameters) const = 0; 

    // подключить провайдер
    virtual void EnableProvider(const GUID&, UCHAR, ULONG) = 0;  
    virtual void EnableProvider(const GUID&, UCHAR, ULONG, ULONG, ULONG) = 0;  
    // отключить провайдер
    virtual void DisableProvider(const GUID&) = 0;  

    // закрыть сеанс трассировки
    virtual void Close() = 0; 
}; 
///////////////////////////////////////////////////////////////////////////////
// Сеанс трассировки, связанный с лог-файлами и/или потребителями
///////////////////////////////////////////////////////////////////////////////
struct EVENT_LOGGER_PARAMS : EVENT_BUFFER_PARAMS {
    ULONG FlushTimer;           // время сброса буферо потребителям
    ULONG MaxLogFileSize;       // максимальный размер лог-файла в байтах
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
    // получить параметры сеанса
    virtual void GetParameters(EVENT_LOGGER_PARAMS* pParameters) const = 0; 
    // получить статистику сеанса
    virtual void GetStatistics(EVENT_LOGGER_STATS* pStatistics) const = 0; 

    // изменить максимальное число буферов
    virtual void SetMaxBuffers(ULONG maxBuffers) = 0; 
    // изменить время сброса буферов
    virtual void SetFlushTimer(ULONG secTimer) = 0;  

    // признак допустимости потребителей
    virtual BOOL IsRealTimeMode() const = 0; 
    // изменить допустимость потребителей
    virtual void SetRealTimeMode(BOOL realTime) = 0;  

    // текущее имя лог-файла
    virtual BSTR GetLogFileName() const = 0; 
    // изменить имя лог-файла
    virtual void SetLogFileName(PCWSTR szFileName) = 0; 

    // сбросить буфер потребителям
    virtual void Flush() = 0; 
};
}
