#include <windows.h>
#include "TraceProvider.h"
#include "TraceETW.hpp"

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// Категория событий
///////////////////////////////////////////////////////////////////////////////
class EventCategory : public IEventCategory
{
    // описатель категории и ее идентификатор
    private: HANDLE _hCategory; GUID _guid; 

    // конструктор
    public: EventCategory(HANDLE hCategory, const GUID guid)

        // сохранить переданные параметры
        : _hCategory(hCategory), _guid(guid) {}

    // идентификатор категории
    public: virtual const GUID& Guid() const { return _guid; }

    // создать уникальный идентификатор для события
    public: EVENT_INSTANCE_INFO CreateInstanceID() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Соединение с сеансом трассировки
///////////////////////////////////////////////////////////////////////////////
class Connection : public IConnection
{
    // конструктор
    public: Connection(TRACEHANDLE hTrace) : _hTrace(hTrace) {} private: TRACEHANDLE _hTrace; 

    // записать событие в сеанс
    public: virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const override; 
    // записать событие в сеанс
    public: virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const override; 

    // записать событие в сеанс
    public: virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const override; 
    // записать событие в сеанс
    public: virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const override; 
}; 

}
