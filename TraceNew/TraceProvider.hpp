#include <windows.h>
#include "TraceProvider.h"
#include "TraceETW.hpp"

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
class EventCategory : public IEventCategory
{
    // ��������� ��������� � �� �������������
    private: HANDLE _hCategory; GUID _guid; 

    // �����������
    public: EventCategory(HANDLE hCategory, const GUID guid)

        // ��������� ���������� ���������
        : _hCategory(hCategory), _guid(guid) {}

    // ������������� ���������
    public: virtual const GUID& Guid() const { return _guid; }

    // ������� ���������� ������������� ��� �������
    public: EVENT_INSTANCE_INFO CreateInstanceID() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� � ������� �����������
///////////////////////////////////////////////////////////////////////////////
class Connection : public IConnection
{
    // �����������
    public: Connection(TRACEHANDLE hTrace) : _hTrace(hTrace) {} private: TRACEHANDLE _hTrace; 

    // �������� ������� � �����
    public: virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const override; 
    // �������� ������� � �����
    public: virtual EVENT_INSTANCE_INFO WriteEvent(const EVENT_INSTANCE_INFO*, 
        const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const override; 

    // �������� ������� � �����
    public: virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const MOF_FIELD*, size_t) const override; 
    // �������� ������� � �����
    public: virtual void WriteEvent(const IEventCategory&, USHORT, UCHAR, UCHAR, const void*, size_t) const override; 
}; 

}
