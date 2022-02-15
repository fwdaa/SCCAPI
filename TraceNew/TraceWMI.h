#pragma once
#include "TraceETW.h"
#include <wbemidl.h>
#include <memory>

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// ������� ��� ������
///////////////////////////////////////////////////////////////////////////////
struct IBasicType
{
    // ��� ������
    virtual CIMTYPE CimType() const = 0; 
    // �������� ����
    virtual IWbemQualifierSet* Qualifiers() const = 0;
}; 

///////////////////////////////////////////////////////////////////////////////
// ������������ ���� WMI
///////////////////////////////////////////////////////////////////////////////
struct INamespace { virtual ~INamespace() {}

    // ����� ��������� �������
    virtual std::unique_ptr<ETW::IProviderInfo> FindEventProvider(REFGUID) const = 0; 

    // ������������� �������
    virtual std::unique_ptr<ETW::IEvent> DecodeEvent(PEVENT_TRACE, size_t = sizeof(void*)) const = 0; 
};

}
