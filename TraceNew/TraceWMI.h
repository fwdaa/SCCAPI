#pragma once
#include "TraceETW.h"
#include <wbemidl.h>
#include <memory>

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// Простой тип данных
///////////////////////////////////////////////////////////////////////////////
struct IBasicType
{
    // тип данных
    virtual CIMTYPE CimType() const = 0; 
    // атрибуты поля
    virtual IWbemQualifierSet* Qualifiers() const = 0;
}; 

///////////////////////////////////////////////////////////////////////////////
// Пространство имен WMI
///////////////////////////////////////////////////////////////////////////////
struct INamespace { virtual ~INamespace() {}

    // найти провайдер событий
    virtual std::unique_ptr<ETW::IProviderInfo> FindEventProvider(REFGUID) const = 0; 

    // раскодировать событие
    virtual std::unique_ptr<ETW::IEvent> DecodeEvent(PEVENT_TRACE, size_t = sizeof(void*)) const = 0; 
};

}
