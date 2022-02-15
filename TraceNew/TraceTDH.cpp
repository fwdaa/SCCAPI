#include <windows.h>
#include "TraceTDH.hpp"
#include <in6addr.h>

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
TDH::EventValueMap::EventValueMap(const EVENT_RECORD* pEvent, PCWSTR szName)
{
    // определить требуемый размер буфера
    ULONG cb = 0; TDHSTATUS status = ::TdhGetEventMapInformation((PEVENT_RECORD)pEvent, (PWSTR)szName, nullptr, &cb);

    // проверить код завершения
    if (status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER) ETW::Exception::Throw(status); 

    // выделить буфер требуемого размера
    _buffer.resize(cb); PEVENT_MAP_INFO pMapInfo = (PEVENT_MAP_INFO)&_buffer[0]; 

    // получить метаданные
    status = ::TdhGetEventMapInformation((PEVENT_RECORD)pEvent, (PWSTR)szName, pMapInfo, &cb);
    
    // проверить код завершения
    if (status != ERROR_SUCCESS) ETW::Exception::Throw(status); _buffer.resize(cb); 

    // для всех отображений битов
    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        // перейти на отдельное отображение
        const EVENT_MAP_ENTRY* pMapEntry = &pMapInfo->MapEntryArray[i]; 

        // определить имя бита
        PWSTR szOutputName = (PWSTR)((PBYTE)pMapInfo + pMapEntry->OutputOffset); 

        // определить размер имени
        size_t cch = wcslen(szOutputName); 

        // удалить завершающий пробел
        if (szOutputName[cch - 1] == L' ') szOutputName[cch - 1] = L'\0'; 
    }
    // добавить описания в таблицу
    for (ULONG i = 0; i < pMapInfo->EntryCount; i++) _map.emplace_back(pMapInfo, i); 
}

TDH::ProviderValueMap::ProviderValueMap(const GUID& providerID, EVENT_FIELD_TYPE type)
{
    // определить требуемый размер буфера
    ULONG cb = 0; TDHSTATUS status = ::TdhEnumerateProviderFieldInformation(
        (LPGUID)&providerID, type, nullptr, &cb
    ); 
    // проверить отсутствие ошибок
    if (status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER) ETW::Exception::Throw(status); 

    // выделить буфер требуемого размера 
    _buffer.resize(cb); PPROVIDER_FIELD_INFOARRAY pMapInfo = (PPROVIDER_FIELD_INFOARRAY)&_buffer[0]; 
    
    // получить описания значений или битов
    status = ::TdhEnumerateProviderFieldInformation((LPGUID)&providerID, type, pMapInfo, &cb); 

    // проверить отсутствие ошибок
    if (status != ERROR_SUCCESS) ETW::Exception::Throw(status); _buffer.resize(cb); 

    // добавить описания в таблицу
    for (ULONG i = 0; i < pMapInfo->NumberOfElements; i++) _map.emplace_back(pMapInfo, i); 
}

///////////////////////////////////////////////////////////////////////////////
// Булевский тип
///////////////////////////////////////////////////////////////////////////////
TDH::BooleanType::BooleanType(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::BooleanType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::BooleanType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Типы чисел
///////////////////////////////////////////////////////////////////////////////
TDH::Int8Type::Int8Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::Int8Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::Int8Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::UInt8Type::UInt8Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::UInt8Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::UInt8Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::Int16Type::Int16Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::Int16Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::Int16Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::UInt16Type::UInt16Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::UInt16Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::UInt16Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::Int32Type::Int32Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::Int32Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::Int32Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::UInt32Type::UInt32Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::UInt32Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::UInt32Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::Int64Type::Int64Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::Int64Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::Int64Type::ToString(parent, pvData, cbData); 
#endif 
}

TDH::UInt64Type::UInt64Type(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}

BSTR TDH::UInt64Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::UInt64Type::ToString(parent, pvData, cbData); 
#endif 
}

BSTR TDH::FloatType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::FloatType::ToString(parent, pvData, cbData); 
#endif 
}

BSTR TDH::DoubleType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::DoubleType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Тип указателя или числа разрядности указателя
///////////////////////////////////////////////////////////////////////////////
TDH::PointerType::PointerType(const Event& event, const EVENT_PROPERTY_INFO& info) 

    // сохранить переданные параметры
    : ETW::PointerType(event.PointerSize()), _event(event), _info(info), _pValueMap(event.GetValueMap(info)) {}
        
BSTR TDH::PointerType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::PointerType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Тип времени
///////////////////////////////////////////////////////////////////////////////
BSTR TDH::DateTimeType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::DateTimeType::ToString(parent, pvData, cbData); 
#endif 
}

BSTR TDH::CimDateTimeType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::CimDateTimeType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Тип строк
///////////////////////////////////////////////////////////////////////////////
size_t TDH::StringType::GetLength(const ETW::IContainer* pParent) const
{
    // при наличии имени поля с указанием размера
    if ((_info.Flags & PropertyParamLength) != 0)
    {
        // проверить указание родительского элемента
        if (!pParent) return 0; size_t length = 0; 

        // получить описание раскодированного события
        const TRACE_EVENT_INFO* pEventInfo = _event.GetEventInfo(); 

        // перейти на структуру описания поля
        const EVENT_PROPERTY_INFO& countInfo = 
            pEventInfo->EventPropertyInfoArray[_info.lengthPropertyIndex]; 

        // определить имя поля 
        PCWSTR szCountName = (PCWSTR)((CONST BYTE*)pEventInfo + countInfo.NameOffset); 

        // проверить тип родительской структуры
        if (pParent->Type().LogicalType() != ETW::TYPE_STRUCT) ETW::ThrowBadData();

        // выполнить преобразование типа
        const ETW::IStruct& parentStruct = (const ETW::IStruct&)*pParent; 

        // найти поле с размером
        if (const ETW::IElement* pCount = parentStruct.FindName(szCountName))
        {
            // прочитать значение поля
            memcpy(&length, pCount->GetDataAddress(), pCount->GetDataSize()); return length;  
        }
        // при ошибке выбросить исключение
        else ETW::ThrowBadData();
    }
    // проверить указание максимального размера
    return ((_info.Flags & PropertyParamFixedLength) != 0) ? _info.length : SIZE_MAX; 
}

BSTR TDH::StringType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::StringType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Бинарный тип данных
///////////////////////////////////////////////////////////////////////////////
size_t TDH::BinaryType::GetSize(const ETW::IContainer& parent) const 
{
    // при наличии имени поля с указанием размера
    if ((_info.Flags & PropertyParamLength) != 0) { size_t length = 0; 
    
        // получить описание раскодированного события
        const TRACE_EVENT_INFO* pEventInfo = _event.GetEventInfo(); 

        // перейти на структуру описания поля
        const EVENT_PROPERTY_INFO& lengthInfo = 
            pEventInfo->EventPropertyInfoArray[_info.lengthPropertyIndex]; 

        // определить имя поля 
        PCWSTR szLengthName = (PCWSTR)((CONST BYTE*)pEventInfo + lengthInfo.NameOffset); 

        // проверить тип родительской структуры
        if (parent.Type().LogicalType() != ETW::TYPE_STRUCT) ETW::ThrowBadData();

        // выполнить преобразование типа
        const ETW::IStruct& parentStruct = (const ETW::IStruct&)parent; 

        // найти поле с размером
        if (const ETW::IElement* pLength = parentStruct.FindName(szLengthName))
        {
            // прочитать значение поля
            memcpy(&length, pLength->GetDataAddress(), pLength->GetDataSize()); return length;  
        }
        // при ошибке выбросить исключение
        else ETW::ThrowBadData();
    }
    // проверить указание максимального размера
    return ((_info.Flags & PropertyParamFixedLength) != 0) ? _info.length : SIZE_MAX; 
}

BSTR TDH::BinaryType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::BinaryType::ToString(parent, pvData, cbData); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Специальные типы данных
///////////////////////////////////////////////////////////////////////////////
BSTR TDH::GuidType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::GuidType::ToString(parent, pvData, cbData); 
#endif 
}

TDH::SidType::SidType(const Event& event, const EVENT_PROPERTY_INFO& info) 
        
    // сохранить переданные параметры
    : ETW::SidType(event.PointerSize()), _event(event), _info(info) {}

BSTR TDH::IPv4Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::IPv4Type::ToString(parent, pvData, cbData); 
#endif 
}

BSTR TDH::IPv6Type::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::IPv6Type::ToString(parent, pvData, cbData); 
#endif 
}

BSTR TDH::SocketAddressType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
#if (WINVER >= _WIN32_WINNT_WIN7)
    // получить строковое представление
    std::wstring str = _event.Format(parent, _info, pvData, cbData); 

    // выделить память для строки
    BSTR bstr = ::SysAllocString(str.c_str()); 

    // проверить отсутствие ошибок
    if (!bstr) ETW::Exception::Throw(E_OUTOFMEMORY); return bstr; 
#else
    // вызвать базовую функцию
    return ETW::SocketAddressType::ToString(parent, pvData, cbData); 
#endif 
}
///////////////////////////////////////////////////////////////////////////////
// Массив
///////////////////////////////////////////////////////////////////////////////
TDH::ArrayType::ArrayType(const Event& event, 
    const EVENT_PROPERTY_INFO& info) : _event(event), _info(info) 
{
    // при указании структуры
    if ((_info.Flags & PropertyStruct) != 0)
    {
        // получить стартовый индекс полей структуры
        size_t startIndex = _info.structType.StructStartIndex; 

        // определить число полей структуры
        size_t count = _info.structType.NumOfStructMembers; 

        // сохранить описание структуры
        _pElementType.reset(new StructType(event, startIndex, count)); 
    }
    else {
        // сохранить описание простого типа
        _pElementType.reset(event.CreateBasicType(info)); 
    }
}

size_t TDH::ArrayType::GetCount(const ETW::IContainer& parent) const
{
    // при указании имени поля с размером
    if ((_info.Flags & PropertyParamCount) != 0) { size_t count = 0; 
     
        // получить описание раскодированного события
        const TRACE_EVENT_INFO* pEventInfo = _event.GetEventInfo(); 
        
        // перейти на описание поля с размером
        const EVENT_PROPERTY_INFO& countInfo = 
            pEventInfo->EventPropertyInfoArray[_info.countPropertyIndex]; 

        // вернуть имя свойства с размером
        PCWSTR szCountField = (PCWSTR)((CONST BYTE*)pEventInfo + countInfo.NameOffset); 

        // проверить тип родительского элемента
        if (parent.Type().LogicalType() == ETW::TYPE_STRUCT) 
        {
            // выполнить преобразование типа
            const ETW::IStruct& parentStruct = (const ETW::IStruct&)parent; 

            // найти поле с размером
            if (const ETW::IElement* pCount = parentStruct.FindName(szCountField))
            {
                // прочитать значение поля
                memcpy(&count, pCount->GetDataAddress(), pCount->GetDataSize()); return count; 
            }
        }
    }
    // проверить наличие фиксированного размера
    if ((_info.Flags & PropertyParamFixedCount) != 0) return _info.count; 

    // проверить наличие фиксированного размера
    return (_info.count != 1) ? _info.count : SIZE_MAX; 
}
    
///////////////////////////////////////////////////////////////////////////////
// Структура
///////////////////////////////////////////////////////////////////////////////
TDH::StructType::StructType(const Event& event, size_t startIndex, size_t count)
{
    // сгенерировать уникальный идентификатор
    HRESULT hr = ::CoCreateGuid(&_id); if (FAILED(hr)) ETW::Exception::Throw(hr); 

    // получить описание раскодированного события
    const TRACE_EVENT_INFO* pEventInfo = event.GetEventInfo(); 
        
    // для всех полей
    for (size_t i = 0; i < count; i++)
    {
        // перейти на описание свойства с размером
        const EVENT_PROPERTY_INFO& info = pEventInfo->EventPropertyInfoArray[startIndex + i]; 

        // определить имя свойства
        std::wstring name((PCWSTR)((CONST BYTE*)pEventInfo + info.NameOffset)); 

        // при указании массива переменного размера
        if ((info.Flags & PropertyParamCount) != 0)
        {
            // добавить описание поля массива
            _fields.emplace_back(name, std::shared_ptr<ETW::IElementType>(
                new ArrayType(event, info)
            )); 
        }
        // при указании массива фиксированного размера
        else if (info.count != 1 || (info.Flags & PropertyParamFixedCount) != 0)
        {
            // добавить описание поля массива
            _fields.emplace_back(name, std::shared_ptr<ETW::IElementType>(
                new ArrayType(event, info)
            )); 
        }
        // при указании структуры
        else if ((info.Flags & PropertyStruct) != 0)
        {
            // получить стартовый индекс полей структуры
            size_t inStartIndex = info.structType.StructStartIndex; 

            // определить число полей структуры
            size_t inCount = info.structType.NumOfStructMembers; 

            // добавить описание поля структуры
            _fields.emplace_back(name, std::shared_ptr<ETW::IElementType>(
                new StructType(event, inStartIndex, inCount)
            )); 
        }
        else {
            // добавить описание простого поля
            _fields.emplace_back(name, std::shared_ptr<ETW::IElementType>(
                event.CreateBasicType(info)
            )); 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Cобытие и связанные с ним метаданные
///////////////////////////////////////////////////////////////////////////////
TDH::Event::Event(TDH_CONTEXT* pContext, ULONG cntContext, const EVENT_RECORD* pEvent)

    // сохранить переданные параметры
    : _pContext(pContext), _cntContext(cntContext), _pEvent(pEvent)
{
    // определить требуемый размер буфера
    DWORD cbBuf = 0; TDHSTATUS status = ::TdhGetEventInformation(
        (PEVENT_RECORD)pEvent, cntContext, pContext, nullptr, &cbBuf
    );
    // проверить код завершения
    if (status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER) ETW::Exception::Throw(status); 

    // выделить буфер требуемого размера
    _vecEventInfo.resize(cbBuf); PTRACE_EVENT_INFO pEventInfo = (PTRACE_EVENT_INFO)&_vecEventInfo[0]; 

    // получить метаданные
    status = ::TdhGetEventInformation((PEVENT_RECORD)pEvent, cntContext, pContext, pEventInfo, &cbBuf);
    
    // проверить код завершения
    if (status != ERROR_SUCCESS) ETW::Exception::Throw(status); _vecEventInfo.resize(cbBuf);

    // раскодировать тип структуры
    _pStructType.reset(new StructType(*this, 0, pEventInfo->TopLevelPropertyCount)); 

    // раскодировать данные в структуре
    _pStruct.reset(new ETW::Struct(L"", *_pStructType, pEvent->UserData, pEvent->UserDataLength)); 
}

std::shared_ptr<ETW::IValueMap> TDH::Event::GetValueMap(const EVENT_PROPERTY_INFO& info) const
{
    // проверить наличие описания значений или битов
    if (info.nonStructType.MapNameOffset == 0) return std::shared_ptr<ETW::IValueMap>(); 

    // выполнить преобразование типа
    const TRACE_EVENT_INFO* pEventInfo = (const TRACE_EVENT_INFO*)&_vecEventInfo[0]; 

    // получить имя описания 
    PCWSTR szName = (PCWSTR)((CONST BYTE*)pEventInfo + info.nonStructType.MapNameOffset); 

    // получить описания значения или битов
    return std::shared_ptr<ETW::IValueMap>(new EventValueMap(_pEvent, szName)); 
}

std::wstring TDH::Event::Format(const ETW::IContainer& parent, 
    const EVENT_PROPERTY_INFO& info, const void* pvData, size_t cbData) const
{
    // инициализировать буфер для описания значений
    TDHSTATUS status = ERROR_SUCCESS; PEVENT_MAP_INFO pMapInfo = nullptr; std::vector<BYTE> vecMapInfo; 

    // при наличии описания значений
    if (info.nonStructType.MapNameOffset != 0) { ULONG cbMapInfo = 0; 
    
        // получить имя описания 
        PCWSTR szName = (PCWSTR)(&_vecEventInfo[0] + info.nonStructType.MapNameOffset); 

        // определить требуемый размер буфера
        status = ::TdhGetEventMapInformation((PEVENT_RECORD)_pEvent, (PWSTR)szName, nullptr, &cbMapInfo);

        // проверить код завершения
        if (status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER) ETW::Exception::Throw(status); 

        // выделить буфер требуемого размера
        vecMapInfo.resize(cbMapInfo); pMapInfo = (PEVENT_MAP_INFO)&vecMapInfo[0]; 

        // получить метаданные
        status = ::TdhGetEventMapInformation((PEVENT_RECORD)_pEvent, (PWSTR)szName, pMapInfo, &cbMapInfo);
    
        // проверить код завершения
        if (status != ERROR_SUCCESS) ETW::Exception::Throw(status); vecMapInfo.resize(cbMapInfo); 
    }
    // выполнить преобразование типа
    PTRACE_EVENT_INFO pEventInfo = (PTRACE_EVENT_INFO)&_vecEventInfo[0]; 
    
    // инициализировать переменные
    USHORT length = 0; USHORT cbConsumed = 0; ULONG cbBuffer = 0; 

    // указать размер буфера для IPv6-адреса
    if (info.nonStructType.OutType == TDH_OUTTYPE_IPV6) length = sizeof(IN6_ADDR); 
    
    // при наличии имени поля с указанием размера
    else if ((info.Flags & PropertyParamLength) == 0) length = info.length; 
    else { 
        // перейти на структуру описания поля
        const EVENT_PROPERTY_INFO& lengthInfo = 
            pEventInfo->EventPropertyInfoArray[info.lengthPropertyIndex]; 

        // определить имя поля 
        PCWSTR szLengthName = (PCWSTR)((CONST BYTE*)pEventInfo + lengthInfo.NameOffset); 

        // проверить тип родительской структуры
        if (parent.Type().LogicalType() != ETW::TYPE_STRUCT) ETW::ThrowBadData();

        // выполнить преобразование типа
        const ETW::IStruct& parentStruct = (const ETW::IStruct&)parent; 

        // найти поле с размером
        if (const ETW::IElement* pLength = parentStruct.FindName(szLengthName))
        {
            // прочитать значение поля
            memcpy(&length, pLength->GetDataAddress(), pLength->GetDataSize()); 
        }
        // при ошибке выбросить исключение
        else ETW::ThrowBadData();
    }
    // определить требуемый размер буфера
    status = ::TdhFormatProperty(pEventInfo, pMapInfo, (ULONG)PointerSize(), 
        info.nonStructType.InType, info.nonStructType.OutType, length, 
        (USHORT)cbData, (PBYTE)pvData, &cbBuffer, nullptr, &cbConsumed
    ); 
    // проверить код завершения
    if (status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER) 
    {
        // при ошибке выбросить исключение
        ETW::Exception::Throw(status); 
    }
    // выделить буфер требуемого размера
    std::wstring strBuffer(cbBuffer / sizeof(WCHAR), 0); 

    // получить строковое представление значения
    status = ::TdhFormatProperty(pEventInfo, pMapInfo, (ULONG)PointerSize(), 
        info.nonStructType.InType, info.nonStructType.OutType, length, 
        (USHORT)cbData, (PBYTE)pvData, &cbBuffer, &strBuffer[0], &cbConsumed
    ); 
    // проверить код завершения
    if (status != ERROR_SUCCESS) ETW::Exception::Throw(status); 

    // вернуть строковое представление значения
    strBuffer.resize(cbBuffer / sizeof(WCHAR)); return strBuffer; 
}

ETW::IBasicType* TDH::Event::CreateBasicType(const EVENT_PROPERTY_INFO& info) const
{
    switch (info.nonStructType.OutType)
    {
    case TDH_OUTTYPE_CIMDATETIME:   return new TDH::CimDateTimeType  (*this, info); 
    case TDH_OUTTYPE_GUID:          return new TDH::GuidType         (*this, info); 
    case TDH_OUTTYPE_IPV4:          return new TDH::IPv4Type         (*this, info); 
    case TDH_OUTTYPE_IPV6:          return new TDH::IPv6Type         (*this, info); 
    case TDH_OUTTYPE_SOCKETADDRESS: return new TDH::SocketAddressType(*this, info); 
    }
    switch (info.nonStructType.InType)
    {
    case TDH_INTYPE_BOOLEAN                     : return new TDH::BooleanType (*this, info); 
    case TDH_INTYPE_INT8                        : return new TDH::Int8Type    (*this, info); 
    case TDH_INTYPE_UINT8                       : return new TDH::UInt8Type   (*this, info); 
    case TDH_INTYPE_INT16                       : return new TDH::Int16Type   (*this, info); 
    case TDH_INTYPE_UINT16                      : return new TDH::UInt16Type  (*this, info); 
    case TDH_INTYPE_INT32                       : return new TDH::Int32Type   (*this, info); 
    case TDH_INTYPE_UINT32                      : return new TDH::UInt32Type  (*this, info); 
    case TDH_INTYPE_HEXINT32                    : return new TDH::UInt32Type  (*this, info); 
    case TDH_INTYPE_INT64                       : return new TDH::Int64Type   (*this, info); 
    case TDH_INTYPE_UINT64                      : return new TDH::UInt64Type  (*this, info); 
    case TDH_INTYPE_HEXINT64                    : return new TDH::UInt64Type  (*this, info); 
    case TDH_INTYPE_FLOAT                       : return new TDH::FloatType   (*this, info); 
    case TDH_INTYPE_DOUBLE                      : return new TDH::DoubleType  (*this, info); 
    case TDH_INTYPE_SIZET                       : return new TDH::PointerType (*this, info); 
    case TDH_INTYPE_POINTER                     : return new TDH::PointerType (*this, info); 
    case TDH_INTYPE_FILETIME                    : return new TDH::DateTimeType(*this, info); 
    case TDH_INTYPE_SYSTEMTIME                  : return new TDH::DateTimeType(*this, info); 
    case TDH_INTYPE_ANSICHAR                    : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_ANSISTRING                  : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_COUNTEDANSISTRING           : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING   : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING  : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_UNICODECHAR                 : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_UNICODESTRING               : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_COUNTEDSTRING               : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING       : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_NONNULLTERMINATEDSTRING     : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING      : return new TDH::StringType  (*this, info); 
    case TDH_INTYPE_BINARY                      : return new TDH::BinaryType  (*this, info); 
    case TDH_INTYPE_HEXDUMP                     : return new TDH::BinaryType  (*this, info); 
    case TDH_INTYPE_MANIFEST_COUNTEDBINARY      : return new TDH::BinaryType  (*this, info); 
    case TDH_INTYPE_SID                         : return new TDH::SidType     (*this, info); 
    case TDH_INTYPE_WBEMSID                     : return new TDH::SidType     (*this, info); 
    }
    return nullptr; 
}
 
