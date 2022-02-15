#pragma once
#include "TraceETW.hpp"

namespace TDH {

///////////////////////////////////////////////////////////////////////////////
// Описание значения или бита
///////////////////////////////////////////////////////////////////////////////
class EventValueInfo : public ETW::IValueInfo
{ 
    // описание значений и индекс значения
    private: const EVENT_MAP_INFO* _pInfo; size_t _index; 

    // конструктор
    public: EventValueInfo(const EVENT_MAP_INFO* pInfo, size_t index)

        // сохранить переданные параметры
        : _pInfo(pInfo), _index(index) {}

    // значение
    public: virtual ULONGLONG Value() const override 
    { 
        // значение
        return _pInfo->MapEntryArray[_index].Value; 
    }
    // имя значения
    public: virtual PCWSTR Name() const override 
    {
        // определить смещение имени
        ULONG offset = _pInfo->MapEntryArray[_index].OutputOffset; 

        // проверить наличие имени
        if (offset == 0) return nullptr; 
        
        // вернуть имя значения
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
};

class ProviderValueInfo : public ETW::IValueInfo
{ 
    // описание значений и индекс значения
    private: const PROVIDER_FIELD_INFOARRAY* _pInfo; size_t _index; 

    // конструктор
    public: ProviderValueInfo(const PROVIDER_FIELD_INFOARRAY* pInfo, size_t index)

        // сохранить переданные параметры
        : _pInfo(pInfo), _index(index) {}

    // значение
    public: virtual ULONGLONG Value() const override 
    { 
        // значение
        return _pInfo->FieldInfoArray[_index].Value; 
    }
    // имя значения
    public: virtual PCWSTR Name() const override 
    {
        // определить смещение имени
        ULONG offset = _pInfo->FieldInfoArray[_index].NameOffset; 

        // проверить наличие имени
        if (offset == 0) return nullptr; 
        
        // вернуть имя значения
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
    // описание значения
    public: virtual PCWSTR Description() const override 
    {
        // определить смещение описания
        ULONG offset = _pInfo->FieldInfoArray[_index].DescriptionOffset; 

        // проверить наличие описания
        if (offset == 0) return nullptr; 
        
        // вернуть описание значения
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
class EventValueMap : public ETW::IValueMap
{ 
    // буфер и таблица описаний битов 
    private: std::vector<BYTE> _buffer; std::vector<EventValueInfo> _map;

    // конструктор
    public: EventValueMap(const EVENT_RECORD*, PCWSTR); 

    // тип значений
    public: virtual ETW::ValueMapType Type() const override
    {
        // преобразовать тип буфера
        const EVENT_MAP_INFO* pInfo = (const EVENT_MAP_INFO*)&_buffer[0]; 

        // проверить тип значений
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) != 0) return ETW::ValueMapType::Flag; 
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP    ) != 0) return ETW::ValueMapType::Flag; 
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP  ) != 0)
        {
            // проверить тип значений
            if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_FLAG  ) != 0) return ETW::ValueMapType::Flag;
        }
        return ETW::ValueMapType::Index;
    }
    // число описаний
    public: virtual size_t Count() const override { return _map.size(); } 
    // описание значений или битов
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

class ProviderValueMap : public ETW::IValueMap
{ 
    // буфер и таблица описаний битов 
    private: std::vector<BYTE> _buffer; std::vector<ProviderValueInfo> _map;

    // конструктор
    public: ProviderValueMap(const GUID&, EVENT_FIELD_TYPE); 

    // тип значений
    public: virtual ETW::ValueMapType Type() const override
    {
        // преобразовать тип буфера
        const PROVIDER_FIELD_INFOARRAY* pInfo = (const PROVIDER_FIELD_INFOARRAY*)&_buffer[0]; 

        // вернуть тип значений
        return (pInfo->FieldType == EventKeywordInformation) ? ETW::ValueMapType::Flag : ETW::ValueMapType::Index; 
    }
    // число описаний
    public: virtual size_t Count() const override { return _map.size(); } 
    // описание значений или битов
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

///////////////////////////////////////////////////////////////////////////////
// Булевский тип
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public ETW::BooleanType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: BooleanType(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Типы чисел
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public ETW::Int8Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: Int8Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt8Type : public ETW::UInt8Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: UInt8Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int16Type : public ETW::Int16Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: Int16Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt16Type : public ETW::UInt16Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: UInt16Type(const class Event&, const EVENT_PROPERTY_INFO&);  
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int32Type : public ETW::Int32Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: Int32Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt32Type : public ETW::UInt32Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: UInt32Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int64Type : public ETW::Int64Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: Int64Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt64Type : public ETW::UInt64Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: UInt64Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class FloatType : public ETW::FloatType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: FloatType(const class Event& event, const EVENT_PROPERTY_INFO& info) : _event(event), _info(info) {}

    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class DoubleType : public ETW::DoubleType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: DoubleType(const class Event& event, const EVENT_PROPERTY_INFO& info) : _event(event), _info(info) {}

    // физический тип данных и способ форматирования
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип указателя или числа разрядности указателя
///////////////////////////////////////////////////////////////////////////////
class PointerType : public ETW::PointerType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // описание значений или битов
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // конструктор
    public: PointerType(const class Event&, const EVENT_PROPERTY_INFO&);  

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип строк
///////////////////////////////////////////////////////////////////////////////
class StringType : public ETW::StringType
{
    // адрес буфера и описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: StringType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // определить размер строки
    protected: virtual size_t GetLength(const ETW::IContainer*) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип времени
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public ETW::DateTimeType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: DateTimeType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
 
class CimDateTimeType : public ETW::CimDateTimeType
{
    // описание данных и способ декодирования строк
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; StringType _decoder;

    // конструктор
    public: CimDateTimeType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info), _decoder(event, info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // способ декодирования строк
    protected: virtual const BasicType& Decoder() const override { return _decoder; } 
};

///////////////////////////////////////////////////////////////////////////////
// Бинарный тип данных
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public ETW::BinaryType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info;

    // конструктор
    public: BinaryType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // определить размер буфера
    protected: virtual size_t GetSize(const ETW::IContainer&) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Специальные типы данных
///////////////////////////////////////////////////////////////////////////////
class GuidType : public ETW::GuidType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: GuidType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class SidType : public ETW::SidType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: SidType(const class Event& event, const EVENT_PROPERTY_INFO& info);  
        
    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class IPv4Type : public ETW::IPv4Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: IPv4Type(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class IPv6Type : public ETW::IPv6Type
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: IPv6Type(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class SocketAddressType : public ETW::SocketAddressType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // конструктор
    public: SocketAddressType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // сохранить переданные параметры
        : _event(event), _info(info) {}

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
///////////////////////////////////////////////////////////////////////////////
// Тип массива
///////////////////////////////////////////////////////////////////////////////
class ArrayType : public ETW::IArrayType
{
    // описание данных
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info;
    // тип элемента
    private: std::shared_ptr<ETW::IElementType> _pElementType; 

    // конструктор
    public: ArrayType(const class Event& event, const EVENT_PROPERTY_INFO& info);  

    // описание типа элемента
    public: virtual const ETW::IElementType& ElementType() const override { return *_pElementType; }
    
    // определить размер массива
    public: virtual size_t GetCount(const ETW::IContainer& parent) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип структуры
///////////////////////////////////////////////////////////////////////////////
class StructType : public ETW::IStructType
{
    // идентификатор и таблица полей
    private: GUID _id; std::vector<ETW::Field> _fields; 

    // конструктор
    public: StructType(const class Event& event, size_t startIndex, size_t count); 

    // GUID структуры
    public: virtual REFGUID Guid() const override { return _id; }

    // число полей
    public: virtual size_t FieldCount() const override { return _fields.size(); }   
    // получить поле по индексу
    public: virtual const ETW::IField& GetField(size_t i) const override { return _fields[i]; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Cобытие и связанные с ним метаданные
///////////////////////////////////////////////////////////////////////////////
class Event : public ETW::IEvent
{
    // внешний контекст 
    private: TDH_CONTEXT* _pContext; ULONG _cntContext; 
    // запись и метаданные события
    private: const EVENT_RECORD* _pEvent; std::vector<BYTE> _vecEventInfo;

    // тип структуры
    private: std::unique_ptr<ETW::IStructType> _pStructType; 
    // раскодированная структура
    private: std::unique_ptr<ETW::IStruct> _pStruct; 

    // конструктор
    public: Event(TDH_CONTEXT* pContext, ULONG cntContext, const EVENT_RECORD* pEvent); 

    // адрес и размер данных
    public: virtual const void* GetDataAddress() const override { return _pEvent->UserData;       }
    public: virtual size_t      GetDataSize   () const override { return _pEvent->UserDataLength; }

    // описание раскодированного события
    public: const TRACE_EVENT_INFO* GetEventInfo() const 
    {
        // описание раскодированного события
        return (const TRACE_EVENT_INFO*)&_vecEventInfo[0]; 
    }
    // получить описания значения или битов
    public: std::shared_ptr<ETW::IValueMap> GetValueMap(const EVENT_PROPERTY_INFO& info) const; 

    // раскодированная структура
    public: virtual const ETW::IStruct& Struct() const override { return *_pStruct; }

    // размер указателя
    public: virtual size_t PointerSize() const override
    { 
        // определить размер указателя
        if (_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) return 4;
        if (_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) return 8;

        // вернуть размер указателя
        return sizeof(void*); 
    }
    // создать простой тип данных
    public: ETW::IBasicType* CreateBasicType(const EVENT_PROPERTY_INFO& info) const; 

    // получить строковое представление элемента
    public: std::wstring Format(const ETW::IContainer& parent, 
        const EVENT_PROPERTY_INFO& info, const void* pvData, size_t cbData) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Описание провайдера
///////////////////////////////////////////////////////////////////////////////
class ProviderInfo : public ETW::IProviderInfo
{
    // идентификатор провайдера и описание категорий и уровней
    private: GUID _id; ProviderValueMap _keywords; ProviderValueMap _levels;

    // конструктор
    public: ProviderInfo(const GUID& id) : _id(id), 
        
        // прочитать описание категорий и уровней
        _keywords(_id, EventKeywordInformation), _levels  (_id, EventLevelInformation) {} 

    // идентификатор провайдера
    public: virtual const GUID& ID() const { return _id; }

    // получить описание категорий трассировки
    public: virtual const ETW::IValueMap& Keywords() const override { return _keywords; }
    // получить описание уровней трассировки
    public: virtual const ETW::IValueMap& Levels() const override { return _levels; }
}; 
}
