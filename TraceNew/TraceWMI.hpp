#pragma once
#include "TraceWMI.h"
#include "TraceETW.hpp"
#include <comdef.h>

///////////////////////////////////////////////////////////////////////////////
// Определения интерфейсов
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(IWbemServices    , __uuidof(IWbemServices    ));
_COM_SMARTPTR_TYPEDEF(IWbemClassObject , __uuidof(IWbemClassObject ));
_COM_SMARTPTR_TYPEDEF(IWbemQualifierSet, __uuidof(IWbemQualifierSet));

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// Описание значения или бита
///////////////////////////////////////////////////////////////////////////////
class ValueInfo : public ETW::IValueInfo
{ 
    // значение, его имя и описаниеж
    private: ULONGLONG _value; _bstr_t _bstrName; _bstr_t _bstrDescription; 

    // конструктор
    public: ValueInfo(ULONGLONG value, BSTR bstrName, BSTR bstrDescription) 
        
        // сохранить переданные параметры
        : _value(value), _bstrName(bstrName), _bstrDescription(bstrDescription) {}

    // значение
    public: virtual ULONGLONG Value() const override { return _value; } 
    // имя значения
    public: virtual PCWSTR Name() const override { return _bstrName; } 

    // описание значения
    public: virtual PCWSTR Description() const override { return _bstrDescription; } 
};

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
class ValueMap : public ETW::IValueMap
{ 
    // тип значений и таблица описаний битов
    private: ETW::ValueMapType _valueType; std::vector<ValueInfo> _map;

    // конструктор
    public: ValueMap(IWbemQualifierSet* pQualifiers, BOOL forceFlags = FALSE); 
    // конструктор
    public: ValueMap() : _valueType(ETW::ValueMapType::Index) {}

    // тип значений
    public: virtual ETW::ValueMapType Type() const override { return _valueType; }

    // число описаний
    public: virtual size_t Count() const override { return _map.size(); } 
    // описание значений или битов
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

///////////////////////////////////////////////////////////////////////////////
// Булевский тип
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public ETW::BooleanType, public IBasicType 
{
    // атрибуты элемента и описание значений
    private: IWbemQualifierSetPtr _pQualifiers; ValueMap _valueMap; 

    // конструктор
    public: BooleanType(IWbemQualifierSet* pQualifiers) : _pQualifiers(pQualifiers), _valueMap(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return CIM_BOOLEAN; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BOOLEAN;  }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_BOOLEAN; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Типы чисел
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public ETW::Int8Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: Int8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt8Type : public ETW::UInt8Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: UInt8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int16Type : public ETW::Int16Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: Int16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt16Type : public ETW::UInt16Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: UInt16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический тип данных и способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int32Type : public ETW::Int32Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: Int32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt32Type : public ETW::UInt32Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: UInt32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int64Type : public ETW::Int64Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: Int64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический тип данных и способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt64Type : public ETW::UInt64Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // способ форматирования и описание значений
    private: USHORT _outType; ValueMap _valueMap;

    // конструктор
    public: UInt64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // способ форматирования
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class FloatType : public ETW::FloatType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: FloatType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};
class DoubleType : public ETW::DoubleType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: DoubleType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

///////////////////////////////////////////////////////////////////////////////
// Тип указателя или числа разрядности указателя
///////////////////////////////////////////////////////////////////////////////
class PointerType : public ETW::PointerType, public IBasicType 
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; ValueMap _valueMap; 
    // физический и логический типы элемента
    private: USHORT _inType; USHORT _outType; size_t _pointerSize; 

    // конструктор
    public: PointerType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _inType;  }
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить описание значений или битов
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // получить описание значений или битов
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Тип строк
///////////////////////////////////////////////////////////////////////////////
class StringType : public ETW::StringType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // физический и логический типы элемента
    private: USHORT _inType; USHORT _outType; 

    // конструктор
    public: StringType(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return _inType;  }
    public: virtual USHORT OutputType() const override { return _outType; }

    // получить размер элемента
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 

    // определить размер строки
    protected: virtual size_t GetLength(const ETW::IContainer*) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип времени
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public ETW::DateTimeType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; 

    // конструктор
    public: DateTimeType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_FILETIME;  }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_DATETIME; }
};
 
class CimDateTimeType : public ETW::CimDateTimeType, public IBasicType
{
    // тип, атрибуты элемента и способ декодирования строк
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; StringType _decoder;

    // конструктор
    public: CimDateTimeType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers), _decoder(type, pQualifiers) {}
        
    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // логический тип данных
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_CIMDATETIME; }

    // способ декодирования строк
    protected: virtual const BasicType& Decoder() const override { return _decoder; } 
};

///////////////////////////////////////////////////////////////////////////////
// Бинарный тип данных
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public ETW::BinaryType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: BinaryType(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}
        
    // тип данных
    public: virtual CIMTYPE CimType() const override { return CIM_OBJECT; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический и логический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_HEXDUMP;    }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_HEXBINARY; }
};

///////////////////////////////////////////////////////////////////////////////
// Специальные типы данных
///////////////////////////////////////////////////////////////////////////////
class GuidType : public ETW::GuidType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: GuidType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

class SidType : public ETW::SidType, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: SidType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize)

        // сохранить переданные параметры
        : ETW::SidType(pointerSize), _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // физический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_WBEMSID; }
};

class IPv4Type : public ETW::IPv4Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: IPv4Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

class IPv6Type : public ETW::IPv6Type, public IBasicType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // конструктор
    public: IPv6Type(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // сохранить переданные параметры
        : _type(type), _pQualifiers(pQualifiers) {}

    // тип данных
    public: virtual CIMTYPE CimType() const override { return _type; }
    // атрибуты поля
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};
 
///////////////////////////////////////////////////////////////////////////////
// Тип массива
///////////////////////////////////////////////////////////////////////////////
class ArrayType : public ETW::IArrayType
{
    // тип и атрибуты элемента
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // тип элементов массива
    private: std::shared_ptr<ETW::IElementType> _pElementType; 

    // конструктор
    public: ArrayType(const class Event&, CIMTYPE, IWbemQualifierSet*); 

    // описание типа элемента
    public: virtual const ETW::IElementType& ElementType() const override 
    { 
        return *_pElementType; 
    } 
    // определить размер массива
    public: virtual size_t GetCount(const ETW::IContainer& parent) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип структуры
///////////////////////////////////////////////////////////////////////////////
class StructType : public ETW::IStructType
{
    // идентификатор и объект структуры
    private: GUID _id; IWbemClassObjectPtr _pClass; 
    // идентификатор, имя класса и таблица полей
    private: std::wstring _name; std::vector<ETW::Field> _fields; 

    // конструктор
    public: StructType(const class Event&, IWbemClassObject*, PCWSTR); 

    // GUID структуры
    public: virtual REFGUID Guid() const override { return _id; }
    // имя структуры
    public: virtual PCWSTR Name() const override { return _name.c_str(); }

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
    // пространство имен и размер указателя
    private: IWbemServicesPtr _pNamespace; size_t _pointerSize; 
    // запись события и объект структуры
    private: const EVENT_TRACE* _pEvent; IWbemClassObjectPtr _pClass; 

    // тип структуры
    private: std::unique_ptr<ETW::IStructType> _pStructType; 
    // раскодированная структура
    private: std::unique_ptr<ETW::IStruct> _pStruct; 

    // конструктор
    public: Event(IWbemServices*, IWbemClassObject*, const EVENT_TRACE*, size_t); 

    // адрес и размер данных
    public: virtual const void* GetDataAddress() const override { return _pEvent->MofData;   }
    public: virtual size_t      GetDataSize   () const override { return _pEvent->MofLength; }

    // раскодированная структура
    public: virtual const ETW::IStruct& Struct() const override { return *_pStruct; }

    // размер указателя
    public: virtual size_t PointerSize() const override { return _pointerSize; }

    // создать тип элемента
    public: ETW::IElementType* CreateElementType(CIMTYPE type, IWbemQualifierSet* pQualifiers) const; 
};  

///////////////////////////////////////////////////////////////////////////////
// Описание провайдера
///////////////////////////////////////////////////////////////////////////////
class ProviderInfo : public ETW::IProviderInfo
{
    // объект пространства имен и GUID провайдера
    private: IWbemServicesPtr _pNamespace; GUID _id; 
    // объект класса провайдера
    private: IWbemClassObjectPtr _pProvider; 

    // описание категорий и уровней
    private: std::unique_ptr<ValueMap> _pKeywords; 
    private: std::unique_ptr<ValueMap> _pLevels;

    // конструктор
    public: ProviderInfo(IWbemServices*, const GUID&, IWbemClassObject*); 
        
    // идентификатор провайдера
    public: virtual const GUID& ID() const { return _id; }

    // получить описание категорий трассировки
    public: virtual const ETW::IValueMap& Keywords() const override { return *_pKeywords; } 
    // получить описание уровней трассировки
    public: virtual const ETW::IValueMap& Levels() const override { return *_pLevels; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Пространство имен WMI
///////////////////////////////////////////////////////////////////////////////
class Namespace : public INamespace
{
    // конструктор
    public: Namespace(IWbemServices* pNamespace) : _pNamespace(pNamespace) {}
    // конструктор
    public: Namespace(); private: IWbemServicesPtr _pNamespace;

    // найти провайдер событий
    public: virtual std::unique_ptr<ETW::IProviderInfo> FindEventProvider(REFGUID guid) const override
    {
        // найти класс провайдера события 
        IWbemClassObjectPtr pProviderClass = FindEventProviderClass(guid); 

        // проверить наличие провайдера
        if (!pProviderClass) return std::unique_ptr<ETW::IProviderInfo>(); 

        // вернуть провайдер событий
        return std::unique_ptr<ETW::IProviderInfo>(new ProviderInfo(_pNamespace, guid, pProviderClass)); 
    }
    // раскодировать событие
    public: virtual std::unique_ptr<ETW::IEvent> DecodeEvent(PEVENT_TRACE pEvent, size_t pointerSize) const override
    {
        // перейти на заголовок события
        const EVENT_TRACE_HEADER& header = pEvent->Header; 

        // получить идентификатор события
        REFGUID guid = (header.Flags & WNODE_FLAG_USE_GUID_PTR) ? *(GUID*)header.GuidPtr : header.Guid; 

        // найти класс события 
        IWbemClassObjectPtr pEventClass = FindEventClass(guid, header.Class.Version, header.Class.Type); 

        // проверить наличие события
        if (!pEventClass) ETW::Exception::Throw(WBEM_E_NOT_FOUND); 

        // раскодировать событие
        return std::unique_ptr<ETW::IEvent>(new Event(_pNamespace, pEventClass, pEvent, pointerSize)); 
    }
    // найти класс провайдера события 
    private: IWbemClassObjectPtr FindEventProviderClass(REFGUID) const; 
    // найти класс категории события
    private: IWbemClassObjectPtr FindEventCategoryClass(REFGUID, USHORT) const; 
    // найти класс события
    private: IWbemClassObjectPtr FindEventClass(REFGUID, USHORT, UCHAR) const; 
};
}
