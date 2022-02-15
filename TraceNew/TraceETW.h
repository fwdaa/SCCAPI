#pragma once
#include <evntrace.h>

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// Интерпретация SAFEARRAY как произвольного типа
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class VariantArrayCast
{
    // ссылка на переменный тип
    private: const VARIANT& _var; const T* _ptr; 

    // конструктор
    public: VariantArrayCast(const VARIANT& var) : _var(var), _ptr(nullptr)
    {
        // получить доступ к данным
        ::SafeArrayAccessData(V_ARRAY(&_var), (void**)&_ptr); 
    }
    // деструктор
    public: ~VariantArrayCast() 
    {
        // отказаться от доступа к данным
        if (_ptr) ::SafeArrayUnaccessData(V_ARRAY(&_var)); 
    } 
    // оператор преобразования типа
    public: operator const T*() const { return _ptr; }
};

///////////////////////////////////////////////////////////////////////////////
// Поддерживаемые типы данных
///////////////////////////////////////////////////////////////////////////////
const ULONG TYPE_NULL                     =  0 | (0 << 4) | (0 << 7); 
const ULONG TYPE_ARRAY                    =  0 | (0 << 4) | (1 << 7); 
const ULONG TYPE_STRUCT                   =  0 | (0 << 4) | (2 << 7); 
const ULONG TYPE_BOOLEAN                  =  1 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT8                     =  2 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT8                    =  3 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT16                    =  4 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT16                   =  5 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT32                    =  6 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT32                   =  7 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT32_IPV4              =  7 | (1 << 4) | (0 << 7); 
const ULONG TYPE_INT64                    =  8 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT64                   =  9 | (0 << 4) | (0 << 7); 
const ULONG TYPE_SIZE_T                   = 10 | (0 << 4) | (0 << 7); 
const ULONG TYPE_POINTER                  = 10 | (1 << 4) | (0 << 7); 
const ULONG TYPE_FLOAT                    = 11 | (0 << 4) | (0 << 7); 
const ULONG TYPE_DOUBLE                   = 12 | (0 << 4) | (0 << 7); 
const ULONG TYPE_DATE                     = 13 | (0 << 4) | (0 << 7); 
const ULONG TYPE_STRING                   = 14 | (0 << 4) | (0 << 7); 
const ULONG TYPE_BINARY                   = 15 | (0 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_GUID              = 15 | (1 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_SID               = 15 | (2 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_IPV6              = 15 | (3 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_SOCKETADDRESS     = 15 | (4 << 4) | (0 << 7); 

///////////////////////////////////////////////////////////////////////////////
// Описание значения или бита
///////////////////////////////////////////////////////////////////////////////
enum class ValueMapType { Index, Flag };

struct IValueInfo { virtual ~IValueInfo() {}

    // значение
    virtual ULONGLONG Value() const = 0; 
    // имя значения
    virtual PCWSTR Name() const = 0; 

    // описание значения
    virtual PCWSTR Description() const { return nullptr; }
};

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
struct IValueMap { virtual ~IValueMap() {}

    // тип значений
    virtual ValueMapType Type() const = 0; 
    // число описаний
    virtual size_t Count() const = 0; 

    // описание значений или битов
    virtual const IValueInfo& Item(size_t) const = 0; 

    // строковое представление значения
    virtual BSTR ToString(ULONGLONG value) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип элемента данных
///////////////////////////////////////////////////////////////////////////////
struct IElementType { virtual ~IElementType() {}

    // логический тип элемента
    virtual ULONG LogicalType() const = 0; 

    // COM-тип элемента
    virtual VARTYPE VariantType() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Элемент данных
///////////////////////////////////////////////////////////////////////////////
struct IElement { virtual ~IElement() {}

    // путь к элементу
    virtual PCWSTR Path() const = 0; 

    // адрес данных
    virtual const void* GetDataAddress() const = 0; 
    // размер данных
    virtual size_t GetDataSize() const = 0; 

    // тип элемента
    virtual const IElementType& Type() const = 0; 
    // значение элемента
    virtual VARIANT GetValue() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Элементы простого типа
///////////////////////////////////////////////////////////////////////////////
struct IBasicType : IElementType
{
    // описание значений или битов
    virtual const IValueMap* GetValueMap() const { return nullptr; } 

    // получить размер элемента
    virtual size_t GetSize(const struct IContainer&, const void*, size_t) const = 0; 

    // получить значение элемента
    virtual VARIANT GetValue(const void* pvData, size_t cbData) const = 0; 

    // получить строковое представление
    virtual BSTR ToString(const struct IContainer&, const void*, size_t) const { return nullptr; } 
};

struct IBasicElement : IElement
{
    // значение элемента
    virtual VARIANT GetValue() const override
    {
        // выполнить преобразование типа
        const IBasicType& type = (const IBasicType&)Type(); 

        // получить значение элемента
        return type.GetValue(GetDataAddress(), GetDataSize()); 
    }
    // строковое представление
    virtual BSTR ToString() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Контейнер с дочерними элементами
///////////////////////////////////////////////////////////////////////////////
struct IContainer : IElement
{ 
    // число элементов
    virtual size_t Count() const = 0; 

    // получить внутренний элемент
    virtual const IElement& operator[](size_t i) const = 0;
};

///////////////////////////////////////////////////////////////////////////////
// Массив
///////////////////////////////////////////////////////////////////////////////
struct IArrayType : IElementType
{
    // логический тип элемента
    virtual ULONG LogicalType() const override { return TYPE_ARRAY; }

    // COM-тип элемента
    virtual VARTYPE VariantType() const override 
    { 
        // получить тип дочернего элемента
        VARTYPE childType = ElementType().VariantType(); 

        // проверить наличие вложенности массива
        return (childType & VT_ARRAY) ? VT_ARRAY : (VT_ARRAY | childType); 
    }
    // базовый тип элементов
    virtual const IElementType& ElementType() const = 0; 

    // получить размер массива
    virtual size_t GetCount(const struct IContainer&) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Поле структуры
///////////////////////////////////////////////////////////////////////////////
struct IField
{
    // имя поля структуры
    virtual PCWSTR Name() const = 0; 
    // тип поля структуры
    virtual const IElementType& Type() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Структура
///////////////////////////////////////////////////////////////////////////////
struct IStructType : IElementType
{
    // логический тип элемента
    virtual ULONG LogicalType() const override { return TYPE_STRUCT; }
    // COM-тип элемента
    virtual VARTYPE VariantType() const override { return VT_RECORD; }

    // GUID структуры
    virtual REFGUID Guid() const = 0; 
    // имя структуры
    virtual PCWSTR Name() const { return nullptr; }

    // число полей
    virtual size_t FieldCount() const = 0;
    // получить поле по индексу
    virtual const IField& GetField(size_t i) const = 0;
}; 

struct IStruct : IContainer
{
    // найти элемент по имени
    virtual const IElement* FindName(PCWSTR szName) const = 0;  
    // найти элемент по пути
    virtual const IElement* FindPath(PCWSTR szPath) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Cобытие
///////////////////////////////////////////////////////////////////////////////
struct IEvent { virtual ~IEvent() {}

    // адрес и размер данных
    virtual const void* GetDataAddress() const = 0; 
    virtual size_t      GetDataSize   () const = 0; 

    // раскодированная структура
    virtual const IStruct& Struct() const = 0; 

    // размер указателя
    virtual size_t PointerSize() const = 0; 
};  

///////////////////////////////////////////////////////////////////////////////
// Описание провайдера
///////////////////////////////////////////////////////////////////////////////
struct IProviderInfo { virtual ~IProviderInfo() {}

    // идентификатор провайдера
    virtual const GUID& ID() const = 0; 

    // получить описание категорий трассировки
    virtual const IValueMap& Keywords() const = 0; 
    // получить описание уровней трассировки
    virtual const IValueMap& Levels() const = 0; 
}; 

}
