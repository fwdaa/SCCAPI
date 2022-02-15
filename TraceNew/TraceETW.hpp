#include <windows.h>
#include "TraceETW.h"
#include <tdh.h>
#include <wbemidl.h>
#include <in6addr.h>

///////////////////////////////////////////////////////////////////////////////
// Стандартная библиотека C++
///////////////////////////////////////////////////////////////////////////////
#include <stdexcept>    // std::runtime_error
#include <memory>       // std::shared_ptr
#include <string>       // std::string, std::wstring
#include <vector>       // std::vector
#include <map>          // std::map
#include <sstream>      // std::wostringstream
#include <ios>          // std::dec, std::hex, std::fixed

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// Исключение
///////////////////////////////////////////////////////////////////////////////
class Exception : public std::runtime_error
{
    // код и описание ошибки
    private: HRESULT _status; std::string _strMessage; 

    // выбросить исключение
    public: static __declspec(noreturn) void Throw(HRESULT status) { throw Exception(status); }
    // выбросить исключение
    public: static __declspec(noreturn) void Throw(HRESULT, IUnknown*, REFIID);

    // конструктор
    public: Exception(HRESULT status, IErrorInfo* pErrorInfo = nullptr); 

    // описание ошибки
    public: virtual const char* what() const { return _strMessage.c_str(); }  
    // код ошибки
    public: HRESULT status() const { return _status; }
};

inline __declspec(noreturn) void ThrowBadData()
{
    // выбросить исключение
    Exception::Throw(HRESULT_FROM_WIN32(ERROR_INVALID_DATA)); 
}

///////////////////////////////////////////////////////////////////////////////
// Простой тип
///////////////////////////////////////////////////////////////////////////////
struct BasicType : IBasicType
{
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const = 0;

    // физический и логический тип данных
    public: virtual USHORT InputType () const = 0; 
    public: virtual USHORT OutputType() const = 0; 

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const {}
};
 
///////////////////////////////////////////////////////////////////////////////
// Булевский тип
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BOOLEAN; }
    // способ форматирования объекта
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_BOOLEAN; }

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_BOOL; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // получить размер элемента
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 
    // получить значение элемента
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип чисел
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_INT8; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_I1; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT8; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(CHAR)) ThrowBadData(); return sizeof(CHAR); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_I1(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            BYTE value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt8Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_UINT8; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_UI1; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT8; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(BYTE)) ThrowBadData(); return sizeof(BYTE); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_UI1(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            BYTE value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int16Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_INT16; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_I2; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT16; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(SHORT)) ThrowBadData(); return sizeof(SHORT); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_I2(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            USHORT value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt16Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_UINT16; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_UI2; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT16; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(USHORT)) ThrowBadData(); return sizeof(USHORT); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_UI2(&var), pvData, cbData); 
        
        // для номера порта
        if (OutputType() == TDH_OUTTYPE_PORT)
        {
             // изменить порядок следования байтов
            V_UI2(&var) = MAKEWORD(HIWORD(V_UI2(&var)), LOWORD(V_UI2(&var))); 
        }
        return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            USHORT value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int32Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_INT16; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_I4; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT32; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(LONG)) ThrowBadData(); return sizeof(LONG); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_I4(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            ULONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt32Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_UINT32; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_UI4; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT32; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(ULONG)) ThrowBadData(); return sizeof(ULONG); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_UI4(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            ULONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int64Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_INT64; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_I8; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT64; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(LONGLONG)) ThrowBadData(); return sizeof(LONGLONG); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_I8(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            ULONGLONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt64Type : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_UINT64; } 

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_UI8; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип данных
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT64; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(ULONGLONG)) ThrowBadData(); return sizeof(ULONGLONG); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_UI8(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // вернуть строковое представление значения
            ULONGLONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class FloatType : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_FLOAT; } 
    // способ форматирования значения
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_FLOAT; }

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_R4; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип значения 
    public: virtual USHORT InputType() const override { return TDH_INTYPE_FLOAT; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(FLOAT)) ThrowBadData(); return sizeof(FLOAT); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_R4(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override
    {
        // получить строковое представление
        stream << std::fixed << V_R4(&value);
    }
};

class DoubleType : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_DOUBLE; } 
    // способ форматирования значения
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_DOUBLE; }

    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_R8; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип значения 
    public: virtual USHORT InputType() const override { return TDH_INTYPE_DOUBLE; }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(DOUBLE)) ThrowBadData(); return sizeof(DOUBLE); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // скопировать значение
        memcpy(&V_R8(&var), pvData, cbData); return var; 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override
    {
        // получить строковое представление
        stream << std::fixed << V_R8(&value);
    }
};

///////////////////////////////////////////////////////////////////////////////
// Тип указателя или числа разрядности указателя
///////////////////////////////////////////////////////////////////////////////
class PointerType : public BasicType
{
    // конструктор
    public: PointerType(size_t pointerSize) 
        
        // сохранить переданные параметры
        : _pointerSize(pointerSize) {} private: size_t _pointerSize; 

    // логический тип элемента
    public: virtual ULONG LogicalType() const override
    {
        // логический тип элемента
        return (InputType() == TDH_INTYPE_POINTER) ? TYPE_POINTER : TYPE_SIZE_T;  
    }
    // COM-тип элемента
    public: virtual VARTYPE VariantType() const override
    {
        // COM-тип элемента
        return (VARTYPE)((_pointerSize == 4) ? VT_UI4 : VT_UI8); 
    }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // физический тип значения 
    public: virtual USHORT InputType() const override 
    { 
        // физический тип значения 
        return (VARTYPE)((_pointerSize == 4) ? TDH_INTYPE_UINT32 : TDH_INTYPE_UINT64); 
    }
    // получить размер элемента
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < _pointerSize) ThrowBadData(); return _pointerSize; 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // инициализировать переменную
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 

        if (_pointerSize == 4)
        {
            // скопировать значение
            memcpy(&V_UI4(&var), pvData, cbData); return var; 
        }
        else {
            // скопировать значение
            memcpy(&V_UI8(&var), pvData, cbData); return var; 
        }
    }
    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            if (_pointerSize == 4) { ULONG value; 
            
                // вернуть строковое представление значения
                memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
            }
            else { ULONGLONG value; 

                // вернуть строковое представление значения
                memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
            }
        }
        // вызвать базовую функцию
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};
 
///////////////////////////////////////////////////////////////////////////////
// Тип строк
///////////////////////////////////////////////////////////////////////////////
class StringType : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_STRING; }

    // СOM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_BSTR; } 
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }  

    // получить размер элемента
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 
    // получить значение элемента
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // определить размер строки
    protected: virtual size_t GetLength(const ETW::IContainer*) const { return SIZE_MAX; } 

    // получить строковое представление
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override; 
    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Тип времени
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public BasicType
{
    // конструктор
    public: DateTimeType(); private: ISWbemDateTime* _pConvert;
    // деструктор
    public: virtual ~DateTimeType() { if (_pConvert) _pConvert->Release(); }

    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_DATE; }  

    // СOM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_DATE; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // получить размер элемента
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // получить значение элемента
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 

    // раскодировать строку
    protected: VARIANT DecodeString(BSTR bstrString) const; 
};
 
class CimDateTimeType : public DateTimeType
{
    // физический тип значения 
    public: virtual USHORT InputType() const override { return Decoder().InputType(); }
    // получить размер элемента
    public: virtual size_t GetSize(const IContainer& parent, const void* pvData, size_t cbRemaining) const override
    {
        // получить размер элемента
        return Decoder().GetSize(parent, pvData, cbRemaining); 
    }
    // получить значение элемента
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // извлечь значение строки
        VARIANT varString = Decoder().GetValue(pvData, cbData); 
        try {
            // раскодировать строку
            VARIANT varValue = DecodeString(V_BSTR(&varString));  

            // освободить выделенные ресурсы
            ::VariantClear(&varString); return varValue; 
        }
        // при ошибке освободить выделенные ресурсы
        catch (...) { ::VariantClear(&varString); throw; }
    }
    // способ декодирования строк
    protected: virtual const BasicType& Decoder() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Бинарный тип данных
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public BasicType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY; } 

    // СOM-тип элемента
    public: virtual VARTYPE VariantType() const override { return VT_UI1 | VT_ARRAY; }
    // совпадение c COM-представлением
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // получить размер элемента
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // получить значение элемента
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // определить размер буфера
    protected: virtual size_t GetSize(const ETW::IContainer&) const { return SIZE_MAX; } 

    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Специальные типы данных
///////////////////////////////////////////////////////////////////////////////
class GuidType : public BinaryType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_GUID; }

    // физический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_GUID; }
    // способ форматирования
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_GUID; }

    // получить размер элемента
    public: virtual size_t GetSize(const IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(GUID)) ThrowBadData(); return sizeof(GUID); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class SidType : public BinaryType
{
    // конструктор
    public: SidType(size_t pointerSize) : _pointerSize(pointerSize) {} private: size_t _pointerSize;

    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_SID; }
    // способ форматирования
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_STRING; }

    // получить размер элемента
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // получить значение элемента
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class IPv4Type : public UInt32Type
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_UINT32_IPV4; }
    // способ форматирования
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_IPV4; }

    // получить строковое представление
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class IPv6Type : public BinaryType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_IPV6; }
    // способ форматирования
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_IPV6; }

    // физический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BINARY; }
    // получить размер элемента
    public: virtual size_t GetSize(const IContainer&, const void*, size_t cbRemaining) const override
    {
        // проверить наличие данных
        if (cbRemaining < sizeof(IN6_ADDR)) ThrowBadData(); return sizeof(IN6_ADDR); 
    }
    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class SocketAddressType : public BinaryType
{
    // логический тип элемента
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_SOCKETADDRESS; }
    // способ форматирования
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_SOCKETADDRESS; }

    // физический тип данных
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BINARY; }

    // получить строковое представление
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Элемент простого типа
///////////////////////////////////////////////////////////////////////////////
class BasicElement : public IBasicElement
{
    // путь элемента и его тип
    private: const IContainer& _parent; std::wstring _path; const IBasicType& _type; 
    // адрес и размер данных 
    private: const void* _pvData; size_t _cbData; 

    // конструктор
    public: BasicElement(const IContainer& parent, const std::wstring& path, 
        const IBasicType& type, const void* pvData, size_t cbData)

        // сохранить переданные параметры
        : _parent(parent), _path(path), _type(type), _pvData(pvData) 
    {
        // определить размер данных
        _cbData = type.GetSize(parent, pvData, cbData); 
    }
    // путь к элементу
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // тип элемента
    public: virtual const IElementType& Type() const override { return _type; }

    // адрес и размер данных
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // строковое представление
    public: virtual BSTR ToString() const override
    { 
        // получить строковое представление
        return _type.ToString(_parent, _pvData, _cbData); 
    }
}; 
///////////////////////////////////////////////////////////////////////////////
// Массив
///////////////////////////////////////////////////////////////////////////////
class Array : public IContainer
{
    // путь элемента и его тип
    private: std::wstring _path; const IArrayType& _type; 
    // адрес, размер данных и COM-массив
    private: const void* _pvData; size_t _cbData; SAFEARRAY* _pSafeArray;

    // конструктор
    public: Array(const IContainer&, const std::wstring&, const IArrayType&, const void*, size_t); 
    // деструктор
    public: virtual ~Array() { ::SafeArrayDestroy(_pSafeArray); }

    // путь к элементу
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // тип элемента
    public: virtual const IElementType& Type() const override { return _type; }

    // адрес и размер данных
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // значение элемента
    public: virtual VARIANT GetValue() const override
    {
        // указать тип массива
        VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = Type().VariantType(); 

        // скопировать значение массива
        HRESULT hr = ::SafeArrayCopy(_pSafeArray, &V_ARRAY(&varValue)); 
        
        // проверить отсутствие ошибок
        if (FAILED(hr)) Exception::Throw(hr); return varValue; 
    }
    // число элементов
    public: virtual size_t Count() const override { return _items.size(); }
    // получить описание внутреннего элемента
    public: virtual const IElement& operator[](size_t i) const override { return *_items[i]; }
    // таблица элементов
    private: std::vector<std::shared_ptr<IElement> > _items; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Поле структуры
///////////////////////////////////////////////////////////////////////////////
class Field : public IField
{
    // имя и тип поля структуры
    private: std::wstring _name; std::shared_ptr<IElementType> _pType; 

    // конструктор
    public: Field(const std::wstring& name, const std::shared_ptr<IElementType>& pType)

        // сохранить переданные параметры
        : _name(name), _pType(pType) {} 

    // имя поля структуры
    public: virtual PCWSTR Name() const override { return _name.c_str(); } 
    // тип поля структуры
    public: virtual const IElementType& Type() const override { return *_pType; }
};

///////////////////////////////////////////////////////////////////////////////
// COM-описание структуры
///////////////////////////////////////////////////////////////////////////////
class RecordInfo : public IRecordInfo
{
    // описание полей, размер структуры и счетчик ссылок
    private: const IStructType& _structType; ULONG _cb; ULONG _cRef;

    // конструктор
    public: RecordInfo(const IStructType& structType); 
    // деструктор
    protected: virtual ~RecordInfo() {}

    // запросить интерфейс
    public: STDMETHOD(QueryInterface)(REFIID riid, void** ppv) override; 

    // увеличить счетчик ссылок
    public: STDMETHOD_(ULONG, AddRef)() override 
    { 
        // увеличить счетчик ссылок
        return ::InterlockedIncrement(&_cRef); 
    }
    // уменьшить счетчик ссылок
    public: STDMETHOD_(ULONG, Release)() override 
    { 
        // уменьшить счетчик ссылок
        ULONG cRef = ::InterlockedDecrement(&_cRef); 

        // при необходимости удалить объект
        if (cRef == 0) delete this; return cRef; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Информационные фукции
    ///////////////////////////////////////////////////////////////////////////

    // GUID типа структуры
    public: STDMETHOD(GetGuid)(GUID* pguid) override
    {
        // скопировать GUID типа структуры
        if (!pguid) return E_POINTER; *pguid = _structType.Guid(); return S_OK; 
    }
    // имя структуры
    public: STDMETHOD(GetName)(BSTR* pbstrName) override
    {
        // проверить наличие указателя
        if (!pbstrName) return E_POINTER; PCWSTR szName = _structType.Name(); 

        // проверить наличие имени
        if (!szName) { *pbstrName = nullptr; return S_OK; }

        // скопировать имя структуры
        *pbstrName = ::SysAllocString(szName); 

        // проверить отсутствие ошибок
        return (*pbstrName) ? S_OK : E_OUTOFMEMORY; 
    }
    // проверить совпадение структур
    public: STDMETHOD_(BOOL, IsMatchingType)(IRecordInfo* pRecordInfo) override; 

    // получить интерфейс ITypeInfo
    public: STDMETHOD(GetTypeInfo)(ITypeInfo**) override
    {
        // операция не поддерживается
        return TYPE_E_INVALIDSTATE; 
    }
    // получить размер структруры
    public: STDMETHOD(GetSize)(ULONG* pcbSize) override
    {
        // вернуть размер структруры
        if (!pcbSize) return E_POINTER; *pcbSize = _cb; return S_OK;
    }
    // перечислить имена полей
    public: STDMETHOD(GetFieldNames)(ULONG* pcNames, BSTR* rgBstrNames) override; 

    ///////////////////////////////////////////////////////////////////////////
    // Создание, удаление и копирование структуры
    ///////////////////////////////////////////////////////////////////////////

    // выделить память для структуры
    public: STDMETHOD_(PVOID, RecordCreate)() override
    {
        // выделить память для структуры
        return ::CoTaskMemAlloc(_cb); 
    }
    // освободить память структуры
    public: STDMETHOD(RecordDestroy)(PVOID pvRecord) override
    {
        // освободить память структуры
        ::CoTaskMemFree(pvRecord); return S_OK; 
    }
    // выделить память и скопировать структуру
    public: STDMETHOD(RecordCreateCopy)(PVOID pvSource, PVOID* ppvDest) override; 

    // инициализировать структуру
    public: STDMETHOD(RecordInit)(PVOID pvNew) override
    {
        // инициализировать структуру
        memset(pvNew, 0, _cb); return S_OK; 
    }
    // освободить используемые ресурсы
    public: STDMETHOD(RecordClear)(PVOID pvExisting) override; 

    // скопировать структуру
    public: STDMETHOD(RecordCopy)(PVOID pvExisting, PVOID pvNew) override; 

    ///////////////////////////////////////////////////////////////////////////
    // Извлечение полей структуры
    ///////////////////////////////////////////////////////////////////////////
       
    // получить ссылку на значение поля
    public: STDMETHOD(GetFieldNoCopy)(PVOID pvData, 
        LPCOLESTR szFieldName, VARIANT* pvarField, PVOID* ppvDataCArray) override; 

    // получить значение поля 
    public: STDMETHOD(GetField)(PVOID pvData, 
        LPCOLESTR szFieldName, VARIANT* pvarField) override
    {
        // проверить наличие указателя
        if (!pvarField) return E_POINTER; VARIANT var; ::VariantInit(&var); 
    
        // получить ссылку на значение поля
        HRESULT hr = GetFieldNoCopy(pvData, szFieldName, &var, nullptr); 

        // выполнить копирование значения с разыменованием
        return (SUCCEEDED(hr)) ? ::VariantCopyInd(&var, pvarField) : hr; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Изменение полей структуры
    ///////////////////////////////////////////////////////////////////////////
     
    // установить значение поля с передачей владения
    public: STDMETHOD(PutFieldNoCopy)(ULONG wFlags, 
        PVOID pvData, LPCOLESTR szFieldName, VARIANT* pvarField) override; 

    // установить значение поля 
    public: STDMETHOD(PutField)(ULONG wFlags, 
        PVOID pvData, LPCOLESTR szFieldName, VARIANT* pvarField) override
    {
        // проверить наличие указателя
        if (!pvarField) return E_POINTER; VARIANT var; ::VariantInit(&var); 

        // скопировать значение с копированием ресурсов
        HRESULT hr = ::VariantCopy(&var, pvarField); if (FAILED(hr)) return hr; 

        // установить значение поля с передачей владения
        hr = PutFieldNoCopy(wFlags, pvData, szFieldName, pvarField); 

        // проверить отсутствие ошибок
        if (FAILED(hr)) ::VariantClear(&var); return hr; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Определение индексов и смещений
    ///////////////////////////////////////////////////////////////////////////
    private: const IElementType* FindFieldType(LPCOLESTR szFieldName) const
    {
        // указать тип таблицы
        typedef std::map<std::wstring, size_t> map_type; 

        // найти элемент по имени
        typename map_type::const_iterator p = _indexes.find(szFieldName); 
        
        // вернуть найденный элемент
        return (p != _indexes.end()) ? &_structType.GetField(p->second).Type() : nullptr; 
    }
    private: const size_t FindFieldOffset(LPCOLESTR szFieldName) const
    {
        // указать тип таблицы
        typedef std::map<std::wstring, size_t> map_type; 

        // найти элемент по имени
        typename map_type::const_iterator p = _offsets.find(szFieldName); 
        
        // вернуть найденный элемент
        return (p != _offsets.end()) ? p->second : SIZE_MAX; 
    }
    // список индексов полей
    private: std::map<std::wstring, size_t> _indexes; 
    // список смещений полей
    private: std::map<std::wstring, size_t> _offsets; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Структура
///////////////////////////////////////////////////////////////////////////////
class Struct : public IStruct
{
    // путь элемента и его тип
    private: std::wstring _path; const IStructType& _type;
    // адрес и размер данных 
    private: const void* _pvData; size_t _cbData; void* _pvRecord;

    // конструктор
    public: Struct(const std::wstring&, const IStructType&, const void*, size_t); 
    // деструктор
    public: virtual ~Struct() 
    { 
        // освободить выделенные ресурсы
        if (_pvRecord != _pvData) ::CoTaskMemFree(_pvRecord); 
    }
    // путь к элементу
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // тип элемента
    public: virtual const IElementType& Type() const override { return _type; }

    // адрес и размер данных
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // значение элемента
    public: virtual VARIANT GetValue() const override; 

    // число элементов
    public: virtual size_t Count() const override { return _items.size(); }

    // получить внутренний элемент
    public: virtual const IElement& operator[](size_t i) const override 
    { 
        // получить внутренний элемент
        return *_items.at(_names[i]); 
    }
    // найти элемент по пути
    public: virtual const ETW::IElement* FindPath(PCWSTR szPath) const override; 
    // найти элемент по имени
    public: virtual const IElement* FindName(PCWSTR szName) const override
    {
        // найти элемент по имени
        map_type::const_iterator p = _items.find(szName); 
        
        // вернуть найденный элемент
        return (p != _items.end()) ? p->second.get() : nullptr; 
    }
    // тип таблицы элементов
    private: typedef std::map<std::wstring, std::shared_ptr<IElement> > map_type; 
    // таблица имен и элементов
    private: std::vector<std::wstring> _names; map_type _items;
}; 

}
