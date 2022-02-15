#include <windows.h>
#include "TraceWMI.hpp"
#include <comdef.h>
#include <comip.h>
#include <comutil.h>

///////////////////////////////////////////////////////////////////////////////
// Определения интерфейсов
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(IWbemLocator        , __uuidof(IWbemLocator        ));
_COM_SMARTPTR_TYPEDEF(IEnumWbemClassObject, __uuidof(IEnumWbemClassObject));

///////////////////////////////////////////////////////////////////////////////
// Исключение
///////////////////////////////////////////////////////////////////////////////
static __declspec(noreturn) void throw_com_error(const _com_error& error)
{
    // получить описание ошибки
    if (IErrorInfo* pErrorInfo = error.ErrorInfo()) 
    {
        // создать объект исключения
        ETW::Exception exception(error.Error(), pErrorInfo); 

        // выбросить исключение
        pErrorInfo->Release(); throw exception; 
    }
    // выбросить исключение
    else throw ETW::Exception(error.Error()); 
}

///////////////////////////////////////////////////////////////////////////////
// Вспомогательные функции
///////////////////////////////////////////////////////////////////////////////
inline BOOL HasAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName)
{
    // содержимое атрибута 
    _variant_t vtValue; 

    // получить значение атрибута
    return SUCCEEDED(pQualifiers->Get(szName, 0, &vtValue, nullptr));  
}
 
template <typename T>
inline BOOL GetAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName, T* value)
try {
    // содержимое атрибутов 
    _variant_t vtValue; 

    // получить значение атрибута
    if (FAILED(pQualifiers->Get(szName, 0, &vtValue, nullptr))) return FALSE;  

    // вернуть значение атрибута
    *value = static_cast<T>(vtValue); return TRUE; 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 
 
template <typename T>
inline T GetAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName)
try {
    // содержимое атрибута 
    _variant_t vtValue; 

    // получить значение атрибута
    HRESULT hr = pQualifiers->Get(szName, 0, &vtValue, nullptr); 
    
    // вернуть значение атрибута
    if (SUCCEEDED(hr)) return static_cast<T>(vtValue); 

    // при ошибке выбросить исключение
    ETW::Exception::Throw(hr, pQualifiers, __uuidof(IWbemQualifierSet)); 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

template <typename T>
inline BOOL GetProperty(IWbemClassObject* pClassObject, PCWSTR szName, T* value)
try {
    // содержимое свойства
    _variant_t vtValue; 

    // получить значение свойства
    if (FAILED(pClassObject->Get(szName, 0, &vtValue, nullptr, nullptr))) return FALSE;  

    // вернуть значение свойства
    *value = static_cast<T>(vtValue); return TRUE; 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 
 
template <typename T>
inline T GetProperty(IWbemClassObject* pClassObject, PCWSTR szName)
try {
    // содержимое свойства
    _variant_t vtValue; 

    // получить значение свойства
    HRESULT hr = pClassObject->Get(szName, 0, &vtValue, nullptr, nullptr); 

    // вернуть значение свойства
    if (SUCCEEDED(hr)) return static_cast<T>(vtValue); 
    
    // при ошибке выбросить исключение
    ETW::Exception::Throw(hr, pClassObject, __uuidof(IWbemClassObject)); 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
WMI::ValueMap::ValueMap(IWbemQualifierSet* pQualifiers, BOOL forceFlags)  
try {
    // содержимое атрибутов 
    _variant_t vtValues; _variant_t vtValueMap; _variant_t vtValueDescriptions; 

    // указать значения по умолчанию
    BOOL bitMap = FALSE; _valueType = ETW::ValueMapType::Index; 
    
    // получить строковые значения
    if (GetAttribute(pQualifiers, L"Values", &vtValues)) 
    {
        // при наличии значений
        _valueType = forceFlags ? ETW::ValueMapType::Flag : ETW::ValueMapType::Index; 
     
        // получить значения 
        GetAttribute(pQualifiers, L"ValueMap", &vtValueMap); _variant_t vtValueType; 

        // получить тип значений 
        if (!forceFlags && GetAttribute(pQualifiers, L"ValueType", &vtValueType))
        {
            // проверить значение типа
            if (::lstrcmpiW(V_BSTR(&vtValueType), L"Flag") == 0) _valueType = ETW::ValueMapType::Flag; 
        }
    }
    // получить строковые значения
    else if (GetAttribute(pQualifiers, L"BitValues", &vtValues)) 
    {
        // при наличии значений
        _valueType = ETW::ValueMapType::Flag; bitMap = TRUE; 
            
        // получить значения 
        GetAttribute(pQualifiers, L"BitMap", &vtValueMap); 
    }
    // получить описания 
    GetAttribute(pQualifiers, L"ValueDescriptions", &vtValueDescriptions); 

    // проверить наличие списка значений
    if ((V_VT(&vtValues) & VT_ARRAY) == 0) return; 
    
    // добавить описания битов
    for (LONG i = 0; (ULONG)i < V_ARRAY(&vtValues)->rgsabound->cElements; i++) 
    {
        // инициализировать переменные
        _variant_t vtName; _variant_t vtDescription; 

        // получить значение элемента массива
        HRESULT hr = ::SafeArrayGetElement(V_ARRAY(&vtValues), &i, &vtName);

        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr); 

        // указать значение порядкового номера
        size_t ordinal = (bitMap) ? (i + 1) : i; 

        // при наличии значений или битов
        if ((vtValueMap.vt & VT_ARRAY) != 0) { _variant_t vtOrdinal;
            
            // получить значение элемента массива
            hr = ::SafeArrayGetElement(V_ARRAY(&vtValueMap), &i, &vtOrdinal);

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr); ordinal = vtOrdinal;
        }
        // вычислить значение
        size_t value = (bitMap) ? ((size_t)1 << (ordinal - 1)) : ordinal; 

        // при наличии описаний
        if ((V_VT(&vtValueDescriptions) & VT_ARRAY) != 0) 
        {
            // получить значение элемента массива
            ::SafeArrayGetElement(V_ARRAY(&vtValueDescriptions), &i, &vtDescription); 
        }
        // добавить значение в таблицу
        _map.emplace_back(value, V_BSTR(&vtName), V_BSTR(&vtDescription)); 
    }
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

///////////////////////////////////////////////////////////////////////////////
// Числовой тип
///////////////////////////////////////////////////////////////////////////////
WMI::Int8Type::Int8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_BYTE; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT8; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT8;
}

WMI::UInt8Type::UInt8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_UNSIGNEDBYTE; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT8; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT8; 
}

WMI::Int16Type::Int16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_SHORT; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT16; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT16; 
}

WMI::UInt16Type::UInt16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _bstr_t bstrExtension; _outType = TDH_OUTTYPE_UNSIGNEDSHORT; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT16; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT16; 

    // получить атрибут расширения
    if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
    {
        // указать способ форматирования
        if (wcscmp(bstrExtension, L"Port") == 0) _outType = TDH_OUTTYPE_PORT; 
    }
}

WMI::Int32Type::Int32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_INT; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT32; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT32; 
}

WMI::UInt32Type::UInt32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers) 
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _bstr_t bstrExtension; _outType = TDH_OUTTYPE_UNSIGNEDINT; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT32; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT32; 
}

WMI::Int64Type::Int64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_LONG; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT64; 
}

WMI::UInt64Type::UInt64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // указать способ форматирования по умолчанию
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_UNSIGNEDLONG; 

    // получить атрибут форматирования
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // указать шестнадцатеричное форматирование
        _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // получить атрибут форматирования
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT64; 
}

///////////////////////////////////////////////////////////////////////////////
// Тип указателя или числа разрядности указателя
///////////////////////////////////////////////////////////////////////////////
WMI::PointerType::PointerType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize) 
    
    // сохранить переданные параметры
    : ETW::PointerType(pointerSize), _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    _bstr_t bstrFormat; _bstr_t bstrExtension; 

    // указать тип элемента
    _inType = TDH_INTYPE_SIZET; _outType = TDH_OUTTYPE_UNSIGNEDINT; 
        
    // скорректировать тип элемента
    if (pointerSize == 8) _outType = TDH_OUTTYPE_UNSIGNEDLONG; 

    // обработать указатели
    if (HasAttribute(pQualifiers, L"Pointer") || HasAttribute(pQualifiers, L"PointerType"))
    {
        // указать тип элемента
        _inType = TDH_INTYPE_POINTER; _outType = TDH_OUTTYPE_HEXINT32; 

        // скорректировать тип элемента
        if (pointerSize == 8) _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // получить атрибут расширения
    else if (GetAttribute(pQualifiers, L"Extension", &bstrExtension) && wcscmp(bstrExtension, L"SizeT") == 0) 
    {
        // получить атрибут форматирования
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
        {
            // скорректировать тип элемента
            _outType = (USHORT)((pointerSize == 4) ? TDH_OUTTYPE_HEXINT32 : TDH_OUTTYPE_HEXINT64); 
        }
        // получить атрибут форматирования
        else if (HasAttribute(pQualifiers, L"DisplayInHex")) 
        { 
            // скорректировать тип элемента
            _outType = (USHORT)((pointerSize == 4) ? TDH_OUTTYPE_HEXINT32 : TDH_OUTTYPE_HEXINT64); 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Тип строки
///////////////////////////////////////////////////////////////////////////////
WMI::StringType::StringType(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers), _outType(TDH_OUTTYPE_STRING)
{
    // указать тип одиночного символа
    if (type == CIM_UINT8) _inType = TDH_INTYPE_ANSICHAR; 

    // указать тип одиночного символа
    else if (type == CIM_CHAR16) _inType = TDH_INTYPE_UNICODECHAR; 

    // обработать массив 
    else if ((type & CIM_FLAG_ARRAY) != 0) 
    {
        // указать тип символов массива
        if (type & CIM_UINT8) _inType = TDH_INTYPE_ANSISTRING; 
    
        // указать тип символов массива
        else _inType = TDH_INTYPE_UNICODESTRING; 
    } 
    // при указании типа CIM_STRING
    else if (type == CIM_STRING) { _bstr_t bstrFormat; _bstr_t bstrTermination; 

        // получить атрибут форматирования
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"w") == 0)
        {
            // получить атрибут завершения строки
            if (!GetAttribute(pQualifiers, L"StringTermination", &bstrTermination)) 
            {
                // указать тип строки
                _inType = TDH_INTYPE_UNICODESTRING;
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"NotCounted") == 0) 
            {
                // размер строки не указан
                _inType = TDH_INTYPE_NONNULLTERMINATEDSTRING; 
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"Counted") == 0) 
            {
                // размер строки содержится в данных в формате LE
               _inType = TDH_INTYPE_COUNTEDSTRING;           
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"ReverseCounted") == 0) 
            {
                // размер строки содержится в данных в формате BE
                _inType = TDH_INTYPE_REVERSEDCOUNTEDSTRING;
            }
            // указать тип строки
            else _inType = TDH_INTYPE_UNICODESTRING;
        }
        else {
            // получить атрибут завершения строки
            if (!GetAttribute(pQualifiers, L"StringTermination", &bstrTermination)) 
            {
                // указать тип строки
                _inType = TDH_INTYPE_ANSISTRING;
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"NotCounted") == 0) 
            {
                // размер строки не указан
                _inType = TDH_INTYPE_NONNULLTERMINATEDANSISTRING; 
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"Counted") == 0) 
            {
                // размер строки содержится в данных в формате LE
               _inType = TDH_INTYPE_COUNTEDANSISTRING;           
            }
            // в зависимости от значения атрибута
            else if (wcscmp(bstrTermination, L"ReverseCounted") == 0) 
            {
                // размер строки содержится в данных в формате BE
                _inType = TDH_INTYPE_REVERSEDCOUNTEDANSISTRING;
            }
            // указать тип строки
            else _inType = TDH_INTYPE_ANSISTRING;
        }
    }
    else { _outType = TDH_OUTTYPE_REDUCEDSTRING;

        // получить атрибут расширения
        _bstr_t bstrExtension = GetAttribute<_bstr_t>(pQualifiers, L"Extension"); 

        // в зависимости от расширения
        if (wcscmp(bstrExtension, L"RString") == 0) 
        {
            // указать тип строки
            _inType = TDH_INTYPE_ANSISTRING;
        }
        // указать тип строки
        else _inType = TDH_INTYPE_UNICODESTRING;
    }
}

size_t WMI::StringType::GetLength(const ETW::IContainer* pParent) const
{
    // указать максимальный размер одиночного символа
    if (_type == CIM_UINT8 || _type == CIM_CHAR16) return 1; size_t cchMax = SIZE_MAX; 

    // при указании типа CIM_STRING
    if (_type == CIM_STRING) 
    { 
        // получить атрибут максимального размера строки
        if (GetAttribute(_pQualifiers, L"MaxLen", &cchMax) && cchMax == 0) cchMax = SIZE_MAX; 
    }
    // при указании массивов
    else if ((_type & CIM_FLAG_ARRAY) != 0) { _bstr_t bstrCountName; 

        // получить атрибут максимального размера массива
        if (GetAttribute(_pQualifiers, L"Max", &cchMax) && cchMax == 0) cchMax = SIZE_MAX; 

        // при указании поля с размером массива
        if (GetAttribute(_pQualifiers, L"WmiSizeIs", &bstrCountName))
        {
            // проверить указание родительского элемента
            if (!pParent) return 0; size_t cch = 0; 

            // проверить тип родительской структуры
            if (pParent->Type().LogicalType() != ETW::TYPE_STRUCT) 
            {
                // при ошибке выбросить исключение
                ETW::Exception::Throw(WBEM_E_INVALID_QUALIFIER);
            }
            // выполнить преобразование типа
            const ETW::IStruct& parentStruct = (const ETW::IStruct&)*pParent; 

            // найти поле с размером
            if (const ETW::IElement* pCount = parentStruct.FindName(bstrCountName))
            {
                // прочитать значение поля
                memcpy(&cch, pCount->GetDataAddress(), pCount->GetDataSize()); return cch; 
            }
            // при ошибке выбросить исключение
            else ETW::Exception::Throw(WBEM_E_NOT_FOUND);
        }
    }
    return cchMax; 
}

///////////////////////////////////////////////////////////////////////////////
// Метаданные массива
///////////////////////////////////////////////////////////////////////////////
WMI::ArrayType::ArrayType(const Event& event, CIMTYPE type, IWbemQualifierSet* pQualifiers)

    // сохранить переданные параметры
    : _type(type), _pQualifiers(pQualifiers) 
{
    // получить тип элемента массива
    _pElementType.reset(event.CreateElementType(_type & ~CIM_FLAG_ARRAY, _pQualifiers)); 
}

size_t WMI::ArrayType::GetCount(const ETW::IContainer& parent) const
{
    // инициализировать переменные
    _bstr_t bstrCountName; size_t maxCount; 

    // получить имя поля с указанием размера
    if (GetAttribute(_pQualifiers, L"WmiSizeIs", &bstrCountName)) 
    {
        // проверить тип родительского элемента
        if (parent.Type().LogicalType() != ETW::TYPE_STRUCT) 
        {
            // при ошибке выбросить исключение
            ETW::Exception::Throw(WBEM_E_INVALID_QUALIFIER);
        }
        // выполнить преобразование типа
        const ETW::IStruct& parentStruct = (const ETW::IStruct&)parent; size_t count = 0; 

        // найти поле с размером
        if (const ETW::IElement* pCount = parentStruct.FindName(bstrCountName))
        {
            // прочитать значение поля
            memcpy(&count, pCount->GetDataAddress(), pCount->GetDataSize()); return count; 
        }
        // при ошибке выбросить исключение
        else ETW::Exception::Throw(WBEM_E_NOT_FOUND);
    }
    // получить фиксированный размер поля
    return (GetAttribute(_pQualifiers, L"Max", &maxCount)) ? maxCount : SIZE_MAX; 
}
    
///////////////////////////////////////////////////////////////////////////////
// Метаданные структуры
///////////////////////////////////////////////////////////////////////////////
WMI::StructType::StructType(const Event& event, IWbemClassObject* pClass, PCWSTR szName) 

    // сохранить переданные параметры
    : _pClass(pClass), _id(GUID_NULL), _name(szName)
{ 
    // инициализи
    _bstr_t bstrGuid; HRESULT hr = S_OK; SAFEARRAY* pNames = nullptr; 

    // получить атрибуты класса
    IWbemQualifierSetPtr pQualifiers; _pClass->GetQualifierSet(&pQualifiers); 

    // при наличии атрибутов
    if (pQualifiers && GetAttribute(pQualifiers, L"Guid", &bstrGuid)) 
    { 
        // преобразовать GUID в строковую форму
        hr = ::IIDFromString(bstrGuid, &_id); 
    }
    // при отсутствии идентификатора
    if (FAILED(hr) || ::InlineIsEqualGUID(_id, GUID_NULL)) 
    {
        // сгенерировать уникальный идентификатор
        hr = ::CoCreateGuid(&_id); if (FAILED(hr)) ETW::Exception::Throw(hr); 
    }
    // перечислить все поля с атрибутом WmiDataId
    hr = _pClass->GetNames(L"WmiDataId", WBEM_FLAG_ONLY_IF_TRUE, nullptr, &pNames); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 
    try { 
        // выделить буфер требуемого размера
        std::vector<std::wstring> names(pNames->rgsabound->cElements); 

        // для всех полей
        for (LONG i = 0; (ULONG)i < pNames->rgsabound->cElements; i++)
        {
            // получить имя поля
            _bstr_t bstrName; hr = SafeArrayGetElement(pNames, &i, &bstrName); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr); 

            // получить атрибуты поля
            hr = _pClass->GetPropertyQualifierSet(bstrName, &pQualifiers); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // получить атрибут WmiDataId
            size_t index = GetAttribute<size_t>(pQualifiers, L"WmiDataId"); 

            // проверить значение индекса
            if (index == 0 || index > names.size()) 
            {
                // при ошибке выбросить исключение
                ETW::Exception::Throw(WBEM_E_VALUE_OUT_OF_RANGE); 
            }
            // сохранить имя поля в нужную позицию
            names[index - 1] = (PCWSTR)bstrName; 
        }
        // для всех полей
        for (size_t i = 0; i < names.size(); i++)
        {
            // получить атрибуты поля
            hr = _pClass->GetPropertyQualifierSet(names[i].c_str(), &pQualifiers); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // получить тип поля
            CIMTYPE type; hr = _pClass->Get(names[i].c_str(), 0, nullptr, &type, 0); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // добавить описание типа в таблицу
            _fields.emplace_back(names[i], std::shared_ptr<ETW::IElementType>(
                event.CreateElementType(type, pQualifiers)
            )); 
        }
        // освободить выделенные ресурсы
        ::SafeArrayDestroy(pNames); 
    }
    // обработать возможную ошибку
    catch (...) { ::SafeArrayDestroy(pNames); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Cобытие и связанные с ним метаданные
///////////////////////////////////////////////////////////////////////////////
WMI::Event::Event(IWbemServices* pNamespace, IWbemClassObject* pClass, const EVENT_TRACE* pEvent, size_t pointerSize) 
    
    // сохранить переданные параметры
    : _pNamespace(pNamespace), _pointerSize(pointerSize), _pEvent(pEvent)
{
    // получить имя класса
    _bstr_t bstrClassName = GetProperty<_bstr_t>(pClass, L"__CLASS"); 

    // раскодировать тип структуры
    _pStructType.reset(new StructType(*this, pClass, bstrClassName)); 

    // раскодировать данные в структуре
    _pStruct.reset(new ETW::Struct(L"", *_pStructType, pEvent->MofData, pEvent->MofLength)); 
}

ETW::IElementType* WMI::Event::CreateElementType(CIMTYPE type, IWbemQualifierSet* pQualifiers) const
{
    _bstr_t bstrExtension; _bstr_t bstrFormat; _bstr_t bstrClassName; 

    // обработать указатели
    if (HasAttribute(pQualifiers, L"Pointer") || HasAttribute(pQualifiers, L"PointerType"))
    {
        // указать тип элемента
        return new WMI::PointerType(type, pQualifiers, PointerSize()); 
    }
    // получить атрибут расширения
    if (GetAttribute(pQualifiers, L"Extension", &bstrExtension) && wcscmp(bstrExtension, L"SizeT") == 0) 
    {
        // указать тип элемента
        return new WMI::PointerType(type, pQualifiers, PointerSize()); 
    }
    // для массива однобайтовых чисел
    if (type == (CIM_FLAG_ARRAY | CIM_SINT8) || type == (CIM_FLAG_ARRAY | CIM_UINT8)) 
    { 
        // получить атрибут форматирования
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"s") == 0)
        {
            // вернуть описание строкового типа
            return new WMI::StringType(type, pQualifiers); 
        }
    }
    // вернуть описание строкового типа
    if (type == (CIM_FLAG_ARRAY | CIM_CHAR16)) return new WMI::StringType(type, pQualifiers);

    // вернуть описание массива
    if ((type & CIM_FLAG_ARRAY) != 0) return new WMI::ArrayType(*this, type, pQualifiers); 

    // для символа ANSI
    if (type == CIM_UINT8 && GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"c") == 0)
    {
        // вернуть описание строкового типа
        return new WMI::StringType(type, pQualifiers); 
    }
    // для символа Unicode вернуть описание строкового типа
    if (type == CIM_CHAR16) return new WMI::StringType(type, pQualifiers); 

    // для строк вернуть описание строкового типа
    if (type == CIM_STRING) return new WMI::StringType(type, pQualifiers); 

    // при наличии объекта
    if (type == CIM_OBJECT) { IWbemClassObjectPtr pStruct;
     
        // при наличии специального префикса
        if (GetAttribute(pQualifiers, L"Cimtype", &bstrClassName) && wcsncmp(bstrClassName, L"object:", 7) == 0) 
        {
            // извлечь имя класса
            std::wstring strClassName((PCWSTR)bstrClassName + 7); bstrClassName = strClassName.c_str();

            // получить описание класса
            HRESULT hr = _pNamespace->GetObject(bstrClassName, 0, nullptr, &pStruct, nullptr); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, __uuidof(IWbemServices)); 

            // вернуть описание структуры
            return new WMI::StructType(*this, pStruct, bstrClassName); 
        }
        // получить атрибут расширения
        if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
        {
            // вернуть описание строкового типа
            if (wcscmp(bstrExtension, L"RString" ) == 0) return new WMI::StringType(type, pQualifiers); 
            if (wcscmp(bstrExtension, L"RWString") == 0) return new WMI::StringType(type, pQualifiers); 

            // вернуть описание типа времени
            if (wcscmp(bstrExtension, L"WmiTime") == 0) return new WMI::DateTimeType(type, pQualifiers); 

            // вернуть бинарные данные
            if (wcscmp(bstrExtension, L"Variant") == 0) return new WMI::BinaryType(type, pQualifiers); 

            // вернуть GUID и SID
            if (wcscmp(bstrExtension, L"Guid") == 0) return new WMI::GuidType(type, pQualifiers);
            if (wcscmp(bstrExtension, L"Sid" ) == 0) return new WMI::SidType (type, pQualifiers, PointerSize()); 

            // вернуть IPv-адреса и номер порта 
            if (wcscmp(bstrExtension, L"IPAddr"  ) == 0) return new WMI::IPv4Type  (type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV4") == 0) return new WMI::IPv4Type  (type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV6") == 0) return new WMI::IPv6Type  (type, pQualifiers);
            if (wcscmp(bstrExtension, L"Port"    ) == 0) return new WMI::UInt16Type(type, pQualifiers);
        }
    }
    switch (type)
    {
    // вернуть булевский тип данных
    case CIM_BOOLEAN: return new WMI::BooleanType(pQualifiers); 

    // вернуть числовой тип данных
    case CIM_SINT8  : return new WMI::Int8Type  (type, pQualifiers); 
    case CIM_UINT8  : return new WMI::UInt8Type (type, pQualifiers); 
    case CIM_SINT16 : return new WMI::Int16Type (type, pQualifiers); 
    case CIM_UINT16 : return new WMI::UInt16Type(type, pQualifiers); 
    case CIM_SINT32 : return new WMI::Int32Type (type, pQualifiers); 
    case CIM_UINT32 : 
    {
        // получить атрибут расширения
        if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
        {
            // вернуть IP-адрес
            if (wcscmp(bstrExtension, L"IPAddr"  ) == 0) return new WMI::IPv4Type(type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV4") == 0) return new WMI::IPv4Type(type, pQualifiers); 
        }
        // вернуть числовой тип
        return new WMI::UInt32Type(type, pQualifiers); 
    }
    case CIM_SINT64 : 
    {
        // для отметки времени
        if (HasAttribute(pQualifiers, L"WmiTimeStamp"))
        {
            // вернуть тип времени
            return new WMI::DateTimeType(type, pQualifiers); 
        }
        // вернуть числовой тип
        return new WMI::Int64Type(type, pQualifiers); 
    }
    case CIM_UINT64 : 
    {
        // для отметки времени
        if (HasAttribute(pQualifiers, L"WmiTimeStamp"))
        {
            // вернуть тип времени
            return new WMI::DateTimeType(type, pQualifiers); 
        }
        // вернуть числовой тип
        return new WMI::UInt64Type(type, pQualifiers); 
    }
    // вернуть числовой тип
    case CIM_REAL32: return new WMI::FloatType (type, pQualifiers); 
    case CIM_REAL64: return new WMI::DoubleType(type, pQualifiers); 

    // вернуть описание типа времени
    case CIM_DATETIME: return new WMI::CimDateTimeType(type, pQualifiers); 
    }
    // при ошибке выбросить исключение
    ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED); 
}

///////////////////////////////////////////////////////////////////////////////
// Описание провайдера
///////////////////////////////////////////////////////////////////////////////
WMI::ProviderInfo::ProviderInfo(IWbemServices* pNamespace, const GUID& id, IWbemClassObject* pProvider) 

    // сохранить переданные параметры
    : _pNamespace(pNamespace), _id(id), _pProvider(pProvider)
{
    // указать имя поля для атрибутов
    IWbemQualifierSetPtr pFlagsQualifiers; IWbemQualifierSetPtr pLevelQualifiers; 

    // получить атрибуты поля
    if (SUCCEEDED(_pProvider->GetPropertyQualifierSet(L"Flags", &pFlagsQualifiers)))
    {
        // сохранить описание категорий трассировки
        _pKeywords.reset(new ValueMap(pFlagsQualifiers, TRUE)); 
    }
    // описание категорий отсутствует
    else _pKeywords.reset(new ValueMap()); 

    // получить арибуты поля
    if (SUCCEEDED(_pProvider->GetPropertyQualifierSet(L"Level", &pLevelQualifiers)))
    {
        // сохранить описание уровней трассировки
        _pLevels.reset(new ValueMap(pLevelQualifiers)); 
    }
    // описание уровней отсутствует
    else _pLevels.reset(new ValueMap()); 
}

///////////////////////////////////////////////////////////////////////////////
// Пространство имен WMI
///////////////////////////////////////////////////////////////////////////////
WMI::Namespace::Namespace()
try {
    // указать имя пространства имен
    IWbemLocatorPtr pLocator; _bstr_t bstrNamespace(L"root\\wmi"); 

    // создать объект подключения
    HRESULT hr = CoCreateInstance(
        __uuidof(WbemLocator ), nullptr, CLSCTX_INPROC_SERVER, 
        __uuidof(IWbemLocator), (PVOID*) &pLocator
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr); 

    // подключиться к пространству имен WMI
    hr = pLocator->ConnectServer(
        bstrNamespace,              // пространство имен
        nullptr,                    // текущий пользователь
        nullptr,                    // текущий контекст безопасности
        nullptr,                    // текущая локализация
        0,                          // отсутствие таймаута 
        nullptr,                    // текущий домен
        nullptr,                    // отсутствие контекста
        &_pNamespace                // объект пространства имен
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, pLocator, __uuidof(pLocator)); 

    // настроить параметры защиты подключения 
    hr = CoSetProxyBlanket(_pNamespace,
        RPC_C_AUTHN_WINNT,              // способ аутентификации
        RPC_C_AUTHZ_NONE,               // способ авторизации
        nullptr,                        // 
        RPC_C_AUTHN_LEVEL_PKT,          // уровень защиты при аутентификации
        RPC_C_IMP_LEVEL_IMPERSONATE,    // уровень заимствования прав
        nullptr,                        // 
        EOAC_NONE                       // 
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr);
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventProviderClass(REFGUID guid) const
try {
    // указать имя корневого класса
    _bstr_t bstrRootClass(L"EventTrace"); IEnumWbemClassObjectPtr pClasses;

    // перечислить все классы, производные от EventTrace
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrRootClass,                      // корневой класс для перечисления подклассов
        WBEM_FLAG_FORWARD_ONLY  |           // однонаправленное перечисление
        WBEM_FLAG_DEEP          |           // перечисление подклассов без корневого класса
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // использование текущей локализации
        nullptr,                            // отсутствие контекста
        &pClasses                           // перечислитель классов
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, _pNamespace.GetIID()); 

    // для всех подклассов
    for (IWbemClassObjectPtr pProvider; ; pProvider.Release())     
    {
        _bstr_t bstrGuid; GUID classGuid; 

        // получить описание следующего класса
        ULONG count = 0; hr = pClasses->Next(WBEM_INFINITE, 1, &pProvider, &count); 

        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr, pClasses, pClasses.GetIID()); 
        
        // проверить завершение перечисления
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 
        
        // получить атрибуты класса
        if (FAILED(pProvider->GetQualifierSet(&pQualifiers))) continue;  

        // получить GUID класса
        if (!GetAttribute(pQualifiers, L"Guid", &bstrGuid)) continue; 

        // преобразовать тип GUID
        if (FAILED(::IIDFromString(bstrGuid, &classGuid))) continue; 
            
        // сравнить GUID   
        if (InlineIsEqualGUID(classGuid, guid)) return pProvider.Detach(); 
    }
    return nullptr; 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventCategoryClass(REFGUID guid, USHORT version) const
try {
    // указать имя корневого класса
    _bstr_t bstrRootClass(L"EventTrace"); IEnumWbemClassObjectPtr pClasses;

    // перечислить все классы, производные от EventTrace
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrRootClass,                      // корневой класс для перечисления подклассов
        WBEM_FLAG_FORWARD_ONLY  |           // однонаправленное перечисление
        WBEM_FLAG_DEEP          |           // перечисление подклассов без корневого класса
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // использование текущей локализации
        nullptr,                            // отсутствие контекста
        &pClasses                           // перечислитель классов
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, __uuidof(IWbemServices)); 

    // для всех подклассов
    for (IWbemClassObjectPtr pEventCategory; ; pEventCategory.Release()) 
    {
        _bstr_t bstrGuid; GUID classGuid; size_t classVersion; 

        // получить описание следующего класса
        ULONG count = 0; hr = pClasses->Next(WBEM_INFINITE, 1, &pEventCategory, &count); 

        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr, pClasses, pClasses.GetIID()); 
        
        // проверить завершение перечисления
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 
        
        // получить атрибуты класса
        if (FAILED(pEventCategory->GetQualifierSet(&pQualifiers))) continue;  

        // получить GUID класса
        if (!GetAttribute(pQualifiers, L"Guid", &bstrGuid)) continue; 

        // преобразовать GUID в строковую форму
        if (FAILED(::IIDFromString(bstrGuid, &classGuid))) continue; 
                
        // сравнить совпадение GUID класса
        if (!InlineIsEqualGUID(classGuid, guid)) continue; 

        // получить версию класса
        if (GetAttribute(pQualifiers, L"EventVersion", &classVersion))
        {
            // проверить совпадение версии
            if (classVersion != version) continue; 
        }
        // вернуть найденный класс
        return pEventCategory.Detach(); 
    }
    return nullptr; 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventClass(REFGUID guid, USHORT version, UCHAR type) const
try {
    // найти класс категории событий
    IWbemClassObjectPtr pEventCategory = FindEventCategoryClass(guid, version); 

    // проверить успешность поиска
    if (!pEventCategory) return nullptr; 

    // получить имя класса относительно пространства имен
    _bstr_t bstrClassPath = GetProperty<_bstr_t>(pEventCategory, L"__RELPATH"); 

     // перечислить все производные классы от категории события
    IEnumWbemClassObjectPtr pEventClasses;
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrClassPath,                      // корневой класс для перечисления подклассов
        WBEM_FLAG_FORWARD_ONLY  |           // однонаправленное перечисление
        WBEM_FLAG_SHALLOW       |           // 
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // использование текущей локализации
        nullptr,                            // отсутствие контекста
        &pEventClasses                      // перечислитель классов
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, pEventClasses, pEventClasses.GetIID()); 

    // для всех подклассов
    for (IWbemClassObjectPtr pEventClass; ; pEventClass.Release()) 
    {
        _variant_t varEventType; INT classEventType = 0;

        // получить описание следующего класса
        ULONG count = 0; hr = pEventClasses->Next(WBEM_INFINITE, 1, &pEventClass, &count); 

        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr, pEventClasses, pEventClasses.GetIID()); 
        
        // проверить завершение перечисления
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 

        // получить атрибуты класса
        if (FAILED(pEventClass->GetQualifierSet(&pQualifiers))) continue;  

        // получить тип класса
        if (!GetAttribute(pQualifiers, L"EventType", &varEventType)) continue; 

        // при указании одного типа типа
        if ((varEventType.vt & VT_ARRAY) == 0) 
        {
            // проверить совпадение типа
            if ((size_t)varEventType == type) return pEventClass.Detach();  
        }
        // для всех элементов массива
        else for (LONG i = 0; (ULONG)i < varEventType.parray->rgsabound->cElements; i++)
        {
            // получить значение элемента массива
            hr = ::SafeArrayGetElement(varEventType.parray, &i, &classEventType); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) ETW::Exception::Throw(hr); 

            // проверить совпадение типа
            if (classEventType == type) return pEventClass.Detach();  
        }
    }
    return nullptr; 
}
// преобразовать тип ошибки
catch (const _com_error& error) { throw_com_error(error); } 



