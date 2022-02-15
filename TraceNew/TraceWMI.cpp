#include <windows.h>
#include "TraceWMI.hpp"
#include <comdef.h>
#include <comip.h>
#include <comutil.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(IWbemLocator        , __uuidof(IWbemLocator        ));
_COM_SMARTPTR_TYPEDEF(IEnumWbemClassObject, __uuidof(IEnumWbemClassObject));

///////////////////////////////////////////////////////////////////////////////
// ����������
///////////////////////////////////////////////////////////////////////////////
static __declspec(noreturn) void throw_com_error(const _com_error& error)
{
    // �������� �������� ������
    if (IErrorInfo* pErrorInfo = error.ErrorInfo()) 
    {
        // ������� ������ ����������
        ETW::Exception exception(error.Error(), pErrorInfo); 

        // ��������� ����������
        pErrorInfo->Release(); throw exception; 
    }
    // ��������� ����������
    else throw ETW::Exception(error.Error()); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������������� �������
///////////////////////////////////////////////////////////////////////////////
inline BOOL HasAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName)
{
    // ���������� �������� 
    _variant_t vtValue; 

    // �������� �������� ��������
    return SUCCEEDED(pQualifiers->Get(szName, 0, &vtValue, nullptr));  
}
 
template <typename T>
inline BOOL GetAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName, T* value)
try {
    // ���������� ��������� 
    _variant_t vtValue; 

    // �������� �������� ��������
    if (FAILED(pQualifiers->Get(szName, 0, &vtValue, nullptr))) return FALSE;  

    // ������� �������� ��������
    *value = static_cast<T>(vtValue); return TRUE; 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 
 
template <typename T>
inline T GetAttribute(IWbemQualifierSet* pQualifiers, PCWSTR szName)
try {
    // ���������� �������� 
    _variant_t vtValue; 

    // �������� �������� ��������
    HRESULT hr = pQualifiers->Get(szName, 0, &vtValue, nullptr); 
    
    // ������� �������� ��������
    if (SUCCEEDED(hr)) return static_cast<T>(vtValue); 

    // ��� ������ ��������� ����������
    ETW::Exception::Throw(hr, pQualifiers, __uuidof(IWbemQualifierSet)); 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

template <typename T>
inline BOOL GetProperty(IWbemClassObject* pClassObject, PCWSTR szName, T* value)
try {
    // ���������� ��������
    _variant_t vtValue; 

    // �������� �������� ��������
    if (FAILED(pClassObject->Get(szName, 0, &vtValue, nullptr, nullptr))) return FALSE;  

    // ������� �������� ��������
    *value = static_cast<T>(vtValue); return TRUE; 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 
 
template <typename T>
inline T GetProperty(IWbemClassObject* pClassObject, PCWSTR szName)
try {
    // ���������� ��������
    _variant_t vtValue; 

    // �������� �������� ��������
    HRESULT hr = pClassObject->Get(szName, 0, &vtValue, nullptr, nullptr); 

    // ������� �������� ��������
    if (SUCCEEDED(hr)) return static_cast<T>(vtValue); 
    
    // ��� ������ ��������� ����������
    ETW::Exception::Throw(hr, pClassObject, __uuidof(IWbemClassObject)); 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� �����
///////////////////////////////////////////////////////////////////////////////
WMI::ValueMap::ValueMap(IWbemQualifierSet* pQualifiers, BOOL forceFlags)  
try {
    // ���������� ��������� 
    _variant_t vtValues; _variant_t vtValueMap; _variant_t vtValueDescriptions; 

    // ������� �������� �� ���������
    BOOL bitMap = FALSE; _valueType = ETW::ValueMapType::Index; 
    
    // �������� ��������� ��������
    if (GetAttribute(pQualifiers, L"Values", &vtValues)) 
    {
        // ��� ������� ��������
        _valueType = forceFlags ? ETW::ValueMapType::Flag : ETW::ValueMapType::Index; 
     
        // �������� �������� 
        GetAttribute(pQualifiers, L"ValueMap", &vtValueMap); _variant_t vtValueType; 

        // �������� ��� �������� 
        if (!forceFlags && GetAttribute(pQualifiers, L"ValueType", &vtValueType))
        {
            // ��������� �������� ����
            if (::lstrcmpiW(V_BSTR(&vtValueType), L"Flag") == 0) _valueType = ETW::ValueMapType::Flag; 
        }
    }
    // �������� ��������� ��������
    else if (GetAttribute(pQualifiers, L"BitValues", &vtValues)) 
    {
        // ��� ������� ��������
        _valueType = ETW::ValueMapType::Flag; bitMap = TRUE; 
            
        // �������� �������� 
        GetAttribute(pQualifiers, L"BitMap", &vtValueMap); 
    }
    // �������� �������� 
    GetAttribute(pQualifiers, L"ValueDescriptions", &vtValueDescriptions); 

    // ��������� ������� ������ ��������
    if ((V_VT(&vtValues) & VT_ARRAY) == 0) return; 
    
    // �������� �������� �����
    for (LONG i = 0; (ULONG)i < V_ARRAY(&vtValues)->rgsabound->cElements; i++) 
    {
        // ���������������� ����������
        _variant_t vtName; _variant_t vtDescription; 

        // �������� �������� �������� �������
        HRESULT hr = ::SafeArrayGetElement(V_ARRAY(&vtValues), &i, &vtName);

        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr); 

        // ������� �������� ����������� ������
        size_t ordinal = (bitMap) ? (i + 1) : i; 

        // ��� ������� �������� ��� �����
        if ((vtValueMap.vt & VT_ARRAY) != 0) { _variant_t vtOrdinal;
            
            // �������� �������� �������� �������
            hr = ::SafeArrayGetElement(V_ARRAY(&vtValueMap), &i, &vtOrdinal);

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr); ordinal = vtOrdinal;
        }
        // ��������� ��������
        size_t value = (bitMap) ? ((size_t)1 << (ordinal - 1)) : ordinal; 

        // ��� ������� ��������
        if ((V_VT(&vtValueDescriptions) & VT_ARRAY) != 0) 
        {
            // �������� �������� �������� �������
            ::SafeArrayGetElement(V_ARRAY(&vtValueDescriptions), &i, &vtDescription); 
        }
        // �������� �������� � �������
        _map.emplace_back(value, V_BSTR(&vtName), V_BSTR(&vtDescription)); 
    }
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

///////////////////////////////////////////////////////////////////////////////
// �������� ���
///////////////////////////////////////////////////////////////////////////////
WMI::Int8Type::Int8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_BYTE; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT8; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT8;
}

WMI::UInt8Type::UInt8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_UNSIGNEDBYTE; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT8; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT8; 
}

WMI::Int16Type::Int16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_SHORT; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT16; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT16; 
}

WMI::UInt16Type::UInt16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _bstr_t bstrExtension; _outType = TDH_OUTTYPE_UNSIGNEDSHORT; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT16; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT16; 

    // �������� ������� ����������
    if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
    {
        // ������� ������ ��������������
        if (wcscmp(bstrExtension, L"Port") == 0) _outType = TDH_OUTTYPE_PORT; 
    }
}

WMI::Int32Type::Int32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_INT; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT32; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT32; 
}

WMI::UInt32Type::UInt32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers) 
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _bstr_t bstrExtension; _outType = TDH_OUTTYPE_UNSIGNEDINT; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT32; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT32; 
}

WMI::Int64Type::Int64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_LONG; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT64; 
}

WMI::UInt64Type::UInt64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 
    
    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    // ������� ������ �������������� �� ���������
    _bstr_t bstrFormat; _outType = TDH_OUTTYPE_UNSIGNEDLONG; 

    // �������� ������� ��������������
    if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
    {
        // ������� ����������������� ��������������
        _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // �������� ������� ��������������
    else if (HasAttribute(pQualifiers, L"DisplayInHex")) _outType = TDH_OUTTYPE_HEXINT64; 
}

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ��� ����� ����������� ���������
///////////////////////////////////////////////////////////////////////////////
WMI::PointerType::PointerType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize) 
    
    // ��������� ���������� ���������
    : ETW::PointerType(pointerSize), _type(type), _pQualifiers(pQualifiers), _valueMap(pQualifiers)
{
    _bstr_t bstrFormat; _bstr_t bstrExtension; 

    // ������� ��� ��������
    _inType = TDH_INTYPE_SIZET; _outType = TDH_OUTTYPE_UNSIGNEDINT; 
        
    // ��������������� ��� ��������
    if (pointerSize == 8) _outType = TDH_OUTTYPE_UNSIGNEDLONG; 

    // ���������� ���������
    if (HasAttribute(pQualifiers, L"Pointer") || HasAttribute(pQualifiers, L"PointerType"))
    {
        // ������� ��� ��������
        _inType = TDH_INTYPE_POINTER; _outType = TDH_OUTTYPE_HEXINT32; 

        // ��������������� ��� ��������
        if (pointerSize == 8) _outType = TDH_OUTTYPE_HEXINT64; 
    }
    // �������� ������� ����������
    else if (GetAttribute(pQualifiers, L"Extension", &bstrExtension) && wcscmp(bstrExtension, L"SizeT") == 0) 
    {
        // �������� ������� ��������������
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"x") == 0)
        {
            // ��������������� ��� ��������
            _outType = (USHORT)((pointerSize == 4) ? TDH_OUTTYPE_HEXINT32 : TDH_OUTTYPE_HEXINT64); 
        }
        // �������� ������� ��������������
        else if (HasAttribute(pQualifiers, L"DisplayInHex")) 
        { 
            // ��������������� ��� ��������
            _outType = (USHORT)((pointerSize == 4) ? TDH_OUTTYPE_HEXINT32 : TDH_OUTTYPE_HEXINT64); 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// ��� ������
///////////////////////////////////////////////////////////////////////////////
WMI::StringType::StringType(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers), _outType(TDH_OUTTYPE_STRING)
{
    // ������� ��� ���������� �������
    if (type == CIM_UINT8) _inType = TDH_INTYPE_ANSICHAR; 

    // ������� ��� ���������� �������
    else if (type == CIM_CHAR16) _inType = TDH_INTYPE_UNICODECHAR; 

    // ���������� ������ 
    else if ((type & CIM_FLAG_ARRAY) != 0) 
    {
        // ������� ��� �������� �������
        if (type & CIM_UINT8) _inType = TDH_INTYPE_ANSISTRING; 
    
        // ������� ��� �������� �������
        else _inType = TDH_INTYPE_UNICODESTRING; 
    } 
    // ��� �������� ���� CIM_STRING
    else if (type == CIM_STRING) { _bstr_t bstrFormat; _bstr_t bstrTermination; 

        // �������� ������� ��������������
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"w") == 0)
        {
            // �������� ������� ���������� ������
            if (!GetAttribute(pQualifiers, L"StringTermination", &bstrTermination)) 
            {
                // ������� ��� ������
                _inType = TDH_INTYPE_UNICODESTRING;
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"NotCounted") == 0) 
            {
                // ������ ������ �� ������
                _inType = TDH_INTYPE_NONNULLTERMINATEDSTRING; 
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"Counted") == 0) 
            {
                // ������ ������ ���������� � ������ � ������� LE
               _inType = TDH_INTYPE_COUNTEDSTRING;           
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"ReverseCounted") == 0) 
            {
                // ������ ������ ���������� � ������ � ������� BE
                _inType = TDH_INTYPE_REVERSEDCOUNTEDSTRING;
            }
            // ������� ��� ������
            else _inType = TDH_INTYPE_UNICODESTRING;
        }
        else {
            // �������� ������� ���������� ������
            if (!GetAttribute(pQualifiers, L"StringTermination", &bstrTermination)) 
            {
                // ������� ��� ������
                _inType = TDH_INTYPE_ANSISTRING;
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"NotCounted") == 0) 
            {
                // ������ ������ �� ������
                _inType = TDH_INTYPE_NONNULLTERMINATEDANSISTRING; 
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"Counted") == 0) 
            {
                // ������ ������ ���������� � ������ � ������� LE
               _inType = TDH_INTYPE_COUNTEDANSISTRING;           
            }
            // � ����������� �� �������� ��������
            else if (wcscmp(bstrTermination, L"ReverseCounted") == 0) 
            {
                // ������ ������ ���������� � ������ � ������� BE
                _inType = TDH_INTYPE_REVERSEDCOUNTEDANSISTRING;
            }
            // ������� ��� ������
            else _inType = TDH_INTYPE_ANSISTRING;
        }
    }
    else { _outType = TDH_OUTTYPE_REDUCEDSTRING;

        // �������� ������� ����������
        _bstr_t bstrExtension = GetAttribute<_bstr_t>(pQualifiers, L"Extension"); 

        // � ����������� �� ����������
        if (wcscmp(bstrExtension, L"RString") == 0) 
        {
            // ������� ��� ������
            _inType = TDH_INTYPE_ANSISTRING;
        }
        // ������� ��� ������
        else _inType = TDH_INTYPE_UNICODESTRING;
    }
}

size_t WMI::StringType::GetLength(const ETW::IContainer* pParent) const
{
    // ������� ������������ ������ ���������� �������
    if (_type == CIM_UINT8 || _type == CIM_CHAR16) return 1; size_t cchMax = SIZE_MAX; 

    // ��� �������� ���� CIM_STRING
    if (_type == CIM_STRING) 
    { 
        // �������� ������� ������������� ������� ������
        if (GetAttribute(_pQualifiers, L"MaxLen", &cchMax) && cchMax == 0) cchMax = SIZE_MAX; 
    }
    // ��� �������� ��������
    else if ((_type & CIM_FLAG_ARRAY) != 0) { _bstr_t bstrCountName; 

        // �������� ������� ������������� ������� �������
        if (GetAttribute(_pQualifiers, L"Max", &cchMax) && cchMax == 0) cchMax = SIZE_MAX; 

        // ��� �������� ���� � �������� �������
        if (GetAttribute(_pQualifiers, L"WmiSizeIs", &bstrCountName))
        {
            // ��������� �������� ������������� ��������
            if (!pParent) return 0; size_t cch = 0; 

            // ��������� ��� ������������ ���������
            if (pParent->Type().LogicalType() != ETW::TYPE_STRUCT) 
            {
                // ��� ������ ��������� ����������
                ETW::Exception::Throw(WBEM_E_INVALID_QUALIFIER);
            }
            // ��������� �������������� ����
            const ETW::IStruct& parentStruct = (const ETW::IStruct&)*pParent; 

            // ����� ���� � ��������
            if (const ETW::IElement* pCount = parentStruct.FindName(bstrCountName))
            {
                // ��������� �������� ����
                memcpy(&cch, pCount->GetDataAddress(), pCount->GetDataSize()); return cch; 
            }
            // ��� ������ ��������� ����������
            else ETW::Exception::Throw(WBEM_E_NOT_FOUND);
        }
    }
    return cchMax; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������
///////////////////////////////////////////////////////////////////////////////
WMI::ArrayType::ArrayType(const Event& event, CIMTYPE type, IWbemQualifierSet* pQualifiers)

    // ��������� ���������� ���������
    : _type(type), _pQualifiers(pQualifiers) 
{
    // �������� ��� �������� �������
    _pElementType.reset(event.CreateElementType(_type & ~CIM_FLAG_ARRAY, _pQualifiers)); 
}

size_t WMI::ArrayType::GetCount(const ETW::IContainer& parent) const
{
    // ���������������� ����������
    _bstr_t bstrCountName; size_t maxCount; 

    // �������� ��� ���� � ��������� �������
    if (GetAttribute(_pQualifiers, L"WmiSizeIs", &bstrCountName)) 
    {
        // ��������� ��� ������������� ��������
        if (parent.Type().LogicalType() != ETW::TYPE_STRUCT) 
        {
            // ��� ������ ��������� ����������
            ETW::Exception::Throw(WBEM_E_INVALID_QUALIFIER);
        }
        // ��������� �������������� ����
        const ETW::IStruct& parentStruct = (const ETW::IStruct&)parent; size_t count = 0; 

        // ����� ���� � ��������
        if (const ETW::IElement* pCount = parentStruct.FindName(bstrCountName))
        {
            // ��������� �������� ����
            memcpy(&count, pCount->GetDataAddress(), pCount->GetDataSize()); return count; 
        }
        // ��� ������ ��������� ����������
        else ETW::Exception::Throw(WBEM_E_NOT_FOUND);
    }
    // �������� ������������� ������ ����
    return (GetAttribute(_pQualifiers, L"Max", &maxCount)) ? maxCount : SIZE_MAX; 
}
    
///////////////////////////////////////////////////////////////////////////////
// ���������� ���������
///////////////////////////////////////////////////////////////////////////////
WMI::StructType::StructType(const Event& event, IWbemClassObject* pClass, PCWSTR szName) 

    // ��������� ���������� ���������
    : _pClass(pClass), _id(GUID_NULL), _name(szName)
{ 
    // ����������
    _bstr_t bstrGuid; HRESULT hr = S_OK; SAFEARRAY* pNames = nullptr; 

    // �������� �������� ������
    IWbemQualifierSetPtr pQualifiers; _pClass->GetQualifierSet(&pQualifiers); 

    // ��� ������� ���������
    if (pQualifiers && GetAttribute(pQualifiers, L"Guid", &bstrGuid)) 
    { 
        // ������������� GUID � ��������� �����
        hr = ::IIDFromString(bstrGuid, &_id); 
    }
    // ��� ���������� ��������������
    if (FAILED(hr) || ::InlineIsEqualGUID(_id, GUID_NULL)) 
    {
        // ������������� ���������� �������������
        hr = ::CoCreateGuid(&_id); if (FAILED(hr)) ETW::Exception::Throw(hr); 
    }
    // ����������� ��� ���� � ��������� WmiDataId
    hr = _pClass->GetNames(L"WmiDataId", WBEM_FLAG_ONLY_IF_TRUE, nullptr, &pNames); 

    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 
    try { 
        // �������� ����� ���������� �������
        std::vector<std::wstring> names(pNames->rgsabound->cElements); 

        // ��� ���� �����
        for (LONG i = 0; (ULONG)i < pNames->rgsabound->cElements; i++)
        {
            // �������� ��� ����
            _bstr_t bstrName; hr = SafeArrayGetElement(pNames, &i, &bstrName); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr); 

            // �������� �������� ����
            hr = _pClass->GetPropertyQualifierSet(bstrName, &pQualifiers); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // �������� ������� WmiDataId
            size_t index = GetAttribute<size_t>(pQualifiers, L"WmiDataId"); 

            // ��������� �������� �������
            if (index == 0 || index > names.size()) 
            {
                // ��� ������ ��������� ����������
                ETW::Exception::Throw(WBEM_E_VALUE_OUT_OF_RANGE); 
            }
            // ��������� ��� ���� � ������ �������
            names[index - 1] = (PCWSTR)bstrName; 
        }
        // ��� ���� �����
        for (size_t i = 0; i < names.size(); i++)
        {
            // �������� �������� ����
            hr = _pClass->GetPropertyQualifierSet(names[i].c_str(), &pQualifiers); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // �������� ��� ����
            CIMTYPE type; hr = _pClass->Get(names[i].c_str(), 0, nullptr, &type, 0); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pClass, _pClass.GetIID()); 

            // �������� �������� ���� � �������
            _fields.emplace_back(names[i], std::shared_ptr<ETW::IElementType>(
                event.CreateElementType(type, pQualifiers)
            )); 
        }
        // ���������� ���������� �������
        ::SafeArrayDestroy(pNames); 
    }
    // ���������� ��������� ������
    catch (...) { ::SafeArrayDestroy(pNames); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// C������ � ��������� � ��� ����������
///////////////////////////////////////////////////////////////////////////////
WMI::Event::Event(IWbemServices* pNamespace, IWbemClassObject* pClass, const EVENT_TRACE* pEvent, size_t pointerSize) 
    
    // ��������� ���������� ���������
    : _pNamespace(pNamespace), _pointerSize(pointerSize), _pEvent(pEvent)
{
    // �������� ��� ������
    _bstr_t bstrClassName = GetProperty<_bstr_t>(pClass, L"__CLASS"); 

    // ������������� ��� ���������
    _pStructType.reset(new StructType(*this, pClass, bstrClassName)); 

    // ������������� ������ � ���������
    _pStruct.reset(new ETW::Struct(L"", *_pStructType, pEvent->MofData, pEvent->MofLength)); 
}

ETW::IElementType* WMI::Event::CreateElementType(CIMTYPE type, IWbemQualifierSet* pQualifiers) const
{
    _bstr_t bstrExtension; _bstr_t bstrFormat; _bstr_t bstrClassName; 

    // ���������� ���������
    if (HasAttribute(pQualifiers, L"Pointer") || HasAttribute(pQualifiers, L"PointerType"))
    {
        // ������� ��� ��������
        return new WMI::PointerType(type, pQualifiers, PointerSize()); 
    }
    // �������� ������� ����������
    if (GetAttribute(pQualifiers, L"Extension", &bstrExtension) && wcscmp(bstrExtension, L"SizeT") == 0) 
    {
        // ������� ��� ��������
        return new WMI::PointerType(type, pQualifiers, PointerSize()); 
    }
    // ��� ������� ������������ �����
    if (type == (CIM_FLAG_ARRAY | CIM_SINT8) || type == (CIM_FLAG_ARRAY | CIM_UINT8)) 
    { 
        // �������� ������� ��������������
        if (GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"s") == 0)
        {
            // ������� �������� ���������� ����
            return new WMI::StringType(type, pQualifiers); 
        }
    }
    // ������� �������� ���������� ����
    if (type == (CIM_FLAG_ARRAY | CIM_CHAR16)) return new WMI::StringType(type, pQualifiers);

    // ������� �������� �������
    if ((type & CIM_FLAG_ARRAY) != 0) return new WMI::ArrayType(*this, type, pQualifiers); 

    // ��� ������� ANSI
    if (type == CIM_UINT8 && GetAttribute(pQualifiers, L"Format", &bstrFormat) && wcscmp(bstrFormat, L"c") == 0)
    {
        // ������� �������� ���������� ����
        return new WMI::StringType(type, pQualifiers); 
    }
    // ��� ������� Unicode ������� �������� ���������� ����
    if (type == CIM_CHAR16) return new WMI::StringType(type, pQualifiers); 

    // ��� ����� ������� �������� ���������� ����
    if (type == CIM_STRING) return new WMI::StringType(type, pQualifiers); 

    // ��� ������� �������
    if (type == CIM_OBJECT) { IWbemClassObjectPtr pStruct;
     
        // ��� ������� ������������ ��������
        if (GetAttribute(pQualifiers, L"Cimtype", &bstrClassName) && wcsncmp(bstrClassName, L"object:", 7) == 0) 
        {
            // ������� ��� ������
            std::wstring strClassName((PCWSTR)bstrClassName + 7); bstrClassName = strClassName.c_str();

            // �������� �������� ������
            HRESULT hr = _pNamespace->GetObject(bstrClassName, 0, nullptr, &pStruct, nullptr); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, __uuidof(IWbemServices)); 

            // ������� �������� ���������
            return new WMI::StructType(*this, pStruct, bstrClassName); 
        }
        // �������� ������� ����������
        if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
        {
            // ������� �������� ���������� ����
            if (wcscmp(bstrExtension, L"RString" ) == 0) return new WMI::StringType(type, pQualifiers); 
            if (wcscmp(bstrExtension, L"RWString") == 0) return new WMI::StringType(type, pQualifiers); 

            // ������� �������� ���� �������
            if (wcscmp(bstrExtension, L"WmiTime") == 0) return new WMI::DateTimeType(type, pQualifiers); 

            // ������� �������� ������
            if (wcscmp(bstrExtension, L"Variant") == 0) return new WMI::BinaryType(type, pQualifiers); 

            // ������� GUID � SID
            if (wcscmp(bstrExtension, L"Guid") == 0) return new WMI::GuidType(type, pQualifiers);
            if (wcscmp(bstrExtension, L"Sid" ) == 0) return new WMI::SidType (type, pQualifiers, PointerSize()); 

            // ������� IPv-������ � ����� ����� 
            if (wcscmp(bstrExtension, L"IPAddr"  ) == 0) return new WMI::IPv4Type  (type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV4") == 0) return new WMI::IPv4Type  (type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV6") == 0) return new WMI::IPv6Type  (type, pQualifiers);
            if (wcscmp(bstrExtension, L"Port"    ) == 0) return new WMI::UInt16Type(type, pQualifiers);
        }
    }
    switch (type)
    {
    // ������� ��������� ��� ������
    case CIM_BOOLEAN: return new WMI::BooleanType(pQualifiers); 

    // ������� �������� ��� ������
    case CIM_SINT8  : return new WMI::Int8Type  (type, pQualifiers); 
    case CIM_UINT8  : return new WMI::UInt8Type (type, pQualifiers); 
    case CIM_SINT16 : return new WMI::Int16Type (type, pQualifiers); 
    case CIM_UINT16 : return new WMI::UInt16Type(type, pQualifiers); 
    case CIM_SINT32 : return new WMI::Int32Type (type, pQualifiers); 
    case CIM_UINT32 : 
    {
        // �������� ������� ����������
        if (GetAttribute(pQualifiers, L"Extension", &bstrExtension)) 
        {
            // ������� IP-�����
            if (wcscmp(bstrExtension, L"IPAddr"  ) == 0) return new WMI::IPv4Type(type, pQualifiers); 
            if (wcscmp(bstrExtension, L"IPAddrV4") == 0) return new WMI::IPv4Type(type, pQualifiers); 
        }
        // ������� �������� ���
        return new WMI::UInt32Type(type, pQualifiers); 
    }
    case CIM_SINT64 : 
    {
        // ��� ������� �������
        if (HasAttribute(pQualifiers, L"WmiTimeStamp"))
        {
            // ������� ��� �������
            return new WMI::DateTimeType(type, pQualifiers); 
        }
        // ������� �������� ���
        return new WMI::Int64Type(type, pQualifiers); 
    }
    case CIM_UINT64 : 
    {
        // ��� ������� �������
        if (HasAttribute(pQualifiers, L"WmiTimeStamp"))
        {
            // ������� ��� �������
            return new WMI::DateTimeType(type, pQualifiers); 
        }
        // ������� �������� ���
        return new WMI::UInt64Type(type, pQualifiers); 
    }
    // ������� �������� ���
    case CIM_REAL32: return new WMI::FloatType (type, pQualifiers); 
    case CIM_REAL64: return new WMI::DoubleType(type, pQualifiers); 

    // ������� �������� ���� �������
    case CIM_DATETIME: return new WMI::CimDateTimeType(type, pQualifiers); 
    }
    // ��� ������ ��������� ����������
    ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////////
WMI::ProviderInfo::ProviderInfo(IWbemServices* pNamespace, const GUID& id, IWbemClassObject* pProvider) 

    // ��������� ���������� ���������
    : _pNamespace(pNamespace), _id(id), _pProvider(pProvider)
{
    // ������� ��� ���� ��� ���������
    IWbemQualifierSetPtr pFlagsQualifiers; IWbemQualifierSetPtr pLevelQualifiers; 

    // �������� �������� ����
    if (SUCCEEDED(_pProvider->GetPropertyQualifierSet(L"Flags", &pFlagsQualifiers)))
    {
        // ��������� �������� ��������� �����������
        _pKeywords.reset(new ValueMap(pFlagsQualifiers, TRUE)); 
    }
    // �������� ��������� �����������
    else _pKeywords.reset(new ValueMap()); 

    // �������� ������� ����
    if (SUCCEEDED(_pProvider->GetPropertyQualifierSet(L"Level", &pLevelQualifiers)))
    {
        // ��������� �������� ������� �����������
        _pLevels.reset(new ValueMap(pLevelQualifiers)); 
    }
    // �������� ������� �����������
    else _pLevels.reset(new ValueMap()); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ���� WMI
///////////////////////////////////////////////////////////////////////////////
WMI::Namespace::Namespace()
try {
    // ������� ��� ������������ ����
    IWbemLocatorPtr pLocator; _bstr_t bstrNamespace(L"root\\wmi"); 

    // ������� ������ �����������
    HRESULT hr = CoCreateInstance(
        __uuidof(WbemLocator ), nullptr, CLSCTX_INPROC_SERVER, 
        __uuidof(IWbemLocator), (PVOID*) &pLocator
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr); 

    // ������������ � ������������ ���� WMI
    hr = pLocator->ConnectServer(
        bstrNamespace,              // ������������ ����
        nullptr,                    // ������� ������������
        nullptr,                    // ������� �������� ������������
        nullptr,                    // ������� �����������
        0,                          // ���������� �������� 
        nullptr,                    // ������� �����
        nullptr,                    // ���������� ���������
        &_pNamespace                // ������ ������������ ����
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, pLocator, __uuidof(pLocator)); 

    // ��������� ��������� ������ ����������� 
    hr = CoSetProxyBlanket(_pNamespace,
        RPC_C_AUTHN_WINNT,              // ������ ��������������
        RPC_C_AUTHZ_NONE,               // ������ �����������
        nullptr,                        // 
        RPC_C_AUTHN_LEVEL_PKT,          // ������� ������ ��� ��������������
        RPC_C_IMP_LEVEL_IMPERSONATE,    // ������� ������������� ����
        nullptr,                        // 
        EOAC_NONE                       // 
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr);
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventProviderClass(REFGUID guid) const
try {
    // ������� ��� ��������� ������
    _bstr_t bstrRootClass(L"EventTrace"); IEnumWbemClassObjectPtr pClasses;

    // ����������� ��� ������, ����������� �� EventTrace
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrRootClass,                      // �������� ����� ��� ������������ ����������
        WBEM_FLAG_FORWARD_ONLY  |           // ���������������� ������������
        WBEM_FLAG_DEEP          |           // ������������ ���������� ��� ��������� ������
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // ������������� ������� �����������
        nullptr,                            // ���������� ���������
        &pClasses                           // ������������� �������
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, _pNamespace.GetIID()); 

    // ��� ���� ����������
    for (IWbemClassObjectPtr pProvider; ; pProvider.Release())     
    {
        _bstr_t bstrGuid; GUID classGuid; 

        // �������� �������� ���������� ������
        ULONG count = 0; hr = pClasses->Next(WBEM_INFINITE, 1, &pProvider, &count); 

        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr, pClasses, pClasses.GetIID()); 
        
        // ��������� ���������� ������������
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 
        
        // �������� �������� ������
        if (FAILED(pProvider->GetQualifierSet(&pQualifiers))) continue;  

        // �������� GUID ������
        if (!GetAttribute(pQualifiers, L"Guid", &bstrGuid)) continue; 

        // ������������� ��� GUID
        if (FAILED(::IIDFromString(bstrGuid, &classGuid))) continue; 
            
        // �������� GUID   
        if (InlineIsEqualGUID(classGuid, guid)) return pProvider.Detach(); 
    }
    return nullptr; 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventCategoryClass(REFGUID guid, USHORT version) const
try {
    // ������� ��� ��������� ������
    _bstr_t bstrRootClass(L"EventTrace"); IEnumWbemClassObjectPtr pClasses;

    // ����������� ��� ������, ����������� �� EventTrace
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrRootClass,                      // �������� ����� ��� ������������ ����������
        WBEM_FLAG_FORWARD_ONLY  |           // ���������������� ������������
        WBEM_FLAG_DEEP          |           // ������������ ���������� ��� ��������� ������
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // ������������� ������� �����������
        nullptr,                            // ���������� ���������
        &pClasses                           // ������������� �������
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pNamespace, __uuidof(IWbemServices)); 

    // ��� ���� ����������
    for (IWbemClassObjectPtr pEventCategory; ; pEventCategory.Release()) 
    {
        _bstr_t bstrGuid; GUID classGuid; size_t classVersion; 

        // �������� �������� ���������� ������
        ULONG count = 0; hr = pClasses->Next(WBEM_INFINITE, 1, &pEventCategory, &count); 

        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr, pClasses, pClasses.GetIID()); 
        
        // ��������� ���������� ������������
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 
        
        // �������� �������� ������
        if (FAILED(pEventCategory->GetQualifierSet(&pQualifiers))) continue;  

        // �������� GUID ������
        if (!GetAttribute(pQualifiers, L"Guid", &bstrGuid)) continue; 

        // ������������� GUID � ��������� �����
        if (FAILED(::IIDFromString(bstrGuid, &classGuid))) continue; 
                
        // �������� ���������� GUID ������
        if (!InlineIsEqualGUID(classGuid, guid)) continue; 

        // �������� ������ ������
        if (GetAttribute(pQualifiers, L"EventVersion", &classVersion))
        {
            // ��������� ���������� ������
            if (classVersion != version) continue; 
        }
        // ������� ��������� �����
        return pEventCategory.Detach(); 
    }
    return nullptr; 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 

IWbemClassObjectPtr WMI::Namespace::FindEventClass(REFGUID guid, USHORT version, UCHAR type) const
try {
    // ����� ����� ��������� �������
    IWbemClassObjectPtr pEventCategory = FindEventCategoryClass(guid, version); 

    // ��������� ���������� ������
    if (!pEventCategory) return nullptr; 

    // �������� ��� ������ ������������ ������������ ����
    _bstr_t bstrClassPath = GetProperty<_bstr_t>(pEventCategory, L"__RELPATH"); 

     // ����������� ��� ����������� ������ �� ��������� �������
    IEnumWbemClassObjectPtr pEventClasses;
    HRESULT hr = _pNamespace->CreateClassEnum(
        bstrClassPath,                      // �������� ����� ��� ������������ ����������
        WBEM_FLAG_FORWARD_ONLY  |           // ���������������� ������������
        WBEM_FLAG_SHALLOW       |           // 
        WBEM_FLAG_USE_AMENDED_QUALIFIERS,   // ������������� ������� �����������
        nullptr,                            // ���������� ���������
        &pEventClasses                      // ������������� �������
    );
    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, pEventClasses, pEventClasses.GetIID()); 

    // ��� ���� ����������
    for (IWbemClassObjectPtr pEventClass; ; pEventClass.Release()) 
    {
        _variant_t varEventType; INT classEventType = 0;

        // �������� �������� ���������� ������
        ULONG count = 0; hr = pEventClasses->Next(WBEM_INFINITE, 1, &pEventClass, &count); 

        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr, pEventClasses, pEventClasses.GetIID()); 
        
        // ��������� ���������� ������������
        if (hr != S_OK) break; IWbemQualifierSetPtr pQualifiers; 

        // �������� �������� ������
        if (FAILED(pEventClass->GetQualifierSet(&pQualifiers))) continue;  

        // �������� ��� ������
        if (!GetAttribute(pQualifiers, L"EventType", &varEventType)) continue; 

        // ��� �������� ������ ���� ����
        if ((varEventType.vt & VT_ARRAY) == 0) 
        {
            // ��������� ���������� ����
            if ((size_t)varEventType == type) return pEventClass.Detach();  
        }
        // ��� ���� ��������� �������
        else for (LONG i = 0; (ULONG)i < varEventType.parray->rgsabound->cElements; i++)
        {
            // �������� �������� �������� �������
            hr = ::SafeArrayGetElement(varEventType.parray, &i, &classEventType); 

            // ��������� ���������� ������
            if (FAILED(hr)) ETW::Exception::Throw(hr); 

            // ��������� ���������� ����
            if (classEventType == type) return pEventClass.Detach();  
        }
    }
    return nullptr; 
}
// ������������� ��� ������
catch (const _com_error& error) { throw_com_error(error); } 



