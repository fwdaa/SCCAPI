#include <ws2tcpip.h>
#include "TraceETW.hpp"
#include <sddl.h>
#include <ip2string.h>
#include <comdef.h>
#include <comutil.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(ISupportErrorInfo, __uuidof(ISupportErrorInfo));
_COM_SMARTPTR_TYPEDEF(IErrorInfo       , __uuidof(IErrorInfo       ));
_COM_SMARTPTR_TYPEDEF(IRecordInfo      , __uuidof(IRecordInfo      ));
_COM_SMARTPTR_TYPEDEF(ISWbemDateTime   , __uuidof(ISWbemDateTime   ));

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������
///////////////////////////////////////////////////////////////////////////////
inline std::string WideCharToMultiByte(UINT codePage, PCWSTR sz, size_t cch, bool exception)
{
    // ���������� ������ ������
    if (cch == size_t(-1)) cch = wcslen(sz); if (cch == 0) return std::string(); 

    // ���������� ��������� ������ ������
    int cb = ::WideCharToMultiByte(codePage, 0, sz, (int)cch, nullptr, 0, nullptr, nullptr); 
    
    // ��� ������������� ������
    if (!cb) { if (!exception) return std::string();
    
        // ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // �������� ����� ���������� �������
    std::string str(cb, 0); 

    // ��������� �������������� ���������
    cb = ::WideCharToMultiByte(codePage, 0, sz, (int)cch, &str[0], cb, nullptr, nullptr); 

    // ��� ������������� ������
    if (!cb) { if (!exception) return std::string();
    
        // ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // ������� ��������������� ������
    str.resize(cb); return str; 
}

inline std::wstring MultiByteToWideChar(UINT codePage, PCSTR sz, size_t cb, bool exception)
{
    // ���������� ������ ������
    if (cb == size_t(-1)) cb = strlen(sz); if (cb == 0) return std::wstring(); 

    // ���������� ��������� ������ ������
    int cch = ::MultiByteToWideChar(codePage, 0, sz, (int)cb, nullptr, 0); 
    
    // ��� ������������� ������
    if (!cch) { if (!exception) return std::wstring();
    
        // ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // �������� ����� ���������� �������
    std::wstring str(cch, 0); 

    // ��������� �������������� ���������
    cch = ::MultiByteToWideChar(codePage, 0, sz, (int)cb, &str[0], cch); 

    // ��� ������������� ������
    if (!cch) { if (!exception) return std::wstring();
    
        // ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // ������� ��������������� ������
    str.resize(cch); return str; 
}
 
///////////////////////////////////////////////////////////////////////////////
// ����������
///////////////////////////////////////////////////////////////////////////////
void ETW::Exception::Throw(HRESULT status, IUnknown* pObj, REFIID riid)
{
    // ���������������� ����������
	ISupportErrorInfoPtr pSupport; BOOL support = FALSE; 

	// ��������� ��������� ����������
	if (SUCCEEDED(pObj->QueryInterface(&pSupport)))
	{
		// ��������� ��������� ������
		support = (pSupport->InterfaceSupportsErrorInfo(riid) == S_OK); 
	}
	// �������� �������� ������
    IErrorInfoPtr pErrorInfo; 
    if (support && SUCCEEDED(::GetErrorInfo(0, &pErrorInfo)))
    {
        // ������� ������ ����������
        Exception error(status, pErrorInfo); 

        // ������������ ������ � ��������� ����������
        ::SetErrorInfo(0, pErrorInfo); throw error;
    }
    // ��������� ����������
    else throw Exception(status); 
}

ETW::Exception::Exception(HRESULT status, IErrorInfo* pErrorInfo) : std::runtime_error(""), _status(status)
{
    // ������� ������������ ANSI-���������
	UINT codePage = CP_ACP; BSTR bstrError = nullptr;

    // �������� ��������� �� ������
	if (pErrorInfo && SUCCEEDED(pErrorInfo->GetDescription(&bstrError)))
	{
        // ���������� ������ ������
        size_t cch = ::SysStringLen(bstrError); 

        // ��������� �������������� ���������
        _strMessage = WideCharToMultiByte(codePage, bstrError, cch, false); 

        // ���������� ���������� �������
        ::SysFreeString(bstrError); if (!_strMessage.empty()) return; 
    }
	// �������� ����������� �������� ������
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); PSTR szMessage = nullptr; 

    // ������� ����� ��������� �������� ������
	DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM; 

	// �������� �������������� ���������
	if (!::FormatMessageA(dwFlags, nullptr, status, langID, (PSTR)&szMessage, 0, nullptr)) 
    {
	    // �������� �������������� ���������
	    if (!::FormatMessageA(dwFlags, nullptr, status, 0, (PSTR)&szMessage, 0, nullptr)) return; 
    }
    // ��������� ���������� ���������
    _strMessage = szMessage; ::LocalFree(szMessage); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� �����
///////////////////////////////////////////////////////////////////////////////
BSTR ETW::IValueMap::ToString(ULONGLONG value) const
{
    std::wstring strValue; 

    // ��� ������������ ��������
    if (Type() == ValueMapType::Index)
    {
        // ��� ���� ��������
        for (size_t i = 0, count = Count(); i < count; i++)
        {
            // �������� �������� ��������
            const IValueInfo& info = Item(i); 

            // ��� ���������� ��������
            if (value == info.Value())
            {
                // ������� ��� ��������
                strValue = info.Name(); break; 
            }
        }
    }
    else {
        // ��� ���� ��������
        for (size_t i = 0, count = Count(); value != 0 && i < count; i++)
        {
            // �������� �������� ��������
            const IValueInfo& info = Item(i); 

            // ��� ������� ���� � ��������
            if ((value & info.Value()) != 0)
            {
                // ������� �����������
                if (!strValue.empty()) strValue += L' '; 

                // ������� ��� �����
                strValue += info.Name(); value &= ~info.Value(); 
            }
        }
    }
    // �������� ������ ��� ������
    BSTR bstrValue = ::SysAllocString(strValue.c_str()); 

    // ��������� ���������� ������
    if (!bstrValue) Exception::Throw(E_OUTOFMEMORY); return bstrValue; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ���
///////////////////////////////////////////////////////////////////////////////
BSTR ETW::BasicType::ToString(const ETW::IContainer&, const void* pvData, size_t cbData) const
{
    // �������� ��������
    VARIANT value = GetValue(pvData, cbData); 
    try {
        // ��������������� ��������
        std::wostringstream stream; Format(value, stream); 

        // �������� ������ ��� ������
        BSTR bstr = ::SysAllocString(stream.str().c_str()); 

        // ��������� ���������� ������
        if (!bstr) Exception::Throw(E_OUTOFMEMORY); 

        // ���������� ���������� �������
        ::VariantClear(&value); return bstr; 
    }
    // ���������� ���������� �������
    catch (...) { ::VariantClear(&value); throw; }
}
 
///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
size_t ETW::BooleanType::GetSize(const ETW::IContainer&, const void*, size_t cbRemaining) const
{
    // � ����������� �� ������� �����������
    size_t cb = SIZE_MAX; switch (InputType())
    {
    // ������� ������ ������
    case TDH_INTYPE_BOOLEAN: cb = sizeof(BOOL); break; 
    case TDH_INTYPE_UINT8  : cb = sizeof(BYTE); break; 
    }
    // ��������� ������������� ������
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb;  
}

VARIANT ETW::BooleanType::GetValue(const void* pvData, size_t cbData) const
{
    // ���������������� ����������
    VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 

    switch (InputType())
    {
    // ������� ������ ������
    case TDH_INTYPE_BOOLEAN: 
    {
        // ������� �������� �� ������
        BOOL boolValue; memcpy(&boolValue, pvData, cbData); 

        // ������� ��������
        V_BOOL(&var) = (boolValue) ? VARIANT_TRUE : VARIANT_FALSE; break;
    }
    case TDH_INTYPE_UINT8:
    {
        // ������� �������� �� ������
        BYTE boolValue; memcpy(&boolValue, pvData, cbData); 

        // ������� ��������
        V_BOOL(&var) = (boolValue) ? VARIANT_TRUE : VARIANT_FALSE; break; 
    }}
    return var; 
}

BSTR ETW::BooleanType::ToString(const ETW::IContainer&, const void* pvData, size_t cbData) const
{
    // �������� ��������
    VARIANT value = GetValue(pvData, cbData); BSTR bstr = nullptr; 
    try {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // �������� ��������� ������������� ��������
            bstr = pValueMap->ToString(V_BOOL(&value) ? 1 : 0); 
        }
        else {
            // �������� ������ ��� ������
            bstr = ::SysAllocString(V_BOOL(&value) ? L"true" : L"false"); 

            // ��������� ���������� ������
            if (!bstr) Exception::Throw(E_OUTOFMEMORY); 
        }
        // ���������� ���������� �������
        ::VariantClear(&value); return bstr; 
    }
    // ���������� ���������� �������
    catch (...) { ::VariantClear(&value); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
void ETW::Int8Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT8        : stream << std::hex << (  signed char)V_I1(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDBYTE   : stream << std::dec << (unsigned char)V_I1(&value); return; 
    case TDH_OUTTYPE_BYTE           : stream << std::dec << (  signed char)V_I1(&value); return; 
    default                         : stream << std::dec << (  signed char)V_I1(&value); return; 
    }
}

void ETW::UInt8Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT8        : stream << std::hex << (unsigned char)V_UI1(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDBYTE   : stream << std::dec << (unsigned char)V_UI1(&value); return; 
    case TDH_OUTTYPE_BYTE           : stream << std::dec << (  signed char)V_UI1(&value); return; 
    default                         : stream << std::dec << (unsigned char)V_UI1(&value); return; 
    }
}

void ETW::Int16Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT16       : stream << std::hex << ( SHORT)V_I2(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDSHORT  : stream << std::dec << (USHORT)V_I2(&value); return; 
    case TDH_OUTTYPE_SHORT          : stream << std::dec << ( SHORT)V_I2(&value); return; 
    default                         : stream << std::dec << ( SHORT)V_I2(&value); return; 
    }
}

void ETW::UInt16Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT16       : stream << std::hex << (USHORT)V_UI2(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDSHORT  : stream << std::dec << (USHORT)V_UI2(&value); return; 
    case TDH_OUTTYPE_SHORT          : stream << std::dec << ( SHORT)V_UI2(&value); return; 
    default                         : stream << std::dec << (USHORT)V_UI2(&value); return; 
    }
}

void ETW::Int32Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT32       : stream << std::hex << ( LONG)V_I4(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDINT    : stream << std::dec << (ULONG)V_I4(&value); return; 
    case TDH_OUTTYPE_INT            : stream << std::dec << ( LONG)V_I4(&value); return; 
    }
    switch (InputType())
    {
    case TDH_INTYPE_HEXINT32        : stream << std::hex << ( LONG)V_I4(&value); return; 
    default                         : stream << std::dec << ( LONG)V_I4(&value); return; 
    }
}

void ETW::UInt32Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_CODE_POINTER   : stream << std::hex << (ULONG)V_UI4(&value); return; 
    case TDH_OUTTYPE_HEXINT32       : stream << std::hex << (ULONG)V_UI4(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDINT    : stream << std::dec << (ULONG)V_UI4(&value); return; 
    case TDH_OUTTYPE_INT            : stream << std::dec << ( LONG)V_UI4(&value); return; 
    }
    switch (InputType())
    {
    case TDH_INTYPE_HEXINT32        : stream << std::hex << (ULONG)V_UI4(&value); return; 
    default                         : stream << std::dec << (ULONG)V_UI4(&value); return; 
    }
}

void ETW::Int64Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_HEXINT64       : stream << std::hex << ( LONGLONG)V_I8(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDLONG   : stream << std::dec << (ULONGLONG)V_I8(&value); return; 
    case TDH_OUTTYPE_LONG           : stream << std::dec << ( LONGLONG)V_I8(&value); return; 
    }
    switch (InputType())
    {
    case TDH_INTYPE_HEXINT64        : stream << std::hex << ( LONGLONG)V_I8(&value); return; 
    default                         : stream << std::dec << ( LONGLONG)V_I8(&value); return; 
    }
}

void ETW::UInt64Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    switch (OutputType())
    {
    case TDH_OUTTYPE_CODE_POINTER   : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
    case TDH_OUTTYPE_HEXINT64       : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
    case TDH_OUTTYPE_UNSIGNEDLONG   : stream << std::dec << (ULONGLONG)V_UI8(&value); return; 
    case TDH_OUTTYPE_LONG           : stream << std::dec << ( LONGLONG)V_UI8(&value); return; 
    }
    switch (InputType())
    {
    case TDH_INTYPE_HEXINT64        : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
    default                         : stream << std::dec << (ULONGLONG)V_UI8(&value); return; 
    }
}

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ��� ����� ����������� ���������
///////////////////////////////////////////////////////////////////////////////
void ETW::PointerType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    if (_pointerSize == 4)
    {
        switch (OutputType())
        {
        case TDH_OUTTYPE_CODE_POINTER   : stream << std::hex << (ULONG)V_UI4(&value); return; 
        case TDH_OUTTYPE_HEXINT32       : stream << std::hex << (ULONG)V_UI4(&value); return; 
        case TDH_OUTTYPE_UNSIGNEDINT    : stream << std::dec << (ULONG)V_UI4(&value); return; 
        case TDH_OUTTYPE_INT            : stream << std::dec << ( LONG)V_UI4(&value); return; 
        }
        switch (InputType())
        {
        case TDH_INTYPE_HEXINT32        : stream << std::hex << (ULONG)V_UI4(&value); return; 
        default                         : stream << std::dec << (ULONG)V_UI4(&value); return; 
        }
    }
    else {
        switch (OutputType())
        {
        case TDH_OUTTYPE_CODE_POINTER   : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
        case TDH_OUTTYPE_HEXINT64       : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
        case TDH_OUTTYPE_UNSIGNEDLONG   : stream << std::dec << (ULONGLONG)V_UI8(&value); return; 
        case TDH_OUTTYPE_LONG           : stream << std::dec << ( LONGLONG)V_UI8(&value); return; 
        }
        switch (InputType())
        {
        case TDH_INTYPE_HEXINT64        : stream << std::hex << (ULONGLONG)V_UI8(&value); return; 
        default                         : stream << std::dec << (ULONGLONG)V_UI8(&value); return; 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
inline size_t GetCharSize(USHORT inType)
{
    switch (inType)
    {
    case TDH_INTYPE_ANSISTRING: 
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING: 
    case TDH_INTYPE_COUNTEDANSISTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING: 
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING : return sizeof(CHAR); 

    case TDH_INTYPE_UNICODESTRING: 
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING: 
    case TDH_INTYPE_COUNTEDSTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING: 
    case TDH_INTYPE_NONNULLTERMINATEDSTRING     : return sizeof(WCHAR);
    }
    return 0; 
}

size_t ETW::StringType::GetSize(
    const ETW::IContainer& parent, const void* pvData, size_t cbRemaining) const
{
    // � ����������� �� ������� ������
    size_t cbChar = GetCharSize(InputType()); switch (InputType())
    {
    // ������ ��������� ����� �������
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:       
    case TDH_INTYPE_NONNULLTERMINATEDSTRING:    
        
        // ��������� ���������� �������� ��������
        if ((cbRemaining & (cbChar - 1)) != 0) ETW::ThrowBadData();
        
        return cbRemaining; 

    // ��� ������� ������� ������ � ������
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:   
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
    case TDH_INTYPE_COUNTEDANSISTRING: 
    case TDH_INTYPE_COUNTEDSTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING: 
    {        
        // ��������� ������������� ������
        if (cbRemaining < sizeof(USHORT)) ETW::ThrowBadData();

        // ��������� ������ ������ � ������
        USHORT cb = 0; memcpy(&cb, pvData, sizeof(cb)); 

        // ��� ������� � ������� big-endian 
        if (InputType() == TDH_INTYPE_REVERSEDCOUNTEDANSISTRING || 
            InputType() == TDH_INTYPE_REVERSEDCOUNTEDSTRING) 
        {
            // �������� ������� ���������� ������
            cb = MAKEWORD(HIWORD(cb), LOWORD(cb));
        }
        // ��������� ���������� �������� ��������
        if ((cb & (cbChar - 1)) != 0) ETW::ThrowBadData();

        // ��������� ������������� ������
        if (cbRemaining < sizeof(cb) + cb) ETW::ThrowBadData();

        // ������� ������ � ������
        return sizeof(cb) + cb; 
    }}
    // ���������� ������ ������ � ��������
    size_t cchMax = GetLength(&parent); if (cchMax != SIZE_MAX)
    {
        // ��������� ������ ������ � ������
        size_t cbMax = cchMax * cbChar; 

        // ��������� ������������ ������������� �������
        if (cbRemaining < cbMax) ETW::ThrowBadData(); return cbMax; 
    }
    // ��� ������������ ������
    if (((ULONG_PTR)pvData & (cbChar - 1)) == 0)
    {
        // ���������� ����� ��������
        size_t cchRemaining = cbRemaining / cbChar; 

        // � ����������� �� ������� ������
        size_t cch = 0; switch (InputType())
        {
        // ����� ���������� ������
        case TDH_INTYPE_ANSISTRING:     cch = strnlen((PCSTR )pvData, cchRemaining); break; 
        case TDH_INTYPE_UNICODESTRING:  cch = wcsnlen((PCWSTR)pvData, cchRemaining); break; 
        }
        // ��������� ���������� �������� ��������
        if (cch == cchRemaining && (cbRemaining & (cbChar - 1)) != 0) ETW::ThrowBadData();

        // ������ ����������� ������
        if (cch < cchRemaining) cch++; return cch * cbChar;  
    }
    // ��� ������������� ������
    else { WCHAR ch = WCHAR_MAX; size_t cb = 0; 

        // ��� ���� �������� ������
        for (; ch != 0 && cb + cbChar <= cbRemaining; )
        {
            // ����������� ������
            memcpy(&ch, pvData, cbChar); cb += cbChar; 

            // ������� �� ��������� ������
            pvData = (CONST BYTE*)pvData + cbChar; 
        }
        // ��������� ���������� �������� ��������
        if (ch != 0 && cb + cbChar > cbRemaining) ETW::ThrowBadData();

        return cb; 
    }
}

VARIANT ETW::StringType::GetValue(const void* pvData, size_t cbData) const
{
    // ���������� ������ �������
    size_t cbChar = GetCharSize(InputType()); size_t cch = cbData / cbChar; 

    // ��� ������������� ������
    if (cbData != 0 && ((ULONG_PTR)pvData & (cbChar - 1)) != 0)
    {
        // ����������� ������ � ����������� �����
        std::wstring buffer(cch, 0); memcpy(&buffer[0], pvData, cbData);

        // ������� ������ �� ������������ ������
        return GetValue(&buffer[0], cbData); 
    }
    switch (InputType())
    {
    // ��� ������� ������� ������ � ������
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:            
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING:             
    case TDH_INTYPE_COUNTEDANSISTRING: 
    case TDH_INTYPE_COUNTEDSTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING:

        // ���������� ������ ������
        pvData = (CONST BYTE*)pvData + sizeof(USHORT); 
        
        // ���������� ������ ������
        cbData -= sizeof(USHORT); cch -= sizeof(USHORT) / cbChar; break; 

    case TDH_INTYPE_ANSISTRING: 

        // ��� ��������� ���������� �����
        if (cch > 0 && GetLength(nullptr) == SIZE_MAX)
        {
            // �� ��������� ����������� ����
            if (((PCSTR)pvData)[cch - 1] == 0) { cbData -= cbChar; cch--; }
        }
        break; 

    case TDH_INTYPE_UNICODESTRING: 

        // ��� ��������� ���������� �����
        if (cch > 0 && GetLength(nullptr) == SIZE_MAX)
        {
            // �� ��������� ����������� ����
            if (((PCWSTR)pvData)[cch - 1] == 0) { cbData -= cbChar; cch--; }
        }
        break; 
    }
    // ���������������� ���������
    VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = VariantType(); 
    
    // ���������� ���������� ������
    if (cch == 0) V_BSTR(&varValue) = ::SysAllocString(L""); 

    // ��� Unicode-������
    else if (cbChar == sizeof(WCHAR))
    {
        // ������� ������ Unicode
        V_BSTR(&varValue) = ::SysAllocStringLen((PCWSTR)pvData, (UINT)cch); 
    }
    else { 
        // ������� ������������ ���������
        UINT codePage = (OutputType() == TDH_OUTTYPE_UTF8 || OutputType() == TDH_OUTTYPE_JSON) ? CP_UTF8 : CP_ACP; 

        // ��������� �������������� ���������
        std::wstring str = MultiByteToWideChar(codePage, (PCSTR)pvData, cbData, true); 

        // ������� ������ Unicode
        V_BSTR(&varValue) = ::SysAllocString(str.c_str()); 
    }
    // ��������� ���������� ������
    if (!V_BSTR(&varValue)) ETW::Exception::Throw(E_OUTOFMEMORY); return varValue; 
}

BSTR ETW::StringType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
    // ��������� ������������� ��������������
    if (OutputType() == TDH_OUTTYPE_STRING) 
    {
        // �������� ��������
        VARIANT varValue = GetValue(pvData, cbData); 
        try {
            // ������� ������
            BSTR bstr = ::SysAllocString(V_BSTR(&varValue)); 

            // ��������� ���������� ������
            if (!bstr) Exception::Throw(E_OUTOFMEMORY); 

            // ���������� ���������� �������
            ::VariantClear(&varValue); return bstr; 
        }
        // ���������� ���������� �������
        catch (...) { ::VariantClear(&varValue); throw; }
    }
    // ������� ������� �������
    return BasicType::ToString(parent, pvData, cbData); 
} 

void ETW::StringType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // ���������� ��������� �������
    PCWSTR str = V_BSTR(&value) + wcsspn(V_BSTR(&value), L" "); 

    // ����� ���������� ������
    if (!*str) return; size_t index = wcscspn(str, L"\t\r\n"); 

    // ��� ������� ���������� ��������
    while (str[index] != 0)
    {
	    // �������� ����� ������
        stream << std::wstring(str, index) << L" "; str += index + 1;

        // ��������� ������� ������������ ��������
        if (str[wcsspn(str, L" ")] == 0) return; 

        // ����� ���������� ������
        index = wcscspn(str, L"\t\r\n"); 
    }
    // �������� ����� ������
    stream << std::wstring(str, index);
}

///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
ETW::DateTimeType::DateTimeType()
{
    // ������� ������ ��������������
    HRESULT hr = ::CoCreateInstance(CLSID_SWbemDateTime, 
        nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&_pConvert)
    );
    // ��������� ���������� ������
    if (FAILED(hr)) _pConvert = nullptr; 
}

size_t ETW::DateTimeType::GetSize(const ETW::IContainer&, const void*, size_t cbRemaining) const 
{
    // � ����������� ��� ������� �������
    size_t cb = SIZE_MAX; switch (InputType())
    {
    // ������� ������ ������� ������
    case TDH_INTYPE_UINT32      : cb = sizeof(UINT32    ); break; 
    case TDH_INTYPE_FILETIME    : cb = sizeof(FILETIME  ); break; 
    case TDH_INTYPE_SYSTEMTIME  : cb = sizeof(SYSTEMTIME); break; 
    }
    // ��������� ������������� ������
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb;
}

VARIANT ETW::DateTimeType::GetValue(const void* pvData, size_t cbData) const
{
    // ���������������� ���������
    VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = VariantType();

    switch (InputType())
    {
    case TDH_INTYPE_UINT32:
    {
        /* TODO */
        break; 
    }
    case TDH_INTYPE_FILETIME: 
    { 
        // ��������� �����
        SYSTEMTIME systemTime; FILETIME fileTime; memcpy(&fileTime, pvData, cbData); 

        // ��������� �������������� �������
        if (!::FileTimeToSystemTime(&fileTime, &systemTime))
        {
            // ��� ������ ��������� ����������
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // ��� �������� UTC-�������
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) { SYSTEMTIME systemTimeLocal;

            // ������������� UTC-����� � ���������
            if (!::SystemTimeToTzSpecificLocalTime(nullptr, &systemTime, &systemTimeLocal))
            {
                // ��� ������ ��������� ����������
                Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            systemTime = systemTimeLocal; 
        }
        // ��������� �������������� �������
        if (!::SystemTimeToVariantTime(&systemTime, &V_DATE(&varValue)))
        {
            // ��� ������ ��������� ����������
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        break; 
    }
    case TDH_INTYPE_SYSTEMTIME: 
    { 
        // ��������� �����
        SYSTEMTIME systemTime; memcpy(&systemTime, pvData, cbData);

        // ��� �������� UTC-�������
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) { SYSTEMTIME systemTimeLocal;

            // ������������� UTC-����� � ���������
            if (!::SystemTimeToTzSpecificLocalTime(nullptr, &systemTime, &systemTimeLocal))
            {
                // ��� ������ ��������� ����������
                Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            systemTime = systemTimeLocal; 
        }
        // ��������� �������������� �������
        if (!::SystemTimeToVariantTime(&systemTime, &V_DATE(&varValue)))
        {
            // ��� ������ ��������� ����������
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        break; 
    }}
    return varValue; 
}

void ETW::DateTimeType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // ������� ������������ �����������
    LCID lcid = LOCALE_USER_DEFAULT;

    switch (OutputType())
    {
    case TDH_OUTTYPE_ETWTIME:
    {
        /* TODO */
        break; 
    }
    case TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME: lcid = LOCALE_INVARIANT; 

    case TDH_OUTTYPE_DATETIME_UTC:
    case TDH_OUTTYPE_DATETIME: { SYSTEMTIME systemTime; 

        // ��������� �������������� �������
        if (!::VariantTimeToSystemTime(V_DATE(&value), &systemTime))
        {
            // ��� ������ ��������� ����������
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // ���������� ��������� ������ ������
        int cchDate = ::GetDateFormatW(lcid, 0, &systemTime, nullptr, nullptr, 0); 

        // ��������� ���������� ������
        if (!cchDate) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // ���������� ��������� ������ ������
        int cchTime = ::GetTimeFormatW(lcid, 0, &systemTime, nullptr, nullptr, 0); 

        // ��������� ���������� ������
        if (!cchTime) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // �������� ����� ���������� �������
        std::wstring strDate(cchDate, 0); std::wstring strTime(cchTime, 0);

        // ��������������� ����
        cchDate = ::GetDateFormatW(lcid, 0, &systemTime, nullptr, &strDate[0], cchDate); 

        // ��������� ���������� ������
        if (!cchDate) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // ��������������� �����
        cchTime = ::GetTimeFormatW(lcid, 0, &systemTime, nullptr, &strDate[0], cchTime); 

        // ��������� ���������� ������
        if (!cchTime) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // ������� �������������� ������
        strDate.resize(cchDate - 1); strTime.resize(cchTime - 1);

        // ������� ���� � �����
        stream << strDate << L' ' << strTime; break; 
    }
    case TDH_OUTTYPE_CIMDATETIME: 
    { 
        // ��������� ������� ���������
        if (!_pConvert) ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED);

        // ������� ������� ���������� �������
        VARIANT_BOOL local = VARIANT_TRUE; BSTR bstr; 

        // ������� ������� UTC-�������
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) local = VARIANT_FALSE; 

        // ������� �������� �������
        HRESULT hr = _pConvert->SetVarDate(V_DATE(&value), local);

        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

        // �������� �������� ��������������� ������
        hr = _pConvert->get_Value(&bstr);
        
        // ��������� ���������� ������
        if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

        // ������� ������������� ������
        stream << bstr; break;  
    }}
}

VARIANT ETW::DateTimeType::DecodeString(BSTR bstrString) const
{
    // ��������� ������� ���������
    if (!_pConvert) ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED); 

    // ������� ������� ���������� �������
    VARIANT_BOOL local = (OutputType() != TDH_OUTTYPE_DATETIME_UTC) ? VARIANT_TRUE : VARIANT_FALSE; 

    // ���������������� ���������
    VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = VariantType(); 

    // ������� �������� ����������������� ������
    HRESULT hr = _pConvert->put_Value(bstrString);

    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

    // ������������� ������ �������
    hr = _pConvert->GetVarDate(local, &V_DATE(&varValue)); 

    // ��������� ���������� ������
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

    return varValue; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
size_t ETW::BinaryType::GetSize(const IContainer& parent, const void* pvData, size_t cbRemaining) const
{
    // � ����������� �� ���� ������
    size_t cb = SIZE_MAX; switch (InputType())
    {
    case TDH_INTYPE_MANIFEST_COUNTEDBINARY: 
    {
        // ��������� ������������� ������
        if (cbRemaining < sizeof(USHORT)) ETW::ThrowBadData();

        // ��������� ������ ������
        USHORT cbValue; memcpy(&cbValue, pvData, sizeof(cbValue)); 
        
        // ������� ����� ������������ ������
        cb = cbValue + sizeof(cbValue); break; 
    }
    case TDH_INTYPE_HEXDUMP: 
    {
        // ��������� ������������� ������
        if (cbRemaining < sizeof(ULONG)) ETW::ThrowBadData();

        // ��������� ������ ������
        ULONG cbValue; memcpy(&cbValue, pvData, sizeof(cbValue)); 
        
        // ������� ����� ������������ ������
        cb = cbValue + sizeof(cbValue); break; 
    }
    // ���������� ������ ������
    case TDH_INTYPE_BINARY: cb = GetSize(parent); break; 
    }
    // ��������� ������������� ������
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb; 
}

VARIANT ETW::BinaryType::GetValue(const void* pvData, size_t cbData) const
{
    switch (InputType())
    {
    case TDH_INTYPE_MANIFEST_COUNTEDBINARY: { size_t cb = sizeof(USHORT); 

        // ���������� ������ ������
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; break; 
    }
    case TDH_INTYPE_HEXDUMP: { size_t cb = sizeof(ULONG); 

        // ���������� ������ ������
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; break; 
    }}
    // ������� COM-������
    SAFEARRAY* pSafeArray = ::SafeArrayCreateVector(VT_UI1, 0, (ULONG)cbData); 

    // ��������� ���������� ������
    if (!pSafeArray) Exception::Throw(E_OUTOFMEMORY); PVOID pvContent;  
    try { 
        // �������� ����� ���������
        HRESULT hr = ::SafeArrayAccessData(pSafeArray, &pvContent); 

        // ��������� ���������� ������
        if (FAILED(hr)) Exception::Throw(hr); 
            
        // ����������� ��������
        memcpy(pvContent, pvData, cbData); ::SafeArrayUnaccessData(pSafeArray);
    }
    // ���������� ���������� �������
    catch (...) { ::SafeArrayDestroy(pSafeArray); throw; }

    // ������� ������������� COM-�������
    VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
    // ������� COM-������
    V_ARRAY(&var) = pSafeArray; return var;  
}

void ETW::BinaryType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // ���������� ������ SID
    LONG cb; HRESULT hr = ::SafeArrayGetUBound(V_ARRAY(&value), 0, &cb); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); PBYTE pbBuffer = nullptr; 

    // �������� ������ � ������
    hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pbBuffer); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); 
    
    // ������� ����������������� ������������� ������
    for (LONG i = 0; i < cb; i++) stream << std::hex << pbBuffer[i]; 

    // ���������� �� ������� � ������
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������
///////////////////////////////////////////////////////////////////////////////
void ETW::GuidType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // �������� ������ ��� ���������� ������������� GUID
    WCHAR szGUID[39]; GUID* pGuid = nullptr; 

    // �������� ������ � ������
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pGuid); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); 
    
    // �������� � ������� ��������� ������������� GUID
    if (::StringFromGUID2(*pGuid, szGUID, _countof(szGUID))) stream << szGUID;

    // ���������� �� ������� � ������
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

size_t ETW::SidType::GetSize(const IContainer&, const void* pvData, size_t cbRemaining) const
{
    // � ����������� �� ���� ������
    size_t cb = 0; switch (InputType())
    {
    // ��� ������� ��������� TOKEN_USER
    case TDH_INTYPE_WBEMSID: cb = 2 * _pointerSize;

        // ��������� ������������� ������
        if (cbRemaining < cb) ETW::ThrowBadData();

        // � ����������� �� ������� ���������
        if (_pointerSize == 4)
        {
            // ��������� �������� ��������� �� TOKEN_USER
            ULONG ptr; memcpy(&ptr, pvData, sizeof(ptr)); 

            // ��������� ������� ���������
            if (ptr == 0) return cb; 
        }
        else {
            // ��������� �������� ��������� �� TOKEN_USER
            ULONGLONG ptr; memcpy(&ptr, pvData, sizeof(ptr)); 

            // ��������� ������� ���������
            if (ptr == 0) return cb; 
        }
        // ���������� ��������� TOKEN_USER
        pvData = (CONST BYTE*)pvData + cb; cbRemaining -= cb; 

    case TDH_INTYPE_SID: 
    {
        // ��������� ������������� ������
        if (cbRemaining < sizeof(SID)) ETW::ThrowBadData();

        // ��������� ��������� SID
        SID sid; memcpy(&sid, pvData, sizeof(sid)); 

        // ���������� ����� ������ SID
        cb += SECURITY_SID_SIZE(sid.SubAuthorityCount); break; 
    }}
    // ��������� ������������� ������
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb; 
}

VARIANT ETW::SidType::GetValue(const void* pvData, size_t cbData) const
{
    // ��� ������� ��������� TOKEN_USER
    if (InputType() == TDH_INTYPE_WBEMSID) { size_t cb = 2 * _pointerSize;

        // ���������� ��������� TOKEN_USER
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; 
    }
    // ������� ������� �������
    return BinaryType::GetValue(pvData, cbData); 
}

void ETW::SidType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // ���������� ������ SID
    LONG cbSID; HRESULT hr = ::SafeArrayGetUBound(V_ARRAY(&value), 0, &cbSID); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); PSID pSID = nullptr; 

    // ��������� ������� SID
    if (cbSID == 0) { stream << L"<NULL>"; return; }

    // �������� ������ � ������
    hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pSID); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); PWSTR szStringSID = nullptr; 
    try {
        // �������� ��������� ������������� SID
        if (!::ConvertSidToStringSidW(pSID, &szStringSID))
        {
            // ��� ������ ��������� ����������
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // ������� ��������� ������������� SID
        stream << szStringSID; ::LocalFree(szStringSID); 

        // ���������� �� ������� � ������
        ::SafeArrayUnaccessData(V_ARRAY(&value));
    }        
    // ���������� �� ������� � ������
    catch (...) { ::SafeArrayUnaccessData(V_ARRAY(&value)); throw; }
}

void ETW::IPv4Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // �������� ����� IPv4
    PIN_ADDR pIPv4 = (PIN_ADDR)&V_UI4(&value); WCHAR szIPv4[16]; 

    // ������� ��������� ������������� ������
    ::RtlIpv4AddressToStringW(pIPv4, szIPv4); stream << szIPv4; 
}

void ETW::IPv6Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // �������� ������ ��� ���������� �������������
    WCHAR szIPv6[46]; PIN6_ADDR pIPv6 = nullptr;

    // �������� ������ � ������
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pIPv6); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); 

    // ������� ��������� ������������� ������
    ::RtlIpv6AddressToStringW(pIPv6, szIPv6); stream << szIPv6;

    // ���������� �� ������� � ������
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

void ETW::SocketAddressType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // �������� ������ ��� ���������� �������������
    WCHAR szIP[46]; PSOCKADDR pAddress = nullptr;

    // �������� ������ � ������
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pAddress); 

    // ��������� ���������� ������
    if (FAILED(hr)) Exception::Throw(hr); switch (pAddress->sa_family) 
    {
    case AF_INET: 
    {
        // ��������� �������������� ����
        PSOCKADDR_IN pAddressIPv4 = (PSOCKADDR_IN)pAddress; 

        // �������� ��������� ������������� ������
        ::RtlIpv4AddressToStringW(&pAddressIPv4->sin_addr, szIP); 
            
        // ������� ��������� ������������� ������
        stream << szIP << L":" << std::dec << pAddressIPv4->sin_port; break; 
    }
    case AF_INET6: 
    {
        // ��������� �������������� ����
        PSOCKADDR_IN6 pAddressIPv6 = (PSOCKADDR_IN6)pAddress; 

        // �������� ��������� ������������� ������
        ::RtlIpv6AddressToStringW(&pAddressIPv6->sin6_addr, szIP); 
            
        // ������� ��������� ������������� ������
        stream << L"[" << szIP << L"]:" << std::dec << pAddressIPv6->sin6_port; break; 
    }}
    // ���������� �� ������� � ������
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

///////////////////////////////////////////////////////////////////////////////
// COM-�������� ���������
///////////////////////////////////////////////////////////////////////////////
ETW::RecordInfo::RecordInfo(const IStructType& structType) : _structType(structType), _cb(0), _cRef(0) 
{
    // ��� ���� �����
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // �������� �������� ���� � ��������� ��� ��������
        const IField& field = _structType.GetField(i); _offsets[field.Name()] = _cb;
        
        // �������� ��� ����
        const IElementType& fieldType = field.Type(); 

        // �������� COM-��� ����
        VARTYPE varFieldType = fieldType.VariantType();

        // ��� ������� ���������� ����� COM-�������
        if ((varFieldType & VT_ARRAY) != 0) _cb += sizeof(SAFEARRAY*); 

        // ��� ���������
        else if (varFieldType == VT_RECORD)
        {
            // ��������� �������������� ����
            const IStructType& fieldStructType = (const IStructType&)fieldType; 

            // �������� �������� ���������
            IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

            // ���������� ������ ���������
            ULONG cb; HRESULT hr = pRecordInfo->GetSize(&cb); 

            // ��������� ���������� ������
            if (FAILED(hr)) Exception::Throw(hr, pRecordInfo, pRecordInfo.GetIID()); _cb += cb; 
        }
        else switch (varFieldType)
        {
        case VT_BOOL    : _cb += sizeof(VARIANT_BOOL   ); break; 
        case VT_I1      : _cb += sizeof(CHAR           ); break; 
        case VT_UI1     : _cb += sizeof(BYTE           ); break; 
        case VT_I2      : _cb += sizeof(SHORT          ); break; 
        case VT_UI2     : _cb += sizeof(USHORT         ); break; 
        case VT_INT     : _cb += sizeof(INT            ); break; 
        case VT_UINT    : _cb += sizeof(UINT           ); break; 
        case VT_I4      : _cb += sizeof(LONG           ); break; 
        case VT_UI4     : _cb += sizeof(ULONG          ); break; 
        case VT_I8      : _cb += sizeof(LONGLONG       ); break; 
        case VT_UI8     : _cb += sizeof(ULONGLONG      ); break; 
        case VT_R4      : _cb += sizeof(FLOAT          ); break; 
        case VT_R8      : _cb += sizeof(DOUBLE         ); break; 
        case VT_DECIMAL : _cb += sizeof(DECIMAL        ); break; 
        case VT_DATE    : _cb += sizeof(DATE           ); break; 
        case VT_CY      : _cb += sizeof(CY             ); break; 
        case VT_ERROR   : _cb += sizeof(SCODE          ); break; 
        case VT_UNKNOWN : _cb += sizeof(LPUNKNOWN      ); break; 
        case VT_DISPATCH: _cb += sizeof(LPDISPATCH     ); break; 
        case VT_VARIANT : _cb += sizeof(VARIANT        ); break; 
        }
    }
}

STDMETHODIMP ETW::RecordInfo::QueryInterface(REFIID riid, void** ppv)
{
    // ��������� ������������ ����������
	if (!ppv) return E_POINTER; *ppv = nullptr; 

	// ��������� ������������� ����������
	if (InlineIsEqualGUID(riid, __uuidof(IRecordInfo))) 
	{
		// ������� ��������� 
		*ppv = static_cast<IRecordInfo*>(this); 
	}
	// ��������� ������������� ����������
	else if (InlineIsEqualGUID(riid, __uuidof(IUnknown))) 
	{
		// ������� ��������� 
		*ppv = static_cast<IRecordInfo*>(this); 
	}
    // ��������� �� ��������������
	else return E_NOINTERFACE; 

    // ��������� ������� ������
	((IUnknown*)(*ppv))->AddRef(); return S_OK;
}

STDMETHODIMP_(BOOL) ETW::RecordInfo::IsMatchingType(IRecordInfo* pRecordInfo)
{
    // ��������� ���������� ���������
    if (pRecordInfo == this) return TRUE; GUID id;

    // �������� GUID ���� ���������
    if (FAILED(pRecordInfo->GetGuid(&id))) return FALSE;  

    // �������� GUID ���� ���������
    return InlineIsEqualGUID(_structType.Guid(), id); 
}

STDMETHODIMP ETW::RecordInfo::RecordCreateCopy(PVOID pvSource, PVOID* ppvDest)
{
    // ��������� ������� ���������
    if (!ppvDest) return E_POINTER; *ppvDest = nullptr; 

    // �������� ������ ��� ���������
    PVOID pvNew = RecordCreate(); if (!pvNew) return E_OUTOFMEMORY; 

    // ���������������� ���������
    HRESULT hr = RecordInit(pvNew); if (FAILED(hr)) 
    { 
        // ���������� ���������� ������
        RecordDestroy(pvNew); return hr; 
    }
    // ����������� ���������
    hr = RecordCopy(pvSource, pvNew); if (FAILED(hr)) 
    {
        // ���������� ���������� ������
        RecordDestroy(pvNew); return hr; 
    }
    // ������� ������������� ���������
    *ppvDest = pvNew; return hr; 
}

STDMETHODIMP ETW::RecordInfo::RecordClear(PVOID pvExisting)
{
    // ��� ���� �����
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // �������� ��� ����
        const IElementType& fieldType = _structType.GetField(i).Type(); 

        // �������� COM-��� ����
        VARTYPE varFieldType = fieldType.VariantType(); ULONG cb = 0; 

        // ��� �������
        if ((varFieldType & VT_ARRAY) != 0) { cb = sizeof(SAFEARRAY*); 
        
            // �������� ����� COM-�������
            SAFEARRAY* pSafeArray; memcpy(&pSafeArray, pvExisting, cb); 

            // ���������� ������� COM-�������
            HRESULT hr = ::SafeArrayDestroy(pSafeArray); if (FAILED(hr)) return hr;
        }
        // ��� ���������
        else if (varFieldType == VT_RECORD)
        {
            // ��������� �������������� ����
            const IStructType& fieldStructType = (const IStructType&)fieldType; 
            try { 
                // �������� �������� ���������
                IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

                // ���������� ������ ���������
                HRESULT hr = pRecordInfo->GetSize(&cb); if (FAILED(hr)) return hr;

                // ���������� ���������� �������
                hr = pRecordInfo->RecordClear(pvExisting); if (FAILED(hr)) return hr;
            }
            // ���������� ������ ��������� ������
            catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
        }
        else switch (varFieldType)
        {
        case VT_BOOL    : cb = sizeof(VARIANT_BOOL  ); break; 
        case VT_I1      : cb = sizeof(CHAR          ); break; 
        case VT_UI1     : cb = sizeof(BYTE          ); break; 
        case VT_I2      : cb = sizeof(SHORT         ); break; 
        case VT_UI2     : cb = sizeof(USHORT        ); break; 
        case VT_INT     : cb = sizeof(INT           ); break; 
        case VT_UINT    : cb = sizeof(UINT          ); break; 
        case VT_I4      : cb = sizeof(LONG          ); break; 
        case VT_UI4     : cb = sizeof(ULONG         ); break; 
        case VT_I8      : cb = sizeof(LONGLONG      ); break; 
        case VT_UI8     : cb = sizeof(ULONGLONG     ); break; 
        case VT_R4      : cb = sizeof(FLOAT         ); break; 
        case VT_R8      : cb = sizeof(DOUBLE        ); break; 
        case VT_DECIMAL : cb = sizeof(DECIMAL       ); break; 
        case VT_DATE    : cb = sizeof(DATE          ); break; 
        case VT_CY      : cb = sizeof(CY            ); break; 
        case VT_ERROR   : cb = sizeof(SCODE         ); break; 
        case VT_BSTR:   { cb = sizeof(BSTR); 

            // ���������� ������� ������
            BSTR bstr; memcpy(&bstr, pvExisting, cb); ::SysFreeString(bstr); break; 
        }
        case VT_UNKNOWN: { cb = sizeof(IUnknown*); 
        
            // ���������� ������� COM-�������
            IUnknown* pUnk; memcpy(&pUnk, pvExisting, cb); pUnk->Release(); break; 
        }
        case VT_DISPATCH: { cb = sizeof(IDispatch*); 

            // ���������� ������� COM-�������
            IDispatch* pDisp; memcpy(&pDisp, pvExisting, cb); pDisp->Release(); break; 
        }
        case VT_VARIANT: { cb = sizeof(VARIANT); 

            // ���������� ������� ����������� COM-����
            VARIANT var; memcpy(&var, pvExisting, cb); ::VariantClear(&var); break; 
        }}
        // ������� �� ��������� ������
        memset(pvExisting, 0, cb); pvExisting = (PBYTE)pvExisting + cb; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::RecordCopy(PVOID pvExisting, PVOID pvNew)
{
    // ��� ���� �����
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // �������� ��� ����
        const IElementType& fieldType = _structType.GetField(i).Type(); 

        // �������� COM-��� ����
        VARTYPE varFieldType = fieldType.VariantType(); ULONG cb = 0; 

        // ��� �������
        if ((varFieldType & VT_ARRAY) != 0) 
        { 
            // ���������������� ����������
            SAFEARRAY* pSafeArray; cb = sizeof(SAFEARRAY*); 
        
            // �������� ����� COM-�������
            SAFEARRAY* pSafeArrayFrom; memcpy(&pSafeArrayFrom, pvExisting, cb); 
            SAFEARRAY* pSafeArrayTo  ; memcpy(&pSafeArrayTo  , pvNew     , cb); 
            
            // ����������� COM-������            
            HRESULT hr = ::SafeArrayCopy(pSafeArrayFrom, &pSafeArray); if (FAILED(hr)) return hr; 

            // ���������� ������� ��������� �������
            if (FAILED(hr)) return hr; hr = ::SafeArrayDestroy(pSafeArrayTo); 

            // ��������� ���������� ������
            if (FAILED(hr)) { ::SafeArrayDestroy(pSafeArray); return hr; } 
            
            // ����������� ����� �������
            memcpy(pvNew, &pSafeArray, cb); 
        }
        // ��� ���������
        else if (varFieldType == VT_RECORD)
        {
            // ��������� �������������� ����
            const IStructType& fieldStructType = (const IStructType&)fieldType; 
            try { 
                // �������� �������� ���������
                IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

                // ���������� ������ ���������
                HRESULT hr = pRecordInfo->GetSize(&cb); if (FAILED(hr)) return hr;

                // ����������� ���������
                hr = pRecordInfo->RecordCopy(pvExisting, pvNew); if (FAILED(hr)) return hr;
            }
            // ���������� ������ ��������� ������
            catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
        }
        else switch (varFieldType)
        {
        case VT_BOOL    : cb = sizeof(VARIANT_BOOL  ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_I1      : cb = sizeof(CHAR          ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_UI1     : cb = sizeof(BYTE          ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_I2      : cb = sizeof(SHORT         ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_UI2     : cb = sizeof(USHORT        ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_INT     : cb = sizeof(INT           ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_UINT    : cb = sizeof(UINT          ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_I4      : cb = sizeof(LONG          ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_UI4     : cb = sizeof(ULONG         ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_I8      : cb = sizeof(LONGLONG      ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_UI8     : cb = sizeof(ULONGLONG     ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_R4      : cb = sizeof(FLOAT         ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_R8      : cb = sizeof(DOUBLE        ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_DECIMAL : cb = sizeof(DECIMAL       ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_DATE    : cb = sizeof(DATE          ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_CY      : cb = sizeof(CY            ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_ERROR   : cb = sizeof(SCODE         ); memcpy(pvNew, pvExisting, cb); break; 
        case VT_BSTR:   { cb = sizeof(BSTR); 

            // �������� ��������� ������
            BSTR bstrFrom; memcpy(&bstrFrom, pvExisting, cb); 
            BSTR bstrTo  ; memcpy(&bstrTo  , pvNew     , cb); 
            
            // ����������� ������
            BSTR bstr = ::SysAllocString(bstrFrom); 

            // ��������� ���������� ������
            if (!bstr && bstrFrom) return E_OUTOFMEMORY; 
            
            // ���������� ������� �������� ������
            ::SysFreeString(bstrTo); memcpy(pvNew, &bstr, cb); break; 
        }
        case VT_UNKNOWN: { cb = sizeof(IUnknown*); 
        
            // �������� ����� COM-�������
            IUnknown* pUnknownFrom; memcpy(&pUnknownFrom, pvExisting, cb); 
            IUnknown* pUnknownTo  ; memcpy(&pUnknownTo  , pvNew     , cb); 

            // ��������� ������� ������ �������
            if (pUnknownFrom) pUnknownFrom->AddRef(); 

            // ��������� ������� ������ �������
            if (pUnknownTo) pUnknownTo->Release(); 

            // ����������� ����� �������
            memcpy(pvNew, &pUnknownFrom, cb); break;
        }
        case VT_DISPATCH: { cb = sizeof(IDispatch*); 

            // �������� ����� COM-�������
            IUnknown* pUnknownFrom; memcpy(&pUnknownFrom, pvExisting, cb); 
            IUnknown* pUnknownTo  ; memcpy(&pUnknownTo  , pvNew     , cb); 

            // ��������� ������� ������ �������
            if (pUnknownFrom) pUnknownFrom->AddRef(); 

            // ��������� ������� ������ �������
            if (pUnknownTo) pUnknownTo->Release(); 

            // ����������� ����� �������
            memcpy(pvNew, &pUnknownFrom, cb); break;
        }
        case VT_VARIANT: { cb = sizeof(VARIANT); _variant_t var; 

            // �������� �������� COM-����
            VARIANT varFrom; memcpy(&varFrom, pvExisting, cb); 
            VARIANT varTo  ; memcpy(&varTo  , pvNew     , cb); 

            // ����������� ��������
            HRESULT hr = ::VariantCopy(&varFrom, &var); if (FAILED(hr)) return hr; 

            // ���������� ������� ��������� ��������
            hr = ::VariantClear(&varTo); if (FAILED(hr)) return hr; 

            // ����������� ����� ��������
            var.Detach(); memcpy(pvNew, &var, cb); break; 
        }}
        // ������� �� ��������� ������
        pvExisting = (PBYTE)pvExisting + cb; pvNew = (PBYTE)pvNew + cb; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::GetFieldNames(ULONG* pcNames, BSTR* rgBstrNames)
{
    // ��������� ������� ���������
    if (!pcNames) return E_POINTER; ULONG count = (ULONG)_structType.FieldCount(); 

    // ������� ����� �����
    if (!rgBstrNames) { *pcNames = count; return S_OK; }

    // ��������������� ����� ������������ ����
    if (*pcNames > count) { *pcNames = count; } 

    // ��� ���� ���� �����
    for (ULONG i = 0; i < *pcNames; i++)
    {
        // ����������� ��� ����
        rgBstrNames[i] = ::SysAllocString(_structType.GetField(i).Name()); 

        // ��������� ���������� ������
        if (rgBstrNames[i]) continue; 

        // ��� ���� ������������� �����
        for (ULONG j = 0; j < i; j++)
        {
            // ���������� ���������� ������
            ::SysFreeString(rgBstrNames[j]); rgBstrNames[j] = nullptr; 
        }
        return E_OUTOFMEMORY; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::GetFieldNoCopy(PVOID pvData, 
    LPCOLESTR szFieldName, VARIANT* pvarField, PVOID* ppvDataCArray)
{
    // �������� �������� ����
    if (!pvarField) return E_POINTER; size_t offset = FindFieldOffset(szFieldName);

    // ������� �� ������ ����
    if (offset == SIZE_MAX) return E_INVALIDARG; pvData = (PBYTE)pvData + offset; 

    // ����������� ����� ���� 
    if (ppvDataCArray) *ppvDataCArray = pvData; 

    // �������� ��� ����
    const IElementType& fieldType = *FindFieldType(szFieldName); 

    // �������� COM-��� ����
    VARTYPE varFieldType = fieldType.VariantType(); 

    // ������� ��� ������
    V_VT(pvarField) = varFieldType | VT_BYREF; 

    // ��� ������� ������� ������ �� ������
    if ((varFieldType & VT_ARRAY) != 0) V_ARRAYREF(pvarField) = (SAFEARRAY**)pvData; 

    // ��� ���������
    else if (varFieldType == VT_RECORD)
    {
        // ��������� �������������� ����
        const IStructType& fieldStructType = (const IStructType&)fieldType; 
        try { 
            // ������� ��������� �������� ���������
            V_RECORDINFO(pvarField) = new RecordInfo(fieldStructType); 

            // ������� ����� ���������
            V_RECORDINFO(pvarField)->AddRef(); V_RECORD(pvarField) = pvData; 
        }
        // ���������� ������ ��������� ������
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } 
    }
    else switch (varFieldType)
    {
    // ������� ����� ��������
    case VT_BOOL    : V_BOOLREF     (pvarField) = (VARIANT_BOOL*)pvData; break; 
    case VT_I1      : V_I1REF       (pvarField) = (CHAR        *)pvData; break; 
    case VT_UI1     : V_UI1REF      (pvarField) = (BYTE        *)pvData; break; 
    case VT_I2      : V_I2REF       (pvarField) = (SHORT       *)pvData; break; 
    case VT_UI2     : V_UI2REF      (pvarField) = (USHORT      *)pvData; break;
    case VT_INT     : V_INTREF      (pvarField) = (INT         *)pvData; break; 
    case VT_UINT    : V_UINTREF     (pvarField) = (UINT        *)pvData; break; 
    case VT_I4      : V_I4REF       (pvarField) = (LONG        *)pvData; break; 
    case VT_UI4     : V_UI4REF      (pvarField) = (ULONG       *)pvData; break; 
    case VT_I8      : V_I8REF       (pvarField) = (LONGLONG    *)pvData; break; 
    case VT_UI8     : V_UI8REF      (pvarField) = (ULONGLONG   *)pvData; break; 
    case VT_R4      : V_R4REF       (pvarField) = (FLOAT       *)pvData; break; 
    case VT_R8      : V_R8REF       (pvarField) = (DOUBLE      *)pvData; break; 
    case VT_DECIMAL : V_DECIMALREF  (pvarField) = (DECIMAL     *)pvData; break;
    case VT_DATE    : V_DATEREF     (pvarField) = (DATE        *)pvData; break; 
    case VT_CY      : V_CYREF       (pvarField) = (CY          *)pvData; break; 
    case VT_ERROR   : V_ERRORREF    (pvarField) = (SCODE       *)pvData; break; 
    case VT_BSTR    : V_BSTRREF     (pvarField) = (BSTR        *)pvData; break; 
    case VT_UNKNOWN : V_UNKNOWNREF  (pvarField) = (IUnknown*   *)pvData; break; 
    case VT_DISPATCH: V_DISPATCHREF (pvarField) = (IDispatch*  *)pvData; break; 
    case VT_VARIANT : V_VARIANTREF  (pvarField) = (VARIANT     *)pvData; break; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::PutFieldNoCopy(ULONG, 
    PVOID pvData, LPCOLESTR szFieldName, VARIANT* pvarField)
{
    // �������� �������� ����
    if (!pvarField) return E_POINTER; size_t offset = FindFieldOffset(szFieldName); 

    // ������� �� ������ ����
    if (offset == SIZE_MAX) return E_INVALIDARG; pvData = (PBYTE)pvData + offset; 

    // �������� ��� ����
    const IElementType& fieldType = *FindFieldType(szFieldName); 

    // �������� COM-��� ����
    VARTYPE varFieldType = fieldType.VariantType(); 

    // ��������� ���������� ����
    if (V_VT(pvarField) != varFieldType) return E_INVALIDARG; 

    // ��� �������
    if ((varFieldType & VT_ARRAY) != 0) 
    { 
        // ����������� ����� �������
        memcpy(pvData, &V_ARRAY(pvarField), sizeof(SAFEARRAY*));  
    }
    // ��� ���������
    else if (varFieldType == VT_RECORD)
    {
        // ��������� �������������� ����
        const IStructType& fieldStructType = (const IStructType&)fieldType; 
        try { 
            // �������� �������� ���������
            IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

            // ��������� ���������� ���������
            if (!pRecordInfo->IsMatchingType(V_RECORDINFO(pvarField))) return E_INVALIDARG;
            
            // ����������� ���������� ���������
            HRESULT hr = pRecordInfo->RecordCopy(V_RECORDINFO(pvarField), pvData); 

            // ���������� ���������� �������
            if (FAILED(hr)) return hr; ::VariantClear(pvarField);
        }
        // ���������� ������ ��������� ������
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    }
    else switch (varFieldType)
    {
    // ���������� ��������
    case VT_BOOL    : memcpy(pvData, &V_BOOL    (pvarField), sizeof(VARIANT_BOOL)); break; 
    case VT_I1      : memcpy(pvData, &V_I1      (pvarField), sizeof(CHAR        )); break; 
    case VT_UI1     : memcpy(pvData, &V_UI1     (pvarField), sizeof(BYTE        )); break; 
    case VT_I2      : memcpy(pvData, &V_I2      (pvarField), sizeof(SHORT       )); break; 
    case VT_UI2     : memcpy(pvData, &V_UI2     (pvarField), sizeof(USHORT      )); break; 
    case VT_INT     : memcpy(pvData, &V_INT     (pvarField), sizeof(INT         )); break; 
    case VT_UINT    : memcpy(pvData, &V_UINT    (pvarField), sizeof(UINT        )); break; 
    case VT_I4      : memcpy(pvData, &V_I4      (pvarField), sizeof(LONG        )); break; 
    case VT_UI4     : memcpy(pvData, &V_UI4     (pvarField), sizeof(ULONG       )); break; 
    case VT_I8      : memcpy(pvData, &V_I8      (pvarField), sizeof(LONGLONG    )); break; 
    case VT_UI8     : memcpy(pvData, &V_UI8     (pvarField), sizeof(ULONGLONG   )); break; 
    case VT_R4      : memcpy(pvData, &V_R4      (pvarField), sizeof(FLOAT       )); break; 
    case VT_R8      : memcpy(pvData, &V_R8      (pvarField), sizeof(DOUBLE      )); break; 
    case VT_DECIMAL : memcpy(pvData, &V_DECIMAL (pvarField), sizeof(DECIMAL     )); break; 
    case VT_DATE    : memcpy(pvData, &V_DATE    (pvarField), sizeof(DATE        )); break; 
    case VT_CY      : memcpy(pvData, &V_CY      (pvarField), sizeof(CY          )); break; 
    case VT_ERROR   : memcpy(pvData, &V_ERROR   (pvarField), sizeof(SCODE       )); break; 
    case VT_BSTR    : memcpy(pvData, &V_BSTR    (pvarField), sizeof(BSTR        )); break; 
    case VT_UNKNOWN : memcpy(pvData, &V_UNKNOWN (pvarField), sizeof(IUnknown*   )); break; 
    case VT_DISPATCH: memcpy(pvData, &V_DISPATCH(pvarField), sizeof(IDispatch*  )); break; 
    case VT_VARIANT : memcpy(pvData,             pvarField , sizeof(VARIANT     )); break; 
    }
    return S_OK; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������� ������
///////////////////////////////////////////////////////////////////////////////
static ETW::IElement* EtwCreateElement(
    const ETW::IContainer& parent, const std::wstring& path, 
    const ETW::IElementType& type, const void* pvData, size_t cbData) 
{
    switch (type.LogicalType())
    {
    case ETW::TYPE_ARRAY: 
    { 
        // ��������� �������������� ����
        const ETW::IArrayType& arrayType = (const ETW::IArrayType&)type; 

        // ������� �������� �������
        return new ETW::Array(parent, path, arrayType, pvData, cbData); 
    }
    case ETW::TYPE_STRUCT: 
    {
        // ��������� �������������� ����
        const ETW::IStructType& structType = (const ETW::IStructType&)type; 

        // ������� �������� ���������
        return new ETW::Struct(path, structType, pvData, cbData); 
    }
    default: 
    {
        // ��������� �������������� ����
        const ETW::IBasicType& basicType = (const ETW::IBasicType&)type; 

        // ������� �������� �������� ��������
        return new ETW::BasicElement(parent, path, basicType, pvData, cbData); 
    }}
}
///////////////////////////////////////////////////////////////////////////////
// ���������� c COM-��������������
///////////////////////////////////////////////////////////////////////////////
static BOOL IsVariantLayout(const ETW::IElementType& type)
{
    switch (type.LogicalType())
    {
    case ETW::TYPE_ARRAY:  return FALSE; 
    case ETW::TYPE_STRUCT: 
    {
        // ��������� �������������� ����
        const ETW::IStructType& structType = (const ETW::IStructType&)type; 

        // ��� ���� ���� �����
        for (size_t i = 0, count = structType.FieldCount(); i < count; i++)
        {
            // �������� ��� ����
            const ETW::IElementType& fieldType = structType.GetField(i).Type(); 

            // ��������� ���������� c COM-��������������
            if (!IsVariantLayout(fieldType)) return FALSE; 
        }
        return TRUE; 
    }
    default: {
        // ��������� �������������� ����
        const ETW::BasicType& basicType = (const ETW::BasicType&)type; 

        // ��������� ���������� c COM-��������������
        return basicType.IsVariantLayout(); 
    }}
}
 
///////////////////////////////////////////////////////////////////////////////
// ������
///////////////////////////////////////////////////////////////////////////////
ETW::Array::Array(const IContainer& parent, const std::wstring& path, 
    const ETW::IArrayType& type, const void* pvData, size_t cbData)

    // ��������� ���������� ���������
    : _path(path), _type(type), _items(type.GetCount(parent)), _pvData(pvData), _cbData(0)
{
    // �������� ��� �������� �������
    const ETW::IElementType& elementType = type.ElementType(); 

    // ��� ���� ��������� �������
    for (size_t i = 0; i < _items.size(); i++)
    {
        // ������� ���� � ��������� ��������
        std::wostringstream childPath(path); childPath << L'[' << std::dec << i << L']'; 

        // ��������� �������� ���������� ��������
        _items[i].reset(EtwCreateElement(*this, childPath.str(), elementType, pvData, cbData));

        // ���������� ������ ��������
        size_t cb = _items[i]->GetDataSize(); _cbData += cb; 

        // ������� �� ��������� ������
        pvData = (const BYTE*)pvData + cb; cbData -= cb; 
    }
    // ������� ��������� �������
    HRESULT hr = ::SafeArrayAllocDescriptorEx(elementType.VariantType(), 1, &_pSafeArray); 

    // ������� ������������� ��������� ������� �������
    if (FAILED(hr)) Exception::Throw(hr); _pSafeArray->fFeatures |= FADF_FIXEDSIZE;

    // ������� ����� ��������� � �������
    _pSafeArray->rgsabound->cElements = (ULONG)_items.size(); _pSafeArray->rgsabound->lLbound = 0; 
    try {
        // ��� ��������� ��������
        if (elementType.VariantType() == VT_RECORD)
        {
            // ��������� �������������� ����
            const ETW::IStructType& elementStructType = (const ETW::IStructType&)elementType; 

            // �������� COM-�������� ���������
            IRecordInfoPtr pRecordInfo(new RecordInfo(elementStructType)); 

            // ���������� COM-�������� ���������
            hr = ::SafeArraySetRecordInfo(_pSafeArray, pRecordInfo); 

            // ��������� ���������� ������
            if (FAILED(hr)) Exception::Throw(hr); 
        }
        // ��� ���������� ��������� ������
        if (IsVariantLayout(elementType)) { _pSafeArray->pvData = (PVOID)pvData; 
        
            // ������� ����� ����������� ���������
            _pSafeArray->fFeatures |= FADF_EMBEDDED; 
        }
        else {
            // �������� ������
            hr = ::SafeArrayAllocData(_pSafeArray); if (FAILED(hr)) Exception::Throw(hr);
        
            // ��� ���� ��������� �������
            for (LONG i = 0; (ULONG)i < _pSafeArray->rgsabound->cElements; i++)
            {
                // �������� �������� ��������
                VARIANT vtValue = _items[i]->GetValue(); 

                // �������� �������� �������� � ������
                hr = ::SafeArrayPutElement(_pSafeArray, &i, &vtValue); 

                // ��������� ���������� ������
                ::VariantClear(&vtValue); if (FAILED(hr)) Exception::Throw(hr); 
            }
        }
    }
    // ���������� ���������� �������
    catch (...) { ::SafeArrayDestroy(_pSafeArray); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ���������
///////////////////////////////////////////////////////////////////////////////
ETW::Struct::Struct(const std::wstring& path, 
    const ETW::IStructType& type, const void* pvData, size_t cbData)

    // ��������� ���������� ���������
    : _path(path), _type(type), _pvData(pvData), _cbData(0) 
{
    // ��� ���� ����� ���������
    for (size_t i = 0, count = type.FieldCount(); i < count; i++)
    {
        // �������� �������� � ��� ����
        const IField& field = type.GetField(i); std::wstring name = field.Name();
        
        // ������� ���� � ��������� ��������
        std::wostringstream childPath(path); childPath << L'.' << name; 

        // ��������� �������� ����
        std::shared_ptr<IElement> pChild(EtwCreateElement(
            *this, childPath.str(), field.Type(), pvData, cbData
        ));
        // ��������� ��� � �������� ����
        _names.push_back(name); _items[name] = pChild;

        // ���������� ������ ��������
        size_t cb = pChild->GetDataSize(); _cbData += cb; 

        // ������� �� ��������� ������
        pvData = (const BYTE*)pvData + cb; cbData -= cb; 
    }
    // ��������� ������������� ��������������
    if (IsVariantLayout(type)) { _pvRecord = (PVOID)_pvData; return; } 

    // �������� �������� ���������
    IRecordInfoPtr pRecordInfo(new RecordInfo(type)); 

    // �������� ������ ���������� �������
    _pvRecord = pRecordInfo->RecordCreate(); if (!_pvRecord) Exception::Throw(E_OUTOFMEMORY);
    try { 
        // ��������� ������������� ���������
        HRESULT hr = pRecordInfo->RecordInit(_pvRecord); 

        // ��� ������ ��������� ����������
        if (FAILED(hr)) Exception::Throw(hr, pRecordInfo, pRecordInfo.GetIID()); 

        // ��� ���� ����� ���������
        for (size_t i = 0; i < _items.size(); i++)
        {
            // �������� ��� � �������� ����
            std::wstring name = type.GetField(i).Name(); 
        
            // �������� �������� ����
            VARIANT vtValue = _items[name]->GetValue(); 

            // ���������� �������� ����
            hr = pRecordInfo->PutField(INVOKE_PROPERTYPUTREF, _pvRecord, name.c_str(), &vtValue);

            // ��� ������������� �������
            ::VariantClear(&vtValue); if (FAILED(hr)) 
            { 
                // ��������� ����������
                Exception::Throw(hr, pRecordInfo, pRecordInfo.GetIID()); 
            }
        }
    }
    // ���������� ���������� �������
    catch (...) { pRecordInfo->RecordDestroy(_pvRecord); throw; }
}

VARIANT ETW::Struct::GetValue() const
{
    // ������� ��� ����������
    VARIANT varValue; ::VariantInit(&varValue); 
    
    // ������� ����� ������ ���������
    V_VT(&varValue) = VT_RECORD; V_RECORD(&varValue) = _pvRecord;
        
    // ������� ����� ���������� ��������
    V_RECORDINFO(&varValue) = new RecordInfo(_type); 

    // ��������� ������� ������
    V_RECORDINFO(&varValue)->AddRef(); return varValue; 
}

const ETW::IElement* ETW::Struct::FindPath(PCWSTR szPath) const 
{
    // ����� ���������� ����� � ������
    if (!szPath || *szPath == 0) return this; PCWSTR szNext = szPath + wcscspn(szPath, L"[."); 

    // ������� ��� ����
    std::wstring strName(szPath, szNext - szPath); 
    
    // ����� ������� �� �����
    const IElement* pElement = FindName(strName.c_str()); 

    // ��������� ������� ��������
    if (!pElement || *szNext == 0) return pElement; 

    // ��� �������� �������
    for (PCWSTR szEnd = szNext; *szNext == L'['; szEnd = szNext)
    {
        // ��������� ������� �������
        if (pElement->Type().LogicalType() != TYPE_ARRAY) return nullptr; 

        // ��������� �������������� ����
        const IContainer* pArray = (const IContainer*)pElement; 

        // ��� ���� �������� �������
        for (szEnd++, szNext++; *szEnd && *szEnd != L']'; szEnd++)
        {
            // ��������� ������� �����
            if (!isdigit(*szEnd)) return nullptr; 
        }
        // ��������� ������� ����������� ������
        if (*szEnd != L']') return nullptr;

        // ������� ����� ������ � ��������
        std::wistringstream stream(std::wstring(szNext, szEnd - szNext)); 

        // ������������� ������
        size_t index; stream >> std::dec >> index; szNext = szEnd + 1; 

        // ��������� ������������ �������
        if (index >= pArray->Count()) return nullptr; 

        // ������� �� ������� ������� � ��������� ���������� ������
        pElement = &pArray[index]; if (*szNext == 0) return pElement; 
    }
    // ��� �������� �����
    if (szNext[0] == L'.' && szNext[1] != 0) 
    {    
        // ��������� ������� ���������
        if (pElement->Type().LogicalType() != TYPE_STRUCT) return nullptr; 

        // ����� �������� ������� �� ����
        return ((const IStruct*)pElement)->FindPath(szNext + 1); 
    }
    return nullptr; 
}

