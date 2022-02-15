#include <ws2tcpip.h>
#include "TraceETW.hpp"
#include <sddl.h>
#include <ip2string.h>
#include <comdef.h>
#include <comutil.h>

///////////////////////////////////////////////////////////////////////////////
// Определения интерфейсов
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(ISupportErrorInfo, __uuidof(ISupportErrorInfo));
_COM_SMARTPTR_TYPEDEF(IErrorInfo       , __uuidof(IErrorInfo       ));
_COM_SMARTPTR_TYPEDEF(IRecordInfo      , __uuidof(IRecordInfo      ));
_COM_SMARTPTR_TYPEDEF(ISWbemDateTime   , __uuidof(ISWbemDateTime   ));

///////////////////////////////////////////////////////////////////////////////
// Преобразования кодировок
///////////////////////////////////////////////////////////////////////////////
inline std::string WideCharToMultiByte(UINT codePage, PCWSTR sz, size_t cch, bool exception)
{
    // определить размер строки
    if (cch == size_t(-1)) cch = wcslen(sz); if (cch == 0) return std::string(); 

    // определить требуемый размер буфера
    int cb = ::WideCharToMultiByte(codePage, 0, sz, (int)cch, nullptr, 0, nullptr, nullptr); 
    
    // при возникновении ошибки
    if (!cb) { if (!exception) return std::string();
    
        // выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // выделить буфер требуемого размера
    std::string str(cb, 0); 

    // выполнить преобразование кодировки
    cb = ::WideCharToMultiByte(codePage, 0, sz, (int)cch, &str[0], cb, nullptr, nullptr); 

    // при возникновении ошибки
    if (!cb) { if (!exception) return std::string();
    
        // выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // вернуть преобразованную строку
    str.resize(cb); return str; 
}

inline std::wstring MultiByteToWideChar(UINT codePage, PCSTR sz, size_t cb, bool exception)
{
    // определить размер строки
    if (cb == size_t(-1)) cb = strlen(sz); if (cb == 0) return std::wstring(); 

    // определить требуемый размер буфера
    int cch = ::MultiByteToWideChar(codePage, 0, sz, (int)cb, nullptr, 0); 
    
    // при возникновении ошибки
    if (!cch) { if (!exception) return std::wstring();
    
        // выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // выделить буфер требуемого размера
    std::wstring str(cch, 0); 

    // выполнить преобразование кодировки
    cch = ::MultiByteToWideChar(codePage, 0, sz, (int)cb, &str[0], cch); 

    // при возникновении ошибки
    if (!cch) { if (!exception) return std::wstring();
    
        // выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // вернуть преобразованную строку
    str.resize(cch); return str; 
}
 
///////////////////////////////////////////////////////////////////////////////
// Исключение
///////////////////////////////////////////////////////////////////////////////
void ETW::Exception::Throw(HRESULT status, IUnknown* pObj, REFIID riid)
{
    // инициализировать переменные
	ISupportErrorInfoPtr pSupport; BOOL support = FALSE; 

	// запросить поддержку интерфейса
	if (SUCCEEDED(pObj->QueryInterface(&pSupport)))
	{
		// запросить поддержку ошибок
		support = (pSupport->InterfaceSupportsErrorInfo(riid) == S_OK); 
	}
	// получить описание ошибки
    IErrorInfoPtr pErrorInfo; 
    if (support && SUCCEEDED(::GetErrorInfo(0, &pErrorInfo)))
    {
        // создать объект исключения
        Exception error(status, pErrorInfo); 

        // восстановить ошибку и выбросить исключение
        ::SetErrorInfo(0, pErrorInfo); throw error;
    }
    // выбросить исключение
    else throw Exception(status); 
}

ETW::Exception::Exception(HRESULT status, IErrorInfo* pErrorInfo) : std::runtime_error(""), _status(status)
{
    // указать используемую ANSI-кодировку
	UINT codePage = CP_ACP; BSTR bstrError = nullptr;

    // получить сообщение об ошибке
	if (pErrorInfo && SUCCEEDED(pErrorInfo->GetDescription(&bstrError)))
	{
        // определить размер строки
        size_t cch = ::SysStringLen(bstrError); 

        // выполнить преобразование кодировки
        _strMessage = WideCharToMultiByte(codePage, bstrError, cch, false); 

        // освободить выделенные ресурсы
        ::SysFreeString(bstrError); if (!_strMessage.empty()) return; 
    }
	// получить локализацию текущего потока
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); PSTR szMessage = nullptr; 

    // указать режим получения описания ошибки
	DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM; 

	// получить локализованное сообщение
	if (!::FormatMessageA(dwFlags, nullptr, status, langID, (PSTR)&szMessage, 0, nullptr)) 
    {
	    // получить локализованное сообщение
	    if (!::FormatMessageA(dwFlags, nullptr, status, 0, (PSTR)&szMessage, 0, nullptr)) return; 
    }
    // сохранить полученное сообщение
    _strMessage = szMessage; ::LocalFree(szMessage); 
}

///////////////////////////////////////////////////////////////////////////////
// Описание значений или битов
///////////////////////////////////////////////////////////////////////////////
BSTR ETW::IValueMap::ToString(ULONGLONG value) const
{
    std::wstring strValue; 

    // для перечисления значений
    if (Type() == ValueMapType::Index)
    {
        // для всех описаний
        for (size_t i = 0, count = Count(); i < count; i++)
        {
            // получить описание значения
            const IValueInfo& info = Item(i); 

            // при совпадении значения
            if (value == info.Value())
            {
                // указать имя значения
                strValue = info.Name(); break; 
            }
        }
    }
    else {
        // для всех описаний
        for (size_t i = 0, count = Count(); value != 0 && i < count; i++)
        {
            // получить описание значения
            const IValueInfo& info = Item(i); 

            // при наличии бита в значении
            if ((value & info.Value()) != 0)
            {
                // указать разделитель
                if (!strValue.empty()) strValue += L' '; 

                // указать имя флага
                strValue += info.Name(); value &= ~info.Value(); 
            }
        }
    }
    // выделить память для строки
    BSTR bstrValue = ::SysAllocString(strValue.c_str()); 

    // проверить отсутствие ошибок
    if (!bstrValue) Exception::Throw(E_OUTOFMEMORY); return bstrValue; 
}

///////////////////////////////////////////////////////////////////////////////
// Простой тип
///////////////////////////////////////////////////////////////////////////////
BSTR ETW::BasicType::ToString(const ETW::IContainer&, const void* pvData, size_t cbData) const
{
    // получить значение
    VARIANT value = GetValue(pvData, cbData); 
    try {
        // отформатировать значение
        std::wostringstream stream; Format(value, stream); 

        // выделить память для строки
        BSTR bstr = ::SysAllocString(stream.str().c_str()); 

        // проверить отсутствие ошибок
        if (!bstr) Exception::Throw(E_OUTOFMEMORY); 

        // освободить выделенные ресурсы
        ::VariantClear(&value); return bstr; 
    }
    // освободить выделенные ресурсы
    catch (...) { ::VariantClear(&value); throw; }
}
 
///////////////////////////////////////////////////////////////////////////////
// Булевский тип
///////////////////////////////////////////////////////////////////////////////
size_t ETW::BooleanType::GetSize(const ETW::IContainer&, const void*, size_t cbRemaining) const
{
    // в зависимости от способа кодирования
    size_t cb = SIZE_MAX; switch (InputType())
    {
    // указать размер данных
    case TDH_INTYPE_BOOLEAN: cb = sizeof(BOOL); break; 
    case TDH_INTYPE_UINT8  : cb = sizeof(BYTE); break; 
    }
    // проверить достаточность буфера
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb;  
}

VARIANT ETW::BooleanType::GetValue(const void* pvData, size_t cbData) const
{
    // инициализировать переменную
    VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 

    switch (InputType())
    {
    // указать размер данных
    case TDH_INTYPE_BOOLEAN: 
    {
        // извлечь значение из буфера
        BOOL boolValue; memcpy(&boolValue, pvData, cbData); 

        // указать значение
        V_BOOL(&var) = (boolValue) ? VARIANT_TRUE : VARIANT_FALSE; break;
    }
    case TDH_INTYPE_UINT8:
    {
        // извлечь значение из буфера
        BYTE boolValue; memcpy(&boolValue, pvData, cbData); 

        // указать значение
        V_BOOL(&var) = (boolValue) ? VARIANT_TRUE : VARIANT_FALSE; break; 
    }}
    return var; 
}

BSTR ETW::BooleanType::ToString(const ETW::IContainer&, const void* pvData, size_t cbData) const
{
    // получить значение
    VARIANT value = GetValue(pvData, cbData); BSTR bstr = nullptr; 
    try {
        // получить описание значений или битов
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // получить строковое представление значения
            bstr = pValueMap->ToString(V_BOOL(&value) ? 1 : 0); 
        }
        else {
            // выделить память для строки
            bstr = ::SysAllocString(V_BOOL(&value) ? L"true" : L"false"); 

            // проверить отсутствие ошибок
            if (!bstr) Exception::Throw(E_OUTOFMEMORY); 
        }
        // освободить выделенные ресурсы
        ::VariantClear(&value); return bstr; 
    }
    // освободить выделенные ресурсы
    catch (...) { ::VariantClear(&value); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Тип чисел
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
// Тип указателя или числа разрядности указателя
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
// Тип строк
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
    // в зависимости от формата строки
    size_t cbChar = GetCharSize(InputType()); switch (InputType())
    {
    // строка завершает буфер события
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:       
    case TDH_INTYPE_NONNULLTERMINATEDSTRING:    
        
        // проверить отсутствие неполных символов
        if ((cbRemaining & (cbChar - 1)) != 0) ETW::ThrowBadData();
        
        return cbRemaining; 

    // при наличии размера строки в буфере
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:   
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
    case TDH_INTYPE_COUNTEDANSISTRING: 
    case TDH_INTYPE_COUNTEDSTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING: 
    {        
        // проверить достаточность буфера
        if (cbRemaining < sizeof(USHORT)) ETW::ThrowBadData();

        // прочитать размер строки в байтах
        USHORT cb = 0; memcpy(&cb, pvData, sizeof(cb)); 

        // для размера в формате big-endian 
        if (InputType() == TDH_INTYPE_REVERSEDCOUNTEDANSISTRING || 
            InputType() == TDH_INTYPE_REVERSEDCOUNTEDSTRING) 
        {
            // изменить порядок следования байтов
            cb = MAKEWORD(HIWORD(cb), LOWORD(cb));
        }
        // проверить отсутствие неполных символов
        if ((cb & (cbChar - 1)) != 0) ETW::ThrowBadData();

        // проверить достаточность буфера
        if (cbRemaining < sizeof(cb) + cb) ETW::ThrowBadData();

        // вернуть размер в байтах
        return sizeof(cb) + cb; 
    }}
    // определить размер строки в символах
    size_t cchMax = GetLength(&parent); if (cchMax != SIZE_MAX)
    {
        // вычислить размер строки в байтах
        size_t cbMax = cchMax * cbChar; 

        // проверить корректность максимального размера
        if (cbRemaining < cbMax) ETW::ThrowBadData(); return cbMax; 
    }
    // при выравнивании данных
    if (((ULONG_PTR)pvData & (cbChar - 1)) == 0)
    {
        // определить число символов
        size_t cchRemaining = cbRemaining / cbChar; 

        // в зависимости от формата строки
        size_t cch = 0; switch (InputType())
        {
        // найти завершение строки
        case TDH_INTYPE_ANSISTRING:     cch = strnlen((PCSTR )pvData, cchRemaining); break; 
        case TDH_INTYPE_UNICODESTRING:  cch = wcsnlen((PCWSTR)pvData, cchRemaining); break; 
        }
        // проверить отсутствие неполных символов
        if (cch == cchRemaining && (cbRemaining & (cbChar - 1)) != 0) ETW::ThrowBadData();

        // учесть завершающий символ
        if (cch < cchRemaining) cch++; return cch * cbChar;  
    }
    // при невыравненных данных
    else { WCHAR ch = WCHAR_MAX; size_t cb = 0; 

        // для всех символов строки
        for (; ch != 0 && cb + cbChar <= cbRemaining; )
        {
            // скопировать символ
            memcpy(&ch, pvData, cbChar); cb += cbChar; 

            // перейти на следующий символ
            pvData = (CONST BYTE*)pvData + cbChar; 
        }
        // проверить отсутствие неполных символов
        if (ch != 0 && cb + cbChar > cbRemaining) ETW::ThrowBadData();

        return cb; 
    }
}

VARIANT ETW::StringType::GetValue(const void* pvData, size_t cbData) const
{
    // определить размер символа
    size_t cbChar = GetCharSize(InputType()); size_t cch = cbData / cbChar; 

    // для невыравненных данных
    if (cbData != 0 && ((ULONG_PTR)pvData & (cbChar - 1)) != 0)
    {
        // скопировать данные в выравненный буфер
        std::wstring buffer(cch, 0); memcpy(&buffer[0], pvData, cbData);

        // извлечь строку из выравненного буфера
        return GetValue(&buffer[0], cbData); 
    }
    switch (InputType())
    {
    // при наличии размера строки в буфере
    case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:            
    case TDH_INTYPE_MANIFEST_COUNTEDSTRING:             
    case TDH_INTYPE_COUNTEDANSISTRING: 
    case TDH_INTYPE_COUNTEDSTRING: 
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING:

        // пропустить размер строки
        pvData = (CONST BYTE*)pvData + sizeof(USHORT); 
        
        // пропустить размер строки
        cbData -= sizeof(USHORT); cch -= sizeof(USHORT) / cbChar; break; 

    case TDH_INTYPE_ANSISTRING: 

        // при возможном завершении нулем
        if (cch > 0 && GetLength(nullptr) == SIZE_MAX)
        {
            // не учитывать завершающий нуль
            if (((PCSTR)pvData)[cch - 1] == 0) { cbData -= cbChar; cch--; }
        }
        break; 

    case TDH_INTYPE_UNICODESTRING: 

        // при возможном завершении нулем
        if (cch > 0 && GetLength(nullptr) == SIZE_MAX)
        {
            // не учитывать завершающий нуль
            if (((PCWSTR)pvData)[cch - 1] == 0) { cbData -= cbChar; cch--; }
        }
        break; 
    }
    // инициализировать результат
    VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = VariantType(); 
    
    // обработать отсутствие строки
    if (cch == 0) V_BSTR(&varValue) = ::SysAllocString(L""); 

    // для Unicode-строки
    else if (cbChar == sizeof(WCHAR))
    {
        // вернуть строку Unicode
        V_BSTR(&varValue) = ::SysAllocStringLen((PCWSTR)pvData, (UINT)cch); 
    }
    else { 
        // указать используемую кодировку
        UINT codePage = (OutputType() == TDH_OUTTYPE_UTF8 || OutputType() == TDH_OUTTYPE_JSON) ? CP_UTF8 : CP_ACP; 

        // выполнить преобразование кодировки
        std::wstring str = MultiByteToWideChar(codePage, (PCSTR)pvData, cbData, true); 

        // вернуть строку Unicode
        V_BSTR(&varValue) = ::SysAllocString(str.c_str()); 
    }
    // проверить отсутствие ошибок
    if (!V_BSTR(&varValue)) ETW::Exception::Throw(E_OUTOFMEMORY); return varValue; 
}

BSTR ETW::StringType::ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const
{
    // проверить необходимость форматирования
    if (OutputType() == TDH_OUTTYPE_STRING) 
    {
        // получить значение
        VARIANT varValue = GetValue(pvData, cbData); 
        try {
            // создать строку
            BSTR bstr = ::SysAllocString(V_BSTR(&varValue)); 

            // проверить отсутствие ошибок
            if (!bstr) Exception::Throw(E_OUTOFMEMORY); 

            // освободить выделенные ресурсы
            ::VariantClear(&varValue); return bstr; 
        }
        // освободить выделенные ресурсы
        catch (...) { ::VariantClear(&varValue); throw; }
    }
    // вызвать базовую функцию
    return BasicType::ToString(parent, pvData, cbData); 
} 

void ETW::StringType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // пропустить начальные пробелы
    PCWSTR str = V_BSTR(&value) + wcsspn(V_BSTR(&value), L" "); 

    // найти заменяемый символ
    if (!*str) return; size_t index = wcscspn(str, L"\t\r\n"); 

    // при наличии заменяемых символов
    while (str[index] != 0)
    {
	    // записать часть строки
        stream << std::wstring(str, index) << L" "; str += index + 1;

        // проверить наличие непробельных символов
        if (str[wcsspn(str, L" ")] == 0) return; 

        // найти заменяемый символ
        index = wcscspn(str, L"\t\r\n"); 
    }
    // записать часть строки
    stream << std::wstring(str, index);
}

///////////////////////////////////////////////////////////////////////////////
// Тип времени
///////////////////////////////////////////////////////////////////////////////
ETW::DateTimeType::DateTimeType()
{
    // создать объект преобразования
    HRESULT hr = ::CoCreateInstance(CLSID_SWbemDateTime, 
        nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&_pConvert)
    );
    // проверить отсутствие ошибок
    if (FAILED(hr)) _pConvert = nullptr; 
}

size_t ETW::DateTimeType::GetSize(const ETW::IContainer&, const void*, size_t cbRemaining) const 
{
    // в зависимости олт формата времени
    size_t cb = SIZE_MAX; switch (InputType())
    {
    // указать размер входных данных
    case TDH_INTYPE_UINT32      : cb = sizeof(UINT32    ); break; 
    case TDH_INTYPE_FILETIME    : cb = sizeof(FILETIME  ); break; 
    case TDH_INTYPE_SYSTEMTIME  : cb = sizeof(SYSTEMTIME); break; 
    }
    // проверить достаточность буфера
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb;
}

VARIANT ETW::DateTimeType::GetValue(const void* pvData, size_t cbData) const
{
    // инициализировать результат
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
        // прочитать время
        SYSTEMTIME systemTime; FILETIME fileTime; memcpy(&fileTime, pvData, cbData); 

        // выполнить преобразование времени
        if (!::FileTimeToSystemTime(&fileTime, &systemTime))
        {
            // при ошибке выбросить исключение
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // при указании UTC-времени
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) { SYSTEMTIME systemTimeLocal;

            // преобразовать UTC-время в локальное
            if (!::SystemTimeToTzSpecificLocalTime(nullptr, &systemTime, &systemTimeLocal))
            {
                // при ошибке выбросить исключение
                Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            systemTime = systemTimeLocal; 
        }
        // выполнить преобразование времени
        if (!::SystemTimeToVariantTime(&systemTime, &V_DATE(&varValue)))
        {
            // при ошибке выбросить исключение
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        break; 
    }
    case TDH_INTYPE_SYSTEMTIME: 
    { 
        // прочитать время
        SYSTEMTIME systemTime; memcpy(&systemTime, pvData, cbData);

        // при указании UTC-времени
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) { SYSTEMTIME systemTimeLocal;

            // преобразовать UTC-время в локальное
            if (!::SystemTimeToTzSpecificLocalTime(nullptr, &systemTime, &systemTimeLocal))
            {
                // при ошибке выбросить исключение
                Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            systemTime = systemTimeLocal; 
        }
        // выполнить преобразование времени
        if (!::SystemTimeToVariantTime(&systemTime, &V_DATE(&varValue)))
        {
            // при ошибке выбросить исключение
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        break; 
    }}
    return varValue; 
}

void ETW::DateTimeType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // указать используемую локализацию
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

        // выполнить преобразование времени
        if (!::VariantTimeToSystemTime(V_DATE(&value), &systemTime))
        {
            // при ошибке выбросить исключение
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // определить требуемый размер буфера
        int cchDate = ::GetDateFormatW(lcid, 0, &systemTime, nullptr, nullptr, 0); 

        // проверить отсутствие ошибок
        if (!cchDate) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // определить требуемый размер буфера
        int cchTime = ::GetTimeFormatW(lcid, 0, &systemTime, nullptr, nullptr, 0); 

        // проверить отсутствие ошибок
        if (!cchTime) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // выделить буфер требуемого размера
        std::wstring strDate(cchDate, 0); std::wstring strTime(cchTime, 0);

        // отформатировать дату
        cchDate = ::GetDateFormatW(lcid, 0, &systemTime, nullptr, &strDate[0], cchDate); 

        // проверить отсутствие ошибок
        if (!cchDate) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // отформатировать время
        cchTime = ::GetTimeFormatW(lcid, 0, &systemTime, nullptr, &strDate[0], cchTime); 

        // проверить отсутствие ошибок
        if (!cchTime) Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 

        // указать действительный размер
        strDate.resize(cchDate - 1); strTime.resize(cchTime - 1);

        // вывести дату и время
        stream << strDate << L' ' << strTime; break; 
    }
    case TDH_OUTTYPE_CIMDATETIME: 
    { 
        // проверить наличие поддержки
        if (!_pConvert) ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED);

        // указать признак локального времени
        VARIANT_BOOL local = VARIANT_TRUE; BSTR bstr; 

        // указать признак UTC-времени
        if (OutputType() == TDH_OUTTYPE_DATETIME_UTC) local = VARIANT_FALSE; 

        // указать значение времени
        HRESULT hr = _pConvert->SetVarDate(V_DATE(&value), local);

        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

        // получить значение преобразованной строки
        hr = _pConvert->get_Value(&bstr);
        
        // проверить отсутствие ошибок
        if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

        // вывести преобразуемую строку
        stream << bstr; break;  
    }}
}

VARIANT ETW::DateTimeType::DecodeString(BSTR bstrString) const
{
    // проверить наличие поддержки
    if (!_pConvert) ETW::Exception::Throw(WBEM_E_NOT_SUPPORTED); 

    // указать признак локального времени
    VARIANT_BOOL local = (OutputType() != TDH_OUTTYPE_DATETIME_UTC) ? VARIANT_TRUE : VARIANT_FALSE; 

    // инициализировать результат
    VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = VariantType(); 

    // указать значение преобразовываемой строки
    HRESULT hr = _pConvert->put_Value(bstrString);

    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

    // преобразовать формат времени
    hr = _pConvert->GetVarDate(local, &V_DATE(&varValue)); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) ETW::Exception::Throw(hr, _pConvert, __uuidof(ISWbemDateTime)); 

    return varValue; 
}

///////////////////////////////////////////////////////////////////////////////
// Бинарный тип данных
///////////////////////////////////////////////////////////////////////////////
size_t ETW::BinaryType::GetSize(const IContainer& parent, const void* pvData, size_t cbRemaining) const
{
    // в зависимости от типа данных
    size_t cb = SIZE_MAX; switch (InputType())
    {
    case TDH_INTYPE_MANIFEST_COUNTEDBINARY: 
    {
        // проверить достаточность буфера
        if (cbRemaining < sizeof(USHORT)) ETW::ThrowBadData();

        // прочитать размер данных
        USHORT cbValue; memcpy(&cbValue, pvData, sizeof(cbValue)); 
        
        // указать общий используемый размер
        cb = cbValue + sizeof(cbValue); break; 
    }
    case TDH_INTYPE_HEXDUMP: 
    {
        // проверить достаточность буфера
        if (cbRemaining < sizeof(ULONG)) ETW::ThrowBadData();

        // прочитать размер данных
        ULONG cbValue; memcpy(&cbValue, pvData, sizeof(cbValue)); 
        
        // указать общий используемый размер
        cb = cbValue + sizeof(cbValue); break; 
    }
    // определить размер буфера
    case TDH_INTYPE_BINARY: cb = GetSize(parent); break; 
    }
    // проверить достаточность буфера
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb; 
}

VARIANT ETW::BinaryType::GetValue(const void* pvData, size_t cbData) const
{
    switch (InputType())
    {
    case TDH_INTYPE_MANIFEST_COUNTEDBINARY: { size_t cb = sizeof(USHORT); 

        // пропустить размер буфера
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; break; 
    }
    case TDH_INTYPE_HEXDUMP: { size_t cb = sizeof(ULONG); 

        // пропустить размер буфера
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; break; 
    }}
    // создать COM-массив
    SAFEARRAY* pSafeArray = ::SafeArrayCreateVector(VT_UI1, 0, (ULONG)cbData); 

    // проверить отсутствие ошибок
    if (!pSafeArray) Exception::Throw(E_OUTOFMEMORY); PVOID pvContent;  
    try { 
        // получить адрес элементов
        HRESULT hr = ::SafeArrayAccessData(pSafeArray, &pvContent); 

        // проверить отсутствие ошибок
        if (FAILED(hr)) Exception::Throw(hr); 
            
        // скопировать элементы
        memcpy(pvContent, pvData, cbData); ::SafeArrayUnaccessData(pSafeArray);
    }
    // освободить выделенные ресурсы
    catch (...) { ::SafeArrayDestroy(pSafeArray); throw; }

    // указать использование COM-массива
    VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
    // вернуть COM-массив
    V_ARRAY(&var) = pSafeArray; return var;  
}

void ETW::BinaryType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // определить размер SID
    LONG cb; HRESULT hr = ::SafeArrayGetUBound(V_ARRAY(&value), 0, &cb); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); PBYTE pbBuffer = nullptr; 

    // получить доступ к данным
    hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pbBuffer); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); 
    
    // вывести шестнадцатеричное представление байтов
    for (LONG i = 0; i < cb; i++) stream << std::hex << pbBuffer[i]; 

    // отказаться от доступа к данным
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

///////////////////////////////////////////////////////////////////////////////
// Специальные типы данных
///////////////////////////////////////////////////////////////////////////////
void ETW::GuidType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // выделить память для строкового представления GUID
    WCHAR szGUID[39]; GUID* pGuid = nullptr; 

    // получить доступ к данным
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pGuid); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); 
    
    // получить и вывести строковое представление GUID
    if (::StringFromGUID2(*pGuid, szGUID, _countof(szGUID))) stream << szGUID;

    // отказаться от доступа к данным
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

size_t ETW::SidType::GetSize(const IContainer&, const void* pvData, size_t cbRemaining) const
{
    // в зависимости от типа данных
    size_t cb = 0; switch (InputType())
    {
    // при наличии заголовка TOKEN_USER
    case TDH_INTYPE_WBEMSID: cb = 2 * _pointerSize;

        // проверить достаточность буфера
        if (cbRemaining < cb) ETW::ThrowBadData();

        // в зависимости от размера указателя
        if (_pointerSize == 4)
        {
            // прочитать значение указателя из TOKEN_USER
            ULONG ptr; memcpy(&ptr, pvData, sizeof(ptr)); 

            // проверить наличие указателя
            if (ptr == 0) return cb; 
        }
        else {
            // прочитать значение указателя из TOKEN_USER
            ULONGLONG ptr; memcpy(&ptr, pvData, sizeof(ptr)); 

            // проверить наличие указателя
            if (ptr == 0) return cb; 
        }
        // пропустить заголовок TOKEN_USER
        pvData = (CONST BYTE*)pvData + cb; cbRemaining -= cb; 

    case TDH_INTYPE_SID: 
    {
        // проверить достаточность буфера
        if (cbRemaining < sizeof(SID)) ETW::ThrowBadData();

        // прочитать заголовок SID
        SID sid; memcpy(&sid, pvData, sizeof(sid)); 

        // определить общий размер SID
        cb += SECURITY_SID_SIZE(sid.SubAuthorityCount); break; 
    }}
    // проверить достаточность буфера
    if (cbRemaining < cb) ETW::ThrowBadData(); return cb; 
}

VARIANT ETW::SidType::GetValue(const void* pvData, size_t cbData) const
{
    // при наличии заголовка TOKEN_USER
    if (InputType() == TDH_INTYPE_WBEMSID) { size_t cb = 2 * _pointerSize;

        // пропустить структуру TOKEN_USER
        pvData = (CONST BYTE*) pvData + cb; cbData -= cb; 
    }
    // вызвать базовую функцию
    return BinaryType::GetValue(pvData, cbData); 
}

void ETW::SidType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // определить размер SID
    LONG cbSID; HRESULT hr = ::SafeArrayGetUBound(V_ARRAY(&value), 0, &cbSID); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); PSID pSID = nullptr; 

    // проверить наличие SID
    if (cbSID == 0) { stream << L"<NULL>"; return; }

    // получить доступ к данным
    hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pSID); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); PWSTR szStringSID = nullptr; 
    try {
        // получить строковое представление SID
        if (!::ConvertSidToStringSidW(pSID, &szStringSID))
        {
            // при ошибке выбросить исключение
            Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
        }
        // вывести строковое представление SID
        stream << szStringSID; ::LocalFree(szStringSID); 

        // отказаться от доступа к данным
        ::SafeArrayUnaccessData(V_ARRAY(&value));
    }        
    // отказаться от доступа к данным
    catch (...) { ::SafeArrayUnaccessData(V_ARRAY(&value)); throw; }
}

void ETW::IPv4Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // получить адрес IPv4
    PIN_ADDR pIPv4 = (PIN_ADDR)&V_UI4(&value); WCHAR szIPv4[16]; 

    // вывести строковое представление адреса
    ::RtlIpv4AddressToStringW(pIPv4, szIPv4); stream << szIPv4; 
}

void ETW::IPv6Type::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // выделить память для строкового представления
    WCHAR szIPv6[46]; PIN6_ADDR pIPv6 = nullptr;

    // получить доступ к данным
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pIPv6); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); 

    // вывести строковое представление адреса
    ::RtlIpv6AddressToStringW(pIPv6, szIPv6); stream << szIPv6;

    // отказаться от доступа к данным
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

void ETW::SocketAddressType::Format(const VARIANT& value, std::wostringstream& stream) const
{
    // выделить память для строкового представления
    WCHAR szIP[46]; PSOCKADDR pAddress = nullptr;

    // получить доступ к данным
    HRESULT hr = ::SafeArrayAccessData(V_ARRAY(&value), (void**)&pAddress); 

    // проверить отсутствие ошибок
    if (FAILED(hr)) Exception::Throw(hr); switch (pAddress->sa_family) 
    {
    case AF_INET: 
    {
        // выполнить преобразование типа
        PSOCKADDR_IN pAddressIPv4 = (PSOCKADDR_IN)pAddress; 

        // получить строковое представление адреса
        ::RtlIpv4AddressToStringW(&pAddressIPv4->sin_addr, szIP); 
            
        // вывести строковое представление адреса
        stream << szIP << L":" << std::dec << pAddressIPv4->sin_port; break; 
    }
    case AF_INET6: 
    {
        // выполнить преобразование типа
        PSOCKADDR_IN6 pAddressIPv6 = (PSOCKADDR_IN6)pAddress; 

        // получить строковое представление адреса
        ::RtlIpv6AddressToStringW(&pAddressIPv6->sin6_addr, szIP); 
            
        // вывести строковое представление адреса
        stream << L"[" << szIP << L"]:" << std::dec << pAddressIPv6->sin6_port; break; 
    }}
    // отказаться от доступа к данным
    ::SafeArrayUnaccessData(V_ARRAY(&value));
}

///////////////////////////////////////////////////////////////////////////////
// COM-описание структуры
///////////////////////////////////////////////////////////////////////////////
ETW::RecordInfo::RecordInfo(const IStructType& structType) : _structType(structType), _cb(0), _cRef(0) 
{
    // для всех полей
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // получить описание поля и сохранить его смещение
        const IField& field = _structType.GetField(i); _offsets[field.Name()] = _cb;
        
        // получить тип поля
        const IElementType& fieldType = field.Type(); 

        // получить COM-тип поля
        VARTYPE varFieldType = fieldType.VariantType();

        // для массива пропустить адрес COM-массива
        if ((varFieldType & VT_ARRAY) != 0) _cb += sizeof(SAFEARRAY*); 

        // для структуры
        else if (varFieldType == VT_RECORD)
        {
            // выполнить преобразование типа
            const IStructType& fieldStructType = (const IStructType&)fieldType; 

            // получить описание структуры
            IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

            // определить размер структуры
            ULONG cb; HRESULT hr = pRecordInfo->GetSize(&cb); 

            // проверить отсутствие ошибок
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
    // проверить корректность параметров
	if (!ppv) return E_POINTER; *ppv = nullptr; 

	// проверить идентификатор интерфейса
	if (InlineIsEqualGUID(riid, __uuidof(IRecordInfo))) 
	{
		// указать интерфейс 
		*ppv = static_cast<IRecordInfo*>(this); 
	}
	// проверить идентификатор интерфейса
	else if (InlineIsEqualGUID(riid, __uuidof(IUnknown))) 
	{
		// указать интерфейс 
		*ppv = static_cast<IRecordInfo*>(this); 
	}
    // интерфейс не поддерживается
	else return E_NOINTERFACE; 

    // увеличить счетчик ссылок
	((IUnknown*)(*ppv))->AddRef(); return S_OK;
}

STDMETHODIMP_(BOOL) ETW::RecordInfo::IsMatchingType(IRecordInfo* pRecordInfo)
{
    // проверить совпадение указателя
    if (pRecordInfo == this) return TRUE; GUID id;

    // получить GUID типа структуры
    if (FAILED(pRecordInfo->GetGuid(&id))) return FALSE;  

    // сравнить GUID типа структуры
    return InlineIsEqualGUID(_structType.Guid(), id); 
}

STDMETHODIMP ETW::RecordInfo::RecordCreateCopy(PVOID pvSource, PVOID* ppvDest)
{
    // проверить наличие указателя
    if (!ppvDest) return E_POINTER; *ppvDest = nullptr; 

    // выделить память для структуры
    PVOID pvNew = RecordCreate(); if (!pvNew) return E_OUTOFMEMORY; 

    // инициализировать структуру
    HRESULT hr = RecordInit(pvNew); if (FAILED(hr)) 
    { 
        // освободить выделенную память
        RecordDestroy(pvNew); return hr; 
    }
    // скопировать структуру
    hr = RecordCopy(pvSource, pvNew); if (FAILED(hr)) 
    {
        // освободить выделенную память
        RecordDestroy(pvNew); return hr; 
    }
    // вернуть скопированную структуру
    *ppvDest = pvNew; return hr; 
}

STDMETHODIMP ETW::RecordInfo::RecordClear(PVOID pvExisting)
{
    // для всех полей
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // получить тип поля
        const IElementType& fieldType = _structType.GetField(i).Type(); 

        // получить COM-тип поля
        VARTYPE varFieldType = fieldType.VariantType(); ULONG cb = 0; 

        // для массива
        if ((varFieldType & VT_ARRAY) != 0) { cb = sizeof(SAFEARRAY*); 
        
            // получить адрес COM-массива
            SAFEARRAY* pSafeArray; memcpy(&pSafeArray, pvExisting, cb); 

            // освободить ресурсы COM-массива
            HRESULT hr = ::SafeArrayDestroy(pSafeArray); if (FAILED(hr)) return hr;
        }
        // для структуры
        else if (varFieldType == VT_RECORD)
        {
            // выполнить преобразование типа
            const IStructType& fieldStructType = (const IStructType&)fieldType; 
            try { 
                // получить описание структуры
                IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

                // определить размер структуры
                HRESULT hr = pRecordInfo->GetSize(&cb); if (FAILED(hr)) return hr;

                // освободить выделенные ресурсы
                hr = pRecordInfo->RecordClear(pvExisting); if (FAILED(hr)) return hr;
            }
            // обработать ошибку выделения памяти
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

            // освободить ресурсы строки
            BSTR bstr; memcpy(&bstr, pvExisting, cb); ::SysFreeString(bstr); break; 
        }
        case VT_UNKNOWN: { cb = sizeof(IUnknown*); 
        
            // освободить ресурсы COM-объекта
            IUnknown* pUnk; memcpy(&pUnk, pvExisting, cb); pUnk->Release(); break; 
        }
        case VT_DISPATCH: { cb = sizeof(IDispatch*); 

            // освободить ресурсы COM-объекта
            IDispatch* pDisp; memcpy(&pDisp, pvExisting, cb); pDisp->Release(); break; 
        }
        case VT_VARIANT: { cb = sizeof(VARIANT); 

            // освободить ресурсы переменного COM-типа
            VARIANT var; memcpy(&var, pvExisting, cb); ::VariantClear(&var); break; 
        }}
        // перейти на следующие данные
        memset(pvExisting, 0, cb); pvExisting = (PBYTE)pvExisting + cb; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::RecordCopy(PVOID pvExisting, PVOID pvNew)
{
    // для всех полей
    for (size_t i = 0, count = _structType.FieldCount(); i < count; i++)
    {
        // получить тип поля
        const IElementType& fieldType = _structType.GetField(i).Type(); 

        // получить COM-тип поля
        VARTYPE varFieldType = fieldType.VariantType(); ULONG cb = 0; 

        // для массива
        if ((varFieldType & VT_ARRAY) != 0) 
        { 
            // инициализировать переменные
            SAFEARRAY* pSafeArray; cb = sizeof(SAFEARRAY*); 
        
            // получить адрес COM-массива
            SAFEARRAY* pSafeArrayFrom; memcpy(&pSafeArrayFrom, pvExisting, cb); 
            SAFEARRAY* pSafeArrayTo  ; memcpy(&pSafeArrayTo  , pvNew     , cb); 
            
            // скопировать COM-массив            
            HRESULT hr = ::SafeArrayCopy(pSafeArrayFrom, &pSafeArray); if (FAILED(hr)) return hr; 

            // освободить ресурсы исходного массива
            if (FAILED(hr)) return hr; hr = ::SafeArrayDestroy(pSafeArrayTo); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) { ::SafeArrayDestroy(pSafeArray); return hr; } 
            
            // скопировать адрес массива
            memcpy(pvNew, &pSafeArray, cb); 
        }
        // для структуры
        else if (varFieldType == VT_RECORD)
        {
            // выполнить преобразование типа
            const IStructType& fieldStructType = (const IStructType&)fieldType; 
            try { 
                // получить описание структуры
                IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

                // определить размер структуры
                HRESULT hr = pRecordInfo->GetSize(&cb); if (FAILED(hr)) return hr;

                // скопировать структуру
                hr = pRecordInfo->RecordCopy(pvExisting, pvNew); if (FAILED(hr)) return hr;
            }
            // обработать ошибку выделения памяти
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

            // получить указатель строки
            BSTR bstrFrom; memcpy(&bstrFrom, pvExisting, cb); 
            BSTR bstrTo  ; memcpy(&bstrTo  , pvNew     , cb); 
            
            // скопировать строку
            BSTR bstr = ::SysAllocString(bstrFrom); 

            // проверить отсутствие ошибок
            if (!bstr && bstrFrom) return E_OUTOFMEMORY; 
            
            // освободить ресурсы исходной строки
            ::SysFreeString(bstrTo); memcpy(pvNew, &bstr, cb); break; 
        }
        case VT_UNKNOWN: { cb = sizeof(IUnknown*); 
        
            // получить адрес COM-объекта
            IUnknown* pUnknownFrom; memcpy(&pUnknownFrom, pvExisting, cb); 
            IUnknown* pUnknownTo  ; memcpy(&pUnknownTo  , pvNew     , cb); 

            // увеличить счетчик ссылок объекта
            if (pUnknownFrom) pUnknownFrom->AddRef(); 

            // уменьшить счетчик ссылок объекта
            if (pUnknownTo) pUnknownTo->Release(); 

            // скопировать адрес объекта
            memcpy(pvNew, &pUnknownFrom, cb); break;
        }
        case VT_DISPATCH: { cb = sizeof(IDispatch*); 

            // получить адрес COM-объекта
            IUnknown* pUnknownFrom; memcpy(&pUnknownFrom, pvExisting, cb); 
            IUnknown* pUnknownTo  ; memcpy(&pUnknownTo  , pvNew     , cb); 

            // увеличить счетчик ссылок объекта
            if (pUnknownFrom) pUnknownFrom->AddRef(); 

            // уменьшить счетчик ссылок объекта
            if (pUnknownTo) pUnknownTo->Release(); 

            // скопировать адрес объекта
            memcpy(pvNew, &pUnknownFrom, cb); break;
        }
        case VT_VARIANT: { cb = sizeof(VARIANT); _variant_t var; 

            // получить значение COM-типа
            VARIANT varFrom; memcpy(&varFrom, pvExisting, cb); 
            VARIANT varTo  ; memcpy(&varTo  , pvNew     , cb); 

            // скопировать значение
            HRESULT hr = ::VariantCopy(&varFrom, &var); if (FAILED(hr)) return hr; 

            // освободить ресурсы исходного значения
            hr = ::VariantClear(&varTo); if (FAILED(hr)) return hr; 

            // скопировать новое значение
            var.Detach(); memcpy(pvNew, &var, cb); break; 
        }}
        // перейти на следующие данные
        pvExisting = (PBYTE)pvExisting + cb; pvNew = (PBYTE)pvNew + cb; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::GetFieldNames(ULONG* pcNames, BSTR* rgBstrNames)
{
    // проверить наличие указателя
    if (!pcNames) return E_POINTER; ULONG count = (ULONG)_structType.FieldCount(); 

    // вернуть число полей
    if (!rgBstrNames) { *pcNames = count; return S_OK; }

    // скорректировать число возвращаемых имен
    if (*pcNames > count) { *pcNames = count; } 

    // для всех имен полей
    for (ULONG i = 0; i < *pcNames; i++)
    {
        // скопировать имя поля
        rgBstrNames[i] = ::SysAllocString(_structType.GetField(i).Name()); 

        // проверить отсутствие ошибок
        if (rgBstrNames[i]) continue; 

        // для всех скопированных строк
        for (ULONG j = 0; j < i; j++)
        {
            // освободить выделенную память
            ::SysFreeString(rgBstrNames[j]); rgBstrNames[j] = nullptr; 
        }
        return E_OUTOFMEMORY; 
    }
    return S_OK; 
}

STDMETHODIMP ETW::RecordInfo::GetFieldNoCopy(PVOID pvData, 
    LPCOLESTR szFieldName, VARIANT* pvarField, PVOID* ppvDataCArray)
{
    // получить смещение поля
    if (!pvarField) return E_POINTER; size_t offset = FindFieldOffset(szFieldName);

    // перейти на данные поля
    if (offset == SIZE_MAX) return E_INVALIDARG; pvData = (PBYTE)pvData + offset; 

    // скопировать адрес поля 
    if (ppvDataCArray) *ppvDataCArray = pvData; 

    // получить тип поля
    const IElementType& fieldType = *FindFieldType(szFieldName); 

    // получить COM-тип поля
    VARTYPE varFieldType = fieldType.VariantType(); 

    // указать тип ссылки
    V_VT(pvarField) = varFieldType | VT_BYREF; 

    // для массива указать ссылку на массив
    if ((varFieldType & VT_ARRAY) != 0) V_ARRAYREF(pvarField) = (SAFEARRAY**)pvData; 

    // для структуры
    else if (varFieldType == VT_RECORD)
    {
        // выполнить преобразование типа
        const IStructType& fieldStructType = (const IStructType&)fieldType; 
        try { 
            // указать интерфейс описания структуры
            V_RECORDINFO(pvarField) = new RecordInfo(fieldStructType); 

            // указать адрес структуры
            V_RECORDINFO(pvarField)->AddRef(); V_RECORD(pvarField) = pvData; 
        }
        // обработать ошибку выделения памяти
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } 
    }
    else switch (varFieldType)
    {
    // указать адрес значения
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
    // получить смещение поля
    if (!pvarField) return E_POINTER; size_t offset = FindFieldOffset(szFieldName); 

    // перейти на данные поля
    if (offset == SIZE_MAX) return E_INVALIDARG; pvData = (PBYTE)pvData + offset; 

    // получить тип поля
    const IElementType& fieldType = *FindFieldType(szFieldName); 

    // получить COM-тип поля
    VARTYPE varFieldType = fieldType.VariantType(); 

    // проверить совпадение типа
    if (V_VT(pvarField) != varFieldType) return E_INVALIDARG; 

    // для массива
    if ((varFieldType & VT_ARRAY) != 0) 
    { 
        // скопировать адрес массива
        memcpy(pvData, &V_ARRAY(pvarField), sizeof(SAFEARRAY*));  
    }
    // для структуры
    else if (varFieldType == VT_RECORD)
    {
        // выполнить преобразование типа
        const IStructType& fieldStructType = (const IStructType&)fieldType; 
        try { 
            // получить описание структуры
            IRecordInfoPtr pRecordInfo(new RecordInfo(fieldStructType)); 

            // проверить совпадение структуры
            if (!pRecordInfo->IsMatchingType(V_RECORDINFO(pvarField))) return E_INVALIDARG;
            
            // скопировать содержимое структуры
            HRESULT hr = pRecordInfo->RecordCopy(V_RECORDINFO(pvarField), pvData); 

            // освободить выделенные ресурсы
            if (FAILED(hr)) return hr; ::VariantClear(pvarField);
        }
        // обработать ошибку выделения памяти
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    }
    else switch (varFieldType)
    {
    // установить значение
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
// Создать элемент данных
///////////////////////////////////////////////////////////////////////////////
static ETW::IElement* EtwCreateElement(
    const ETW::IContainer& parent, const std::wstring& path, 
    const ETW::IElementType& type, const void* pvData, size_t cbData) 
{
    switch (type.LogicalType())
    {
    case ETW::TYPE_ARRAY: 
    { 
        // выполнить преобразование типа
        const ETW::IArrayType& arrayType = (const ETW::IArrayType&)type; 

        // создать описание массива
        return new ETW::Array(parent, path, arrayType, pvData, cbData); 
    }
    case ETW::TYPE_STRUCT: 
    {
        // выполнить преобразование типа
        const ETW::IStructType& structType = (const ETW::IStructType&)type; 

        // создать описание структуры
        return new ETW::Struct(path, structType, pvData, cbData); 
    }
    default: 
    {
        // выполнить преобразование типа
        const ETW::IBasicType& basicType = (const ETW::IBasicType&)type; 

        // создать описание простого элемента
        return new ETW::BasicElement(parent, path, basicType, pvData, cbData); 
    }}
}
///////////////////////////////////////////////////////////////////////////////
// Совпадение c COM-представлением
///////////////////////////////////////////////////////////////////////////////
static BOOL IsVariantLayout(const ETW::IElementType& type)
{
    switch (type.LogicalType())
    {
    case ETW::TYPE_ARRAY:  return FALSE; 
    case ETW::TYPE_STRUCT: 
    {
        // выполнить преобразование типа
        const ETW::IStructType& structType = (const ETW::IStructType&)type; 

        // для всех имен полей
        for (size_t i = 0, count = structType.FieldCount(); i < count; i++)
        {
            // получить тип поля
            const ETW::IElementType& fieldType = structType.GetField(i).Type(); 

            // проверить совпадение c COM-представлением
            if (!IsVariantLayout(fieldType)) return FALSE; 
        }
        return TRUE; 
    }
    default: {
        // выполнить преобразование типа
        const ETW::BasicType& basicType = (const ETW::BasicType&)type; 

        // проверить совпадение c COM-представлением
        return basicType.IsVariantLayout(); 
    }}
}
 
///////////////////////////////////////////////////////////////////////////////
// Массив
///////////////////////////////////////////////////////////////////////////////
ETW::Array::Array(const IContainer& parent, const std::wstring& path, 
    const ETW::IArrayType& type, const void* pvData, size_t cbData)

    // сохранить переданные параметры
    : _path(path), _type(type), _items(type.GetCount(parent)), _pvData(pvData), _cbData(0)
{
    // получить тип элемента массива
    const ETW::IElementType& elementType = type.ElementType(); 

    // для всех элементов массива
    for (size_t i = 0; i < _items.size(); i++)
    {
        // создать путь к дочернуму элементу
        std::wostringstream childPath(path); childPath << L'[' << std::dec << i << L']'; 

        // сохранить описание отдельного элемента
        _items[i].reset(EtwCreateElement(*this, childPath.str(), elementType, pvData, cbData));

        // определить размер элемента
        size_t cb = _items[i]->GetDataSize(); _cbData += cb; 

        // перейти на следующие данные
        pvData = (const BYTE*)pvData + cb; cbData -= cb; 
    }
    // создать заголовок массива
    HRESULT hr = ::SafeArrayAllocDescriptorEx(elementType.VariantType(), 1, &_pSafeArray); 

    // указать невозможность изменения размера массива
    if (FAILED(hr)) Exception::Throw(hr); _pSafeArray->fFeatures |= FADF_FIXEDSIZE;

    // указать число элементов в массиве
    _pSafeArray->rgsabound->cElements = (ULONG)_items.size(); _pSafeArray->rgsabound->lLbound = 0; 
    try {
        // для вложенных структур
        if (elementType.VariantType() == VT_RECORD)
        {
            // выполнить преобразование типа
            const ETW::IStructType& elementStructType = (const ETW::IStructType&)elementType; 

            // получить COM-описание структуры
            IRecordInfoPtr pRecordInfo(new RecordInfo(elementStructType)); 

            // установить COM-описание структуры
            hr = ::SafeArraySetRecordInfo(_pSafeArray, pRecordInfo); 

            // проверить отсутствие ошибок
            if (FAILED(hr)) Exception::Throw(hr); 
        }
        // при совпадении раскладки данных
        if (IsVariantLayout(elementType)) { _pSafeArray->pvData = (PVOID)pvData; 
        
            // указать адрес размещенных элементов
            _pSafeArray->fFeatures |= FADF_EMBEDDED; 
        }
        else {
            // выделить память
            hr = ::SafeArrayAllocData(_pSafeArray); if (FAILED(hr)) Exception::Throw(hr);
        
            // для всех элементов массива
            for (LONG i = 0; (ULONG)i < _pSafeArray->rgsabound->cElements; i++)
            {
                // получить значение элемента
                VARIANT vtValue = _items[i]->GetValue(); 

                // добавить значение элемента в массив
                hr = ::SafeArrayPutElement(_pSafeArray, &i, &vtValue); 

                // проверить отсутствие ошибок
                ::VariantClear(&vtValue); if (FAILED(hr)) Exception::Throw(hr); 
            }
        }
    }
    // освободить выделенные ресурсы
    catch (...) { ::SafeArrayDestroy(_pSafeArray); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Структура
///////////////////////////////////////////////////////////////////////////////
ETW::Struct::Struct(const std::wstring& path, 
    const ETW::IStructType& type, const void* pvData, size_t cbData)

    // сохранить переданные параметры
    : _path(path), _type(type), _pvData(pvData), _cbData(0) 
{
    // для всех полей структуры
    for (size_t i = 0, count = type.FieldCount(); i < count; i++)
    {
        // получить описание и имя поля
        const IField& field = type.GetField(i); std::wstring name = field.Name();
        
        // создать путь к дочернуму элементу
        std::wostringstream childPath(path); childPath << L'.' << name; 

        // сохранить описание поля
        std::shared_ptr<IElement> pChild(EtwCreateElement(
            *this, childPath.str(), field.Type(), pvData, cbData
        ));
        // сохранить имя и описание поля
        _names.push_back(name); _items[name] = pChild;

        // определить размер элемента
        size_t cb = pChild->GetDataSize(); _cbData += cb; 

        // перейти на следующие данные
        pvData = (const BYTE*)pvData + cb; cbData -= cb; 
    }
    // проверить необходимость переразмещения
    if (IsVariantLayout(type)) { _pvRecord = (PVOID)_pvData; return; } 

    // получить описание структуры
    IRecordInfoPtr pRecordInfo(new RecordInfo(type)); 

    // выделить память требуемого размера
    _pvRecord = pRecordInfo->RecordCreate(); if (!_pvRecord) Exception::Throw(E_OUTOFMEMORY);
    try { 
        // выполнить инициализацию структуры
        HRESULT hr = pRecordInfo->RecordInit(_pvRecord); 

        // при ошибке выбросить исключение
        if (FAILED(hr)) Exception::Throw(hr, pRecordInfo, pRecordInfo.GetIID()); 

        // для всех полей структуры
        for (size_t i = 0; i < _items.size(); i++)
        {
            // получить имя и значение поля
            std::wstring name = type.GetField(i).Name(); 
        
            // получить значение поля
            VARIANT vtValue = _items[name]->GetValue(); 

            // установить значение поля
            hr = pRecordInfo->PutField(INVOKE_PROPERTYPUTREF, _pvRecord, name.c_str(), &vtValue);

            // при возникновении оошибки
            ::VariantClear(&vtValue); if (FAILED(hr)) 
            { 
                // выбросить исключение
                Exception::Throw(hr, pRecordInfo, pRecordInfo.GetIID()); 
            }
        }
    }
    // освободить выделенные ресурсы
    catch (...) { pRecordInfo->RecordDestroy(_pvRecord); throw; }
}

VARIANT ETW::Struct::GetValue() const
{
    // указать тип интерфейса
    VARIANT varValue; ::VariantInit(&varValue); 
    
    // указать адрес данных структуры
    V_VT(&varValue) = VT_RECORD; V_RECORD(&varValue) = _pvRecord;
        
    // указать адрес интерфейса описания
    V_RECORDINFO(&varValue) = new RecordInfo(_type); 

    // увеличить счетчик ссылок
    V_RECORDINFO(&varValue)->AddRef(); return varValue; 
}

const ETW::IElement* ETW::Struct::FindPath(PCWSTR szPath) const 
{
    // найти завершение имени в строке
    if (!szPath || *szPath == 0) return this; PCWSTR szNext = szPath + wcscspn(szPath, L"[."); 

    // извлечь имя поля
    std::wstring strName(szPath, szNext - szPath); 
    
    // найти элемент по имени
    const IElement* pElement = FindName(strName.c_str()); 

    // проверить наличие элемента
    if (!pElement || *szNext == 0) return pElement; 

    // при указании индекса
    for (PCWSTR szEnd = szNext; *szNext == L'['; szEnd = szNext)
    {
        // проверить наличие массива
        if (pElement->Type().LogicalType() != TYPE_ARRAY) return nullptr; 

        // выполнить преобразование типа
        const IContainer* pArray = (const IContainer*)pElement; 

        // для всех символов индекса
        for (szEnd++, szNext++; *szEnd && *szEnd != L']'; szEnd++)
        {
            // проверить наличие цифры
            if (!isdigit(*szEnd)) return nullptr; 
        }
        // проверить наличие закрывающей скобки
        if (*szEnd != L']') return nullptr;

        // извлечь часть строки с индексом
        std::wistringstream stream(std::wstring(szNext, szEnd - szNext)); 

        // раскодировать индекс
        size_t index; stream >> std::dec >> index; szNext = szEnd + 1; 

        // проверить корректность индекса
        if (index >= pArray->Count()) return nullptr; 

        // перейти на элемент массива и проверить завершение поиска
        pElement = &pArray[index]; if (*szNext == 0) return pElement; 
    }
    // при указании точки
    if (szNext[0] == L'.' && szNext[1] != 0) 
    {    
        // проверить наличие структуры
        if (pElement->Type().LogicalType() != TYPE_STRUCT) return nullptr; 

        // найти дочерний элемент по пути
        return ((const IStruct*)pElement)->FindPath(szNext + 1); 
    }
    return nullptr; 
}

