#pragma once
#include <unknwn.h>
#include <oaidl.h>
#include <oledb.h>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (B9C9408B, 25C5, 468D, 94B3, FC5CC02A1823)
#include "TraceCOM.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Используемые библиотеки
///////////////////////////////////////////////////////////////////////////////
#pragma comment(lib, "oleaut32.lib")

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorInfo* GetErrorInfo(IUnknown* pObj, REFIID iid)
{
    // инициализировать указатели на интерфейсы
    ISupportErrorInfo* pSupportErrorInfo = nullptr; IErrorInfo* pErrorInfo = nullptr; 
    __try { 
	    // получить интерфейс проверки поодержки описания ошибок
	    if (FAILED(pObj->QueryInterface(
            IID_ISupportErrorInfo, (void**)&pSupportErrorInfo))) return nullptr; 

	    // проверить поддержку описания ошибок для интерфейса
        HRESULT hr = pSupportErrorInfo->InterfaceSupportsErrorInfo(iid); 

        // освободить интерфейс
        pSupportErrorInfo->Release(); if (hr != S_OK) return nullptr; 

        // получить требуемый интерфейс
	    return (SUCCEEDED(::GetErrorInfo(0, &pErrorInfo))) ? pErrorInfo : nullptr; 
    }
    // обработать возможное исключение
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

///////////////////////////////////////////////////////////////////////////////
// Исключение COM
///////////////////////////////////////////////////////////////////////////////
class com_exception : public windows_exception
{
    // объект и описание ошибки
    private: IUnknown* pObj; private: IErrorInfo* pErrorInfo; 

    // конструктор
    public: com_exception(IUnknown* p, REFIID iid, HRESULT code, const char* szFile, int line)
        
        // сохранить переданные параметры
        : windows_exception(hresult_error(code), szFile, line) 
    { 
        // сохранить переданные параметры
        pObj = p; pObj->AddRef(); pErrorInfo = ::GetErrorInfo(pObj, iid); 
    }
    // конструктор
    public: com_exception(const com_exception& other) : windows_exception(other)
    {
        // сохранить переданные параметры
        pObj = other.pObj; pObj->AddRef(); 

        // сохранить переданные параметры
        pErrorInfo = other.pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // деструктор
    public: virtual ~com_exception() 
    { 
        // освободить выделенные ресурсы
        pObj->Release(); if (pErrorInfo) pErrorInfo->Release(); 
    }
    // выбросить исключение
    public: virtual void raise() const { trace(); throw *this; }
    // передать сообщение отладчику
    public: virtual void trace() const;  

    // получить интерфейс описания ошибки
    public: IErrorInfo* GetErrorInfo() const 
    { 
        // получить интерфейс описания ошибки
        if (pErrorInfo) pErrorInfo->AddRef(); return pErrorInfo; 
    }  
    // вывести описание ошибки
    private: void TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const; 

    // получить отдельную запись описания ошибки
    private: IErrorRecords* GetErrorRecords() const;  
    // вывести описание ошибки
    private: void TraceErrorRecords(IErrorRecords* pErrorRecords) const; 

    // получить интерфейс описания исключения CLR
    private: IDispatch* GetClrException() const;  
    // вывести описание ошибки
    private: void TraceClrException(IDispatch* pException) const;  
};

///////////////////////////////////////////////////////////////////////////////
// Передать сообщение отладчику
///////////////////////////////////////////////////////////////////////////////
inline void com_exception::trace() const 
{
	// вызвать базовую функцию
	windows_exception::trace(); if (!pErrorInfo) return; 
    __try { 
        // получить источник ошибки
        BSTR bstrSource;
        if (SUCCEEDED(pErrorInfo->GetSource(&bstrSource)))
        {
	        // выполнить запись в журнал
	        ATRACE(TRACE_LEVEL_ERROR, "Source = %!ARWSTR!", bstrSource); 

            // освободить выделенные ресурсы
            ::SysFreeString(bstrSource); 
        }
        // получить описание ошибки
        BSTR bstrDescription;
        if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
        {
	        // выполнить запись в журнал
	        ATRACE(TRACE_LEVEL_ERROR, "Description = %!ARWSTR!", bstrDescription); 

            // освободить выделенные ресурсы
            ::SysFreeString(bstrDescription); 
        }
        // получить отдельные записи описания ошибки
        if (IErrorRecords* pErrorRecords = GetErrorRecords())
        {
            // вывести описание ошибки
            TraceErrorRecords(pErrorRecords); pErrorRecords->Release(); 
        }
        // получить интерфейс описания исключения CLR
        if (IDispatch* pException = GetClrException())
        {
            // вывести описание ошибки
            TraceClrException(pException); pException->Release();
        }
    }
    // обработать возможное исключение
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
}

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки COM
///////////////////////////////////////////////////////////////////////////////
inline void com_exception::TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const 
{
    // получить описание ошибки
    BSTR bstrDescription;
    if (SUCCEEDED(pError->GetDescription(&bstrDescription)))
    {
	    // выполнить запись в журнал
	    ATRACE(TRACE_LEVEL_ERROR, "%lsDescription = %!ARWSTR!", szPrefix, bstrDescription); 

        // освободить выделенные ресурсы
        ::SysFreeString(bstrDescription); 
    }
    // получить источник ошибки
    BSTR bstrSource;
    if (SUCCEEDED(pError->GetSource(&bstrSource)))
    {
	    // выполнить запись в журнал
	    ATRACE(TRACE_LEVEL_ERROR, "%lsSource = %!ARWSTR!", szPrefix, bstrSource); 

        // освободить выделенные ресурсы
        ::SysFreeString(bstrSource); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// Описание записей ошибки COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorRecords* com_exception::GetErrorRecords() const 
{
    // инициализировать указатели на интерфейсы
	IErrorRecords* pErrorRecords = nullptr; 

    // получить требуемый интерфейс
	if (FAILED(pErrorInfo->QueryInterface(
	    IID_IErrorRecords, (void**) &pErrorRecords))) return nullptr; 

    // вернуть полученный интерфейс
    return pErrorRecords; 
}

inline void com_exception::TraceErrorRecords(IErrorRecords* pErrorRecords) const
{
	// указать используемую локализацию
	LCID lcid = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), SORT_DEFAULT); 

    // инициализировать переменные
	ULONG ulNumErrorRecs = 0; IErrorInfo* pRecordInfo = nullptr; WCHAR szPrefix[16]; 

	// получить число записей описания ошибок
	if (FAILED(pErrorRecords->GetRecordCount(&ulNumErrorRecs))) return; 

	// для всех записей описания ошибки
	for (ULONG i = 0; i < ulNumErrorRecs; i++)
	{
		// получить запись описания ошибки
		if (SUCCEEDED(pErrorRecords->GetErrorInfo(i, lcid, &pRecordInfo)))
        {
            // указать строку форматирования
            swprintf(szPrefix, sizeof(szPrefix) / sizeof(WCHAR),  L"Index = %ld", i);

            // вывести описание ошибки
            TraceErrorInfo(szPrefix, pRecordInfo); pRecordInfo->Release(); 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Описание исключения CLR
///////////////////////////////////////////////////////////////////////////////
inline IDispatch* com_exception::GetClrException() const 
{
	IDispatch* pDispatch = nullptr;

    // указать интерфейс mscorlib::_Exception
    const IID iid = { 0xb36b5c63, 0x42ef, 0x38bc, 
        { 0xa0, 0x7e, 0x0b, 0x34, 0xc9, 0x8f, 0x16, 0x4a }
    }; 
    // получить интерфейс описания исключения
	if (FAILED(pErrorInfo->QueryInterface(
	    iid, (void**) &pDispatch))) return nullptr; return pDispatch; 
}

inline void com_exception::TraceClrException(IDispatch* pException) const 
{
    // указать используемые методы
    LPCOLESTR szMethodNames[] = { L"Message", L"StackTrace" }; 

    // выделить память для идентификаторов методов
    LCID lcid = LOCALE_USER_DEFAULT; DISPID id = 0; 

    // получить идентификатор метода
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[0], 1, lcid, &id)))
    {
        // создать место для результата
        VARIANT varMessage; ::VariantInit(&varMessage);

        // указать отсутствие параметров методов
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // получить описание ошибки
	    if (SUCCEEDED(pException->Invoke(id, IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varMessage, nullptr, nullptr)))
        {
		    // выполнить запись в журнал
		    ATRACE(TRACE_LEVEL_ERROR, "CLR Message = %!ARWSTR!", varMessage.bstrVal); 

            // освободить выделенные ресурсы
            ::VariantClear(&varMessage);
        }
    }
    // получить идентификатор метода
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[1], 1, lcid, &id)))
    {
	    // создать место для результата
        VARIANT varStack; ::VariantInit(&varStack);

        // указать отсутствие параметров методов
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // получить описание ошибки
	    if (SUCCEEDED(pException->Invoke(id, IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varStack, nullptr, nullptr)))
        {
		    // выполнить запись в журнал
		    ATRACE(TRACE_LEVEL_ERROR, "CLR StackTrace ="); 
            
		    // выполнить запись в журнал
            ATRACE_MULTILINE(TRACE_LEVEL_ERROR, varStack.bstrVal);

            // освободить выделенные ресурсы
            ::VariantClear(&varStack);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
