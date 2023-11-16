#pragma once
#include "TraceWindows.h"
#include <objbase.h>
#include <unknwn.h>
#include <oaidl.h>
#include <oledb.h>

///////////////////////////////////////////////////////////////////////////////
// Определение отсутствия возврата из функции
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define _NORETURN	__attribute__((noreturn))
#elif defined _MSC_VER
#define _NORETURN	__declspec(noreturn)
#else 
#define _NORETURN	[[noreturn]]
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
class com_error : public windows_error
{
    // описание ошибки
    private: private: IErrorInfo* pErrorInfo; 

    // конструктор
    public: com_error(IUnknown* p, REFIID iid, HRESULT code) : windows_error(code) 
    { 
        // сохранить переданные параметры
        pErrorInfo = ::GetErrorInfo(p, iid); 
    }
    // конструктор
    public: com_error(IErrorInfo* pErrorInfo, HRESULT code) : windows_error(code) 
    { 
        // сохранить переданные параметры
        this->pErrorInfo = pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // конструктор
    public: com_error(const com_error& other) : windows_error(other)
    {
        // сохранить переданные параметры
        pErrorInfo = other.pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // деструктор
    public: virtual ~com_error() { if (pErrorInfo) pErrorInfo->Release(); }

    // выбросить исключение
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
    { 
        // выбросить исключение
        trace(szFile, line); throw *this; 
    }
    // передать сообщение отладчику
    public: virtual void trace(const char*, int) const;  

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
inline void com_error::trace(const char* szFile, int line) const 
{
	// вызвать базовую функцию
	windows_error::trace(szFile, line); if (!pErrorInfo) return; 
    __try { 
        // получить источник ошибки
        BSTR bstrSource;
        if (SUCCEEDED(pErrorInfo->GetSource(&bstrSource)))
        {
	        // выполнить запись в журнал
	        trace_format("Source = %ls", bstrSource); 

            // освободить выделенные ресурсы
            ::SysFreeString(bstrSource); 
        }
        // получить описание ошибки
        BSTR bstrDescription;
        if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
        {
	        // выполнить запись в журнал
	        trace_format("Description = %ls", bstrDescription); 

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
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки COM
///////////////////////////////////////////////////////////////////////////////
inline void com_error::TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const 
{
    // получить описание ошибки
    BSTR bstrDescription;
    if (SUCCEEDED(pError->GetDescription(&bstrDescription)))
    {
	    // выполнить запись в журнал
	    trace_format("%lsDescription = %ls", szPrefix, bstrDescription); 

        // освободить выделенные ресурсы
        ::SysFreeString(bstrDescription); 
    }
    // получить источник ошибки
    BSTR bstrSource;
    if (SUCCEEDED(pError->GetSource(&bstrSource)))
    {
	    // выполнить запись в журнал
	    trace_format("%lsSource = %ls", szPrefix, bstrSource); 

        // освободить выделенные ресурсы
        ::SysFreeString(bstrSource); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// Описание записей ошибки COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorRecords* com_error::GetErrorRecords() const 
{
    // инициализировать указатели на интерфейсы
	IErrorRecords* pErrorRecords = nullptr; 

    // получить требуемый интерфейс
	if (FAILED(pErrorInfo->QueryInterface(
	    IID_IErrorRecords, (void**) &pErrorRecords))) return nullptr; 

    // вернуть полученный интерфейс
    return pErrorRecords; 
}

inline void com_error::TraceErrorRecords(IErrorRecords* pErrorRecords) const
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
inline IDispatch* com_error::GetClrException() const 
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

inline void com_error::TraceClrException(IDispatch* pException) const 
{
    // указать используемые методы
    LPCOLESTR szMethodNames[] = { L"Message", L"StackTrace" }; 

    // выделить память для идентификаторов методов
    LCID lcid = LOCALE_USER_DEFAULT; DISPID ids[2]; 

    // получить идентификатор метода
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[0], 1, lcid, &ids[0])))
    {
        // создать место для результата
        VARIANT varMessage; ::VariantInit(&varMessage);

        // указать отсутствие параметров методов
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // получить описание ошибки
	    if (SUCCEEDED(pException->Invoke(ids[0], IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varMessage, nullptr, nullptr)))
        {
		    // выполнить запись в журнал
		    trace_format("CLR Message = %ls", varMessage.bstrVal); 

            // освободить выделенные ресурсы
            ::VariantClear(&varMessage);
        }
    }
    // получить идентификатор метода
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[1], 1, lcid, &ids[1])))
    {
	    // создать место для результата
        VARIANT varStack; ::VariantInit(&varStack);

        // указать отсутствие параметров методов
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // получить описание ошибки
	    if (SUCCEEDED(pException->Invoke(ids[1], IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varStack, nullptr, nullptr)))
        {
		    // выполнить запись в журнал
		    trace_format("%hs", "CLR StackTrace ="); 
            
		    // выполнить запись в журнал
            ATRACE_MULTILINE(TRACE_LEVEL_ERROR, varStack.bstrVal);

            // освободить выделенные ресурсы
            ::VariantClear(&varStack);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Трассировка ошибок COM
///////////////////////////////////////////////////////////////////////////////
// Возбуждение исключения
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)          \
    com_error(OBJ, IID, WPP_VAR(LINE)).trace(FILE, LINE);                   \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)          \
    com_error(OBJ, IID, WPP_VAR(LINE)).raise(FILE, LINE);
#endif 

// Параметры трассировки для отладчика
#define WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(LEVEL, OBJ, IID, HR)        WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)

// Отсутствие предварительных действий
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(LEVEL, OBJ, IID, HR)       WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)

// Проверка наличия трассировки
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)   WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)

// Проверка наличия ошибки
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(LEVEL, OBJ, IID, HR)                    \
    ; if (WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)) {            \
         WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, __FILE__, __LINE__)         \
    }}

// Определение трассировки
#if defined WPP_CONTROL_GUIDS
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_LOGGER(LEVEL, OBJ, IID, HR)    WPP_TRACELEVEL_HRESULT_LOGGER(LEVEL, HR)
#else 
#define AE_CHECK_COM(OBJ, IID, HR)                                                                                                \
    WPP_LOG_ALWAYS(WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(TRACE_LEVEL_ERROR, OBJ, IID, HR), "ERROR %!HRESULT!", WPP_VAR(__LINE__))     \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                           \
    (void)((                                                                                                                      \
        WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                                   \
        ? WPP_INVOKE_WPP_DEBUG(("ERROR %!HRESULT!", WPP_VAR(__LINE__))), 1 : 0                                                    \
    ))                                                                                                                            \
    WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(TRACE_LEVEL_ERROR, OBJ, IID, HR)                                  
#endif 

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
