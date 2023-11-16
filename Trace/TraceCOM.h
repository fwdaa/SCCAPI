#pragma once
#include "TraceWindows.h"
#include <objbase.h>
#include <unknwn.h>
#include <oaidl.h>
#include <oledb.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� �������� �� �������
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define _NORETURN	__attribute__((noreturn))
#elif defined _MSC_VER
#define _NORETURN	__declspec(noreturn)
#else 
#define _NORETURN	[[noreturn]]
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������������ ����������
///////////////////////////////////////////////////////////////////////////////
#pragma comment(lib, "oleaut32.lib")

///////////////////////////////////////////////////////////////////////////////
// �������� ������ COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorInfo* GetErrorInfo(IUnknown* pObj, REFIID iid)
{
    // ���������������� ��������� �� ����������
    ISupportErrorInfo* pSupportErrorInfo = nullptr; IErrorInfo* pErrorInfo = nullptr; 
    __try { 
	    // �������� ��������� �������� ��������� �������� ������
	    if (FAILED(pObj->QueryInterface(
            IID_ISupportErrorInfo, (void**)&pSupportErrorInfo))) return nullptr; 

	    // ��������� ��������� �������� ������ ��� ����������
        HRESULT hr = pSupportErrorInfo->InterfaceSupportsErrorInfo(iid); 

        // ���������� ���������
        pSupportErrorInfo->Release(); if (hr != S_OK) return nullptr; 

        // �������� ��������� ���������
	    return (SUCCEEDED(::GetErrorInfo(0, &pErrorInfo))) ? pErrorInfo : nullptr; 
    }
    // ���������� ��������� ����������
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

///////////////////////////////////////////////////////////////////////////////
// ���������� COM
///////////////////////////////////////////////////////////////////////////////
class com_error : public windows_error
{
    // �������� ������
    private: private: IErrorInfo* pErrorInfo; 

    // �����������
    public: com_error(IUnknown* p, REFIID iid, HRESULT code) : windows_error(code) 
    { 
        // ��������� ���������� ���������
        pErrorInfo = ::GetErrorInfo(p, iid); 
    }
    // �����������
    public: com_error(IErrorInfo* pErrorInfo, HRESULT code) : windows_error(code) 
    { 
        // ��������� ���������� ���������
        this->pErrorInfo = pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // �����������
    public: com_error(const com_error& other) : windows_error(other)
    {
        // ��������� ���������� ���������
        pErrorInfo = other.pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // ����������
    public: virtual ~com_error() { if (pErrorInfo) pErrorInfo->Release(); }

    // ��������� ����������
    public: virtual _NORETURN void raise(const char* szFile, int line) const 
    { 
        // ��������� ����������
        trace(szFile, line); throw *this; 
    }
    // �������� ��������� ���������
    public: virtual void trace(const char*, int) const;  

    // �������� ��������� �������� ������
    public: IErrorInfo* GetErrorInfo() const 
    { 
        // �������� ��������� �������� ������
        if (pErrorInfo) pErrorInfo->AddRef(); return pErrorInfo; 
    }  
    // ������� �������� ������
    private: void TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const; 

    // �������� ��������� ������ �������� ������
    private: IErrorRecords* GetErrorRecords() const;  
    // ������� �������� ������
    private: void TraceErrorRecords(IErrorRecords* pErrorRecords) const; 

    // �������� ��������� �������� ���������� CLR
    private: IDispatch* GetClrException() const;  
    // ������� �������� ������
    private: void TraceClrException(IDispatch* pException) const;  
};

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
inline void com_error::trace(const char* szFile, int line) const 
{
	// ������� ������� �������
	windows_error::trace(szFile, line); if (!pErrorInfo) return; 
    __try { 
        // �������� �������� ������
        BSTR bstrSource;
        if (SUCCEEDED(pErrorInfo->GetSource(&bstrSource)))
        {
	        // ��������� ������ � ������
	        trace_format("Source = %ls", bstrSource); 

            // ���������� ���������� �������
            ::SysFreeString(bstrSource); 
        }
        // �������� �������� ������
        BSTR bstrDescription;
        if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
        {
	        // ��������� ������ � ������
	        trace_format("Description = %ls", bstrDescription); 

            // ���������� ���������� �������
            ::SysFreeString(bstrDescription); 
        }
        // �������� ��������� ������ �������� ������
        if (IErrorRecords* pErrorRecords = GetErrorRecords())
        {
            // ������� �������� ������
            TraceErrorRecords(pErrorRecords); pErrorRecords->Release(); 
        }
        // �������� ��������� �������� ���������� CLR
        if (IDispatch* pException = GetClrException())
        {
            // ������� �������� ������
            TraceClrException(pException); pException->Release();
        }
    }
    // ���������� ��������� ����������
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������ COM
///////////////////////////////////////////////////////////////////////////////
inline void com_error::TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const 
{
    // �������� �������� ������
    BSTR bstrDescription;
    if (SUCCEEDED(pError->GetDescription(&bstrDescription)))
    {
	    // ��������� ������ � ������
	    trace_format("%lsDescription = %ls", szPrefix, bstrDescription); 

        // ���������� ���������� �������
        ::SysFreeString(bstrDescription); 
    }
    // �������� �������� ������
    BSTR bstrSource;
    if (SUCCEEDED(pError->GetSource(&bstrSource)))
    {
	    // ��������� ������ � ������
	    trace_format("%lsSource = %ls", szPrefix, bstrSource); 

        // ���������� ���������� �������
        ::SysFreeString(bstrSource); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ������ COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorRecords* com_error::GetErrorRecords() const 
{
    // ���������������� ��������� �� ����������
	IErrorRecords* pErrorRecords = nullptr; 

    // �������� ��������� ���������
	if (FAILED(pErrorInfo->QueryInterface(
	    IID_IErrorRecords, (void**) &pErrorRecords))) return nullptr; 

    // ������� ���������� ���������
    return pErrorRecords; 
}

inline void com_error::TraceErrorRecords(IErrorRecords* pErrorRecords) const
{
	// ������� ������������ �����������
	LCID lcid = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), SORT_DEFAULT); 

    // ���������������� ����������
	ULONG ulNumErrorRecs = 0; IErrorInfo* pRecordInfo = nullptr; WCHAR szPrefix[16]; 

	// �������� ����� ������� �������� ������
	if (FAILED(pErrorRecords->GetRecordCount(&ulNumErrorRecs))) return; 

	// ��� ���� ������� �������� ������
	for (ULONG i = 0; i < ulNumErrorRecs; i++)
	{
		// �������� ������ �������� ������
		if (SUCCEEDED(pErrorRecords->GetErrorInfo(i, lcid, &pRecordInfo)))
        {
            // ������� ������ ��������������
            swprintf(szPrefix, sizeof(szPrefix) / sizeof(WCHAR),  L"Index = %ld", i);

            // ������� �������� ������
            TraceErrorInfo(szPrefix, pRecordInfo); pRecordInfo->Release(); 
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� CLR
///////////////////////////////////////////////////////////////////////////////
inline IDispatch* com_error::GetClrException() const 
{
	IDispatch* pDispatch = nullptr;

    // ������� ��������� mscorlib::_Exception
    const IID iid = { 0xb36b5c63, 0x42ef, 0x38bc, 
        { 0xa0, 0x7e, 0x0b, 0x34, 0xc9, 0x8f, 0x16, 0x4a }
    }; 
    // �������� ��������� �������� ����������
	if (FAILED(pErrorInfo->QueryInterface(
	    iid, (void**) &pDispatch))) return nullptr; return pDispatch; 
}

inline void com_error::TraceClrException(IDispatch* pException) const 
{
    // ������� ������������ ������
    LPCOLESTR szMethodNames[] = { L"Message", L"StackTrace" }; 

    // �������� ������ ��� ��������������� �������
    LCID lcid = LOCALE_USER_DEFAULT; DISPID ids[2]; 

    // �������� ������������� ������
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[0], 1, lcid, &ids[0])))
    {
        // ������� ����� ��� ����������
        VARIANT varMessage; ::VariantInit(&varMessage);

        // ������� ���������� ���������� �������
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // �������� �������� ������
	    if (SUCCEEDED(pException->Invoke(ids[0], IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varMessage, nullptr, nullptr)))
        {
		    // ��������� ������ � ������
		    trace_format("CLR Message = %ls", varMessage.bstrVal); 

            // ���������� ���������� �������
            ::VariantClear(&varMessage);
        }
    }
    // �������� ������������� ������
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[1], 1, lcid, &ids[1])))
    {
	    // ������� ����� ��� ����������
        VARIANT varStack; ::VariantInit(&varStack);

        // ������� ���������� ���������� �������
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // �������� �������� ������
	    if (SUCCEEDED(pException->Invoke(ids[1], IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varStack, nullptr, nullptr)))
        {
		    // ��������� ������ � ������
		    trace_format("%hs", "CLR StackTrace ="); 
            
		    // ��������� ������ � ������
            ATRACE_MULTILINE(TRACE_LEVEL_ERROR, varStack.bstrVal);

            // ���������� ���������� �������
            ::VariantClear(&varStack);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ COM
///////////////////////////////////////////////////////////////////////////////
// ����������� ����������
#if defined _MANAGED && _MANAGED == 1
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)          \
    com_error(OBJ, IID, WPP_VAR(LINE)).trace(FILE, LINE);                   \
    throw gcnew System::ComponentModel::Win32Exception(WPP_VAR(LINE));  
#else
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, FILE, LINE)          \
    com_error(OBJ, IID, WPP_VAR(LINE)).raise(FILE, LINE);
#endif 

// ��������� ����������� ��� ���������
#define WPP_EX_TRACELEVEL_OBJ_IID_HRESULT(LEVEL, OBJ, IID, HR)        WPP_EX_TRACELEVEL_HRESULT(LEVEL, HR)

// ���������� ��������������� ��������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_PRE(LEVEL, OBJ, IID, HR)       WPP_TRACELEVEL_HRESULT_PRE(LEVEL, HR)

// �������� ������� �����������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)   WPP_TRACELEVEL_HRESULT_ENABLED(LEVEL, HR)

// �������� ������� ������
#define WPP_TRACELEVEL_OBJ_IID_HRESULT_POST(LEVEL, OBJ, IID, HR)                    \
    ; if (WPP_TRACELEVEL_OBJ_IID_HRESULT_ENABLED(LEVEL, OBJ, IID, HR)) {            \
         WPP_TRACELEVEL_OBJ_IID_HRESULT_RAISE(OBJ, IID, __FILE__, __LINE__)         \
    }}

// ����������� �����������
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
// ������ �������� ��������
///////////////////////////////////////////////////////////////////////////////
#undef _NORETURN
