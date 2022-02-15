#pragma once
#include <unknwn.h>
#include <oaidl.h>
#include <oledb.h>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (B9C9408B, 25C5, 468D, 94B3, FC5CC02A1823)
#include "TraceCOM.tmh"
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
class com_exception : public windows_exception
{
    // ������ � �������� ������
    private: IUnknown* pObj; private: IErrorInfo* pErrorInfo; 

    // �����������
    public: com_exception(IUnknown* p, REFIID iid, HRESULT code, const char* szFile, int line)
        
        // ��������� ���������� ���������
        : windows_exception(hresult_error(code), szFile, line) 
    { 
        // ��������� ���������� ���������
        pObj = p; pObj->AddRef(); pErrorInfo = ::GetErrorInfo(pObj, iid); 
    }
    // �����������
    public: com_exception(const com_exception& other) : windows_exception(other)
    {
        // ��������� ���������� ���������
        pObj = other.pObj; pObj->AddRef(); 

        // ��������� ���������� ���������
        pErrorInfo = other.pErrorInfo; if (pErrorInfo) pErrorInfo->AddRef(); 
    }
    // ����������
    public: virtual ~com_exception() 
    { 
        // ���������� ���������� �������
        pObj->Release(); if (pErrorInfo) pErrorInfo->Release(); 
    }
    // ��������� ����������
    public: virtual void raise() const { trace(); throw *this; }
    // �������� ��������� ���������
    public: virtual void trace() const;  

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
inline void com_exception::trace() const 
{
	// ������� ������� �������
	windows_exception::trace(); if (!pErrorInfo) return; 
    __try { 
        // �������� �������� ������
        BSTR bstrSource;
        if (SUCCEEDED(pErrorInfo->GetSource(&bstrSource)))
        {
	        // ��������� ������ � ������
	        ATRACE(TRACE_LEVEL_ERROR, "Source = %!ARWSTR!", bstrSource); 

            // ���������� ���������� �������
            ::SysFreeString(bstrSource); 
        }
        // �������� �������� ������
        BSTR bstrDescription;
        if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
        {
	        // ��������� ������ � ������
	        ATRACE(TRACE_LEVEL_ERROR, "Description = %!ARWSTR!", bstrDescription); 

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
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������ COM
///////////////////////////////////////////////////////////////////////////////
inline void com_exception::TraceErrorInfo(PCWSTR szPrefix, IErrorInfo* pError) const 
{
    // �������� �������� ������
    BSTR bstrDescription;
    if (SUCCEEDED(pError->GetDescription(&bstrDescription)))
    {
	    // ��������� ������ � ������
	    ATRACE(TRACE_LEVEL_ERROR, "%lsDescription = %!ARWSTR!", szPrefix, bstrDescription); 

        // ���������� ���������� �������
        ::SysFreeString(bstrDescription); 
    }
    // �������� �������� ������
    BSTR bstrSource;
    if (SUCCEEDED(pError->GetSource(&bstrSource)))
    {
	    // ��������� ������ � ������
	    ATRACE(TRACE_LEVEL_ERROR, "%lsSource = %!ARWSTR!", szPrefix, bstrSource); 

        // ���������� ���������� �������
        ::SysFreeString(bstrSource); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ������ COM
///////////////////////////////////////////////////////////////////////////////
inline IErrorRecords* com_exception::GetErrorRecords() const 
{
    // ���������������� ��������� �� ����������
	IErrorRecords* pErrorRecords = nullptr; 

    // �������� ��������� ���������
	if (FAILED(pErrorInfo->QueryInterface(
	    IID_IErrorRecords, (void**) &pErrorRecords))) return nullptr; 

    // ������� ���������� ���������
    return pErrorRecords; 
}

inline void com_exception::TraceErrorRecords(IErrorRecords* pErrorRecords) const
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
inline IDispatch* com_exception::GetClrException() const 
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

inline void com_exception::TraceClrException(IDispatch* pException) const 
{
    // ������� ������������ ������
    LPCOLESTR szMethodNames[] = { L"Message", L"StackTrace" }; 

    // �������� ������ ��� ��������������� �������
    LCID lcid = LOCALE_USER_DEFAULT; DISPID id = 0; 

    // �������� ������������� ������
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[0], 1, lcid, &id)))
    {
        // ������� ����� ��� ����������
        VARIANT varMessage; ::VariantInit(&varMessage);

        // ������� ���������� ���������� �������
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // �������� �������� ������
	    if (SUCCEEDED(pException->Invoke(id, IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varMessage, nullptr, nullptr)))
        {
		    // ��������� ������ � ������
		    ATRACE(TRACE_LEVEL_ERROR, "CLR Message = %!ARWSTR!", varMessage.bstrVal); 

            // ���������� ���������� �������
            ::VariantClear(&varMessage);
        }
    }
    // �������� ������������� ������
    if (SUCCEEDED(pException->GetIDsOfNames(
        IID_NULL, (LPOLESTR*)&szMethodNames[1], 1, lcid, &id)))
    {
	    // ������� ����� ��� ����������
        VARIANT varStack; ::VariantInit(&varStack);

        // ������� ���������� ���������� �������
        DISPPARAMS parameters = { nullptr, nullptr, 0, 0 }; 

        // �������� �������� ������
	    if (SUCCEEDED(pException->Invoke(id, IID_NULL, lcid, 
            DISPATCH_PROPERTYGET, &parameters, &varStack, nullptr, nullptr)))
        {
		    // ��������� ������ � ������
		    ATRACE(TRACE_LEVEL_ERROR, "CLR StackTrace ="); 
            
		    // ��������� ������ � ������
            ATRACE_MULTILINE(TRACE_LEVEL_ERROR, varStack.bstrVal);

            // ���������� ���������� �������
            ::VariantClear(&varStack);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
