#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp" 
#include <atlenc.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� Windows
///////////////////////////////////////////////////////////////////////////////
#include <wincred.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "credui.lib" )
#pragma comment(lib, "Aladdin.CAPI.COM.lib" )

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.COM.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������������� ����������
///////////////////////////////////////////////////////////////////////////////
static bool IsProcessInteractive()
{
	// �������� ������� ���� ����������
	HWINSTA hStation = ::GetProcessWindowStation();

	// ��������� ������� �������� �����
	if (hStation == NULL) return true; USEROBJECTFLAGS uof = { 0 };

	// �������� �������� �������� �����
	if (::GetUserObjectInformationW(hStation, UOI_FLAGS, 
		&uof, sizeof(USEROBJECTFLAGS), nullptr))
	{
		// ��������� ����������������� �������� �����
		if ((uof.dwFlags & WSF_VISIBLE) == 0) return false;
	}
	return true;
}
///////////////////////////////////////////////////////////////////////////////
// ���������� IUnknown
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
Aladdin::CAPI::COM::UnknownObject<Interface>::UnknownObject(
	Interface* pObject, bool registerGIT) : dwCookieGIT(0)
{
	// ��������� ���������� ��������� 
	this->pObject = pObject; cRef = 1; if (!registerGIT) return; 

	// �������� ������ ������� GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	AE_CHECK_HRESULT(pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	)); 
	// ���������������� ������ � ������� 
	AE_CHECK_HRESULT(pGIT->RegisterInterfaceInGlobal(
		pObject, GetIID(), &dwCookieGIT
	)); 
}

template <class Interface>
Aladdin::CAPI::COM::UnknownObject<Interface>::~UnknownObject() 
{ 
	// ��������� ������������� �������� �� ������� 
	ATLASSERT(cRef == 1); if (dwCookieGIT == 0) return; 

	// �������� ������ ������� GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	HRESULT hr = pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	); 
	// �������� ����������� ������� 
	if (SUCCEEDED(hr)) pGIT->RevokeInterfaceFromGlobal(dwCookieGIT); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� Dispose ��� ������������ �������
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetTypeInfoCount(
	UINT *pctinfo)
{$
	// ������� ������� �����
	HRESULT hr = BaseObject()->GetTypeInfoCount(pctinfo); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetTypeInfo( 
	UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo)
{$
	// ������� ������� �����
	HRESULT hr = BaseObject()->GetTypeInfo(iTInfo, lcid, ppTInfo); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetIDsOfNames( 
	REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId)
{$
	// ������� ������� �����
	HRESULT hr = BaseObject()->GetIDsOfNames(riid, rgszNames, cNames, lcid, rgDispId); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::Invoke( 
	DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, 
	DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr)
{$
	// ������� ������� �����
	HRESULT hr = BaseObject()->Invoke(dispIdMember, riid, 
		lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr
	); 
	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DistinctName::get_Encoded(BSTR* pRetVal)
{$
	// ������������ ��������� ��� � ��������� Base-64
	HRESULT hr = BaseObject()->get_Encoded(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::DistinctName::Encoded() const
{$
	// ������������ ��������� ��� � ��������� Base-64
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->get_Encoded(&bstrEncoded); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DistinctName::ToString(BSTR* pRetVal)
{$
	// �������� ��������� ������������� ���������� �����
	HRESULT hr = BaseObject()->ToString(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::DistinctName::ToString() const
{$
	// �������� ��������� ������������� ���������� �����
	ATL::CComBSTR bstrName; HRESULT hr = BaseObject()->ToString(&bstrName); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ��������� �������������
	return std::wstring(bstrName); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� ����������
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Encoded(BSTR *pRetVal)
{$
	// ������������ ���������� � ��������� Base-64
	HRESULT hr = BaseObject()->get_Encoded(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::Encoded() const
{
	// ������������ ���������� � ��������� Base-64
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->get_Encoded(&bstrEncoded); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Issuer(
	Aladdin_CAPI_COM::IDistinctName** pRetVal)
{$
	// �������� �������� �����������
	HRESULT hr = BaseObject()->get_Issuer(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::COM::Certificate::Issuer() const
{$
	// �������� �������� �����������
	ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> pName; 
	HRESULT hr = BaseObject()->get_Issuer(&pName); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ��� ��������
	return std::shared_ptr<IDistinctName>(
		new DistinctName(pName), Deleter<DistinctName>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Subject(
	Aladdin_CAPI_COM::IDistinctName** pRetVal)
{$
	// �������� �������� �����������
	HRESULT hr = BaseObject()->get_Subject(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::COM::Certificate::Subject() const
{$
	// �������� �������� �����������
	ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> pName; 
	HRESULT hr = BaseObject()->get_Subject(&pName); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ��� ��������
	return std::shared_ptr<IDistinctName>(
		new DistinctName(pName), Deleter<DistinctName>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_KeyOID(BSTR* pRetVal)
{$
	// �������� ������������� (OID) �����
	HRESULT hr = BaseObject()->get_KeyOID(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_KeyUsage(
	Aladdin_CAPI_COM::KeyUsage *pRetVal)
{$
	// �������� ������ ������������� �����
	HRESULT hr = BaseObject()->get_KeyUsage(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::Certificate::KeyOID() const
try {$
	// �������� ������������� (OID) �����
	ATL::CComBSTR bstrKeyOID;  
	HRESULT hr = BaseObject()->get_KeyOID(&bstrKeyOID); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
	
	// ������� ������������� �����
	return std::wstring(bstrKeyOID); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::wstring(); 
}

Aladdin::CAPI::KeyUsage Aladdin::CAPI::COM::Certificate::KeyUsage() const
{$
	// �������� ������ ������������� �����
	Aladdin_CAPI_COM::KeyUsage keyUsage; 
	HRESULT hr = BaseObject()->get_KeyUsage(&keyUsage); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ���������� �����
	return static_cast<CAPI::KeyUsage>(keyUsage); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::Encrypt(
	BSTR data, BSTR *pRetVal)
{$
	// ����������� ������ � ��������� Base-64
	HRESULT hr = BaseObject()->Encrypt(data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::Encrypt(
	const void* pvData, size_t cbData) const 
try {$
	// ����������� ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ����������� ������ � ��������� Base-64
	ATL::CComBSTR bstrEncrypted; HRESULT hr = 
		BaseObject()->Encrypt(
			ATL::CComBSTR(encoded.c_str()), &bstrEncrypted
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrEncrypted); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::VerifySign(
	BSTR data, BSTR *pRetVal)
{$
	// ��������� ������� ������ � ��������� Base-64
	HRESULT hr = BaseObject()->VerifySign(data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::VerifySign(
	const void* pvData, size_t cbData) const
try {$
	// ����������� ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ��������� ������� ������ � ��������� Base-64
	ATL::CComBSTR bstrVerified; HRESULT hr = 
		BaseObject()->VerifySign(
			ATL::CComBSTR(encoded.c_str()), &bstrVerified
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrVerified); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� ������ ����
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::ToString(BSTR *pRetVal)
{$
	// ������������ ������ ����
	HRESULT hr = BaseObject()->ToString(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::PrivateKey::ToString() const
{$
	// ������������ ������ ����
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->ToString(&bstrEncoded); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ��������� �������������
	return std::wstring(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::get_Certificate(
	Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ���������� ��������� �����
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// �������� ���������� ��������� �����
	HRESULT hr = BaseObject()->get_Certificate(&pCertificate); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
	
		// ������� ���������� ��������� �����
		*pRetVal = new CAPI::COM::Certificate(pCertificate); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::PrivateKey::Certificate() const
{$
	// ���������� ��������� �����
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// �������� ���������� ��������� �����
	HRESULT hr = BaseObject()->get_Certificate(&pCertificate); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// ������� ���������� ��������� �����
	return std::shared_ptr<ICertificate>(
		new COM::Certificate(pCertificate), Deleter<COM::Certificate>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::SetCertificateContext(
	void* pCertificateContext)
{$
	// ������� �������� ����������� � ������
	HRESULT hr = BaseObject()->SetCertificateContext(pCertificateContext); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::PrivateKey::SetCertificateContext(PCCERT_CONTEXT pCertificateContext) const
{$
	// ������� �������� ����������� � ������
	HRESULT hr = BaseObject()->SetCertificateContext((void*)pCertificateContext); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::put_Authentication(
	Aladdin_CAPI_COM::IAuthentication* pAuthentication)
{$
	// ���������� ������ ��������������
	HRESULT hr = BaseObject()->put_Authentication(pAuthentication); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::put_Password(BSTR password)
{$
	// ������� ������ ����������
	HRESULT hr = BaseObject()->put_Password(password); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::PrivateKey::SetPassword(const wchar_t* szPassword)
try {$
	// ������� ������ ����������
	HRESULT hr = BaseObject()->put_Password(ATL::CComBSTR(szPassword)); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);  
}
// ���������� ��������� ������
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); }

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::Encrypt( 
	Aladdin_CAPI_COM::ICertificate* pCertificate, BSTR data, BSTR* pRetVal)
{$
	// ����������� ������ � ��������� Base-64
	HRESULT hr = BaseObject()->Encrypt(pCertificate, data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::Encrypt(
	const CAPI::ICertificate* pCertificate, 
	const void* pvData, size_t cbData) const
try {$
	// ������������� ��� �����
	Aladdin_CAPI_COM::ICertificate* pComCertificate = 
		static_cast<COM::Certificate*>(
			const_cast<CAPI::ICertificate*>(pCertificate)
	); 
	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ����������� ������ � ��������� Base-64
	ATL::CComBSTR bstrEncrypted; HRESULT hr = 
		BaseObject()->Encrypt(pComCertificate, 
			ATL::CComBSTR(encoded.c_str()), &bstrEncrypted
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrEncrypted); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::Decrypt(
	BSTR data, BSTR *pRetVal)
{$
	// ������������ ������ � ��������� Base-64
	HRESULT hr = BaseObject()->Decrypt(data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::Decrypt(
	const void* pvData, size_t cbData) const
try {$
	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ������������ ������ � ��������� Base-64
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->Decrypt( 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrDecrypted); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::SignData(
	BSTR data, BSTR *pRetVal)
{$
	// ��������� ������ � ��������� Base-64
	HRESULT hr = BaseObject()->SignData(data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
} 

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::SignData(
	const void* pvData, size_t cbData) const
try {$
	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ��������� ������ � ��������� Base-64
	ATL::CComBSTR bstrSigned; HRESULT hr = 
		BaseObject()->SignData( 
			ATL::CComBSTR(encoded.c_str()), &bstrSigned
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrSigned); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////
// ������������� ������� ����������
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::get_LCID(long *pRetVal)
{$
	// ������������� �����������
	HRESULT hr = BaseObject()->get_LCID(pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::Factory::PasswordAuthenticate(
	void* hwnd, const wchar_t* szTarget, const wchar_t* szUser, 
	size_t attempts, pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// ��������� ��������������� ����������
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// ������� ������ ���������� �������
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// ��� �������������
	WCHAR szFixedUser[] = L"USER"; if (szUser && *szUser) dwFlags |= CREDUI_FLAGS_KEEP_USERNAME; 
	else { 
		// ��������� ���� ����� ������������
		szUser = szFixedUser; dwFlags |= CREDUI_FLAGS_PASSWORD_ONLY_OK; 
	}
	// ����������� ��������� �������
	WCHAR szCaption[CREDUI_MAX_CAPTION_LENGTH + 1] = {0}; wcsncpy_s(
		szCaption, sizeof(szCaption) / sizeof(WCHAR), szTarget, wcslen(szTarget)
	); 
	// ����������� ��� ������������ 
	WCHAR szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = {0}; wcsncpy_s(
		szUserName, sizeof(szUserName) / sizeof(WCHAR), szUser, wcslen(szUser)
	); 
	// �������� ������ ��� ������
	WCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = {0}; 
	
	// ������� ��������� �������
	DWORD code = ERROR_SUCCESS; std::wstring error; 
	
	// ��� ���������� ����� �������
	for (size_t i = attempts; i != 0; i--)
	{
		// ������� ��������� ����������� /* TODO */
		CREDUI_INFOW uiInfo = { sizeof(uiInfo), (HWND)hwnd, error.c_str(), szCaption }; 

		// ��������� ������ � ������������� 
		code = ::CredUIPromptForCredentialsW(&uiInfo, szCaption, NULL, code, 
			szUserName, (DWORD)(sizeof(szUserName) / sizeof(WCHAR)),
			szPassword, (DWORD)(sizeof(szPassword) / sizeof(WCHAR)), NULL, dwFlags
		);
		// ��������� ���������� ������
		if (code == ERROR_CANCELLED) break; AE_CHECK_WINERROR(code); 
		try {
			// ��������� ������� ��������� ������
			(*pfnAuthenticate)(szTarget, szUserName, szPassword, pvData); 
			
			// ������� ��� ������������
			return szUser ? std::wstring(szUserName) : std::wstring(L"\0", 1); 
		}
		// ��� ������������� ������
		catch (const com_exception& e) { code = e.value(); error = L""; 

			// �������� ��������� �������� ������
			if (IErrorInfo* pErrorInfo = e.GetErrorInfo())
			{
				// �������� �������� ������
				BSTR bstrDescription;
				if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
				{
					// ��������� �������� �� ������
					error = bstrDescription; ::SysFreeString(bstrDescription);
				}
				// ���������� ���������
				pErrorInfo->Release(); 
			}
			// ��������� ��������� �� ������
			if (error.empty()) error = to_unicode(e.what()); if (i == 1) throw; 
		}
		// ��� ������������� ������
		catch (const system_exception& e) { code = e.value(); 

			// ��������� ��������� �� ������
			error = to_unicode(e.what()); if (i == 1) throw; 
		}
		// ��� ������������� ������
		catch (const std::exception& e) { code = E_FAIL;

			// ��������� ��������� �� ������
			error = to_unicode(e.what()); if (i == 1) throw; 
		}
	}
	// �������� ��������
	return std::wstring(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordAuthentication(
	void* hwnd, Aladdin_CAPI_COM::IAuthentication** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; if (!IsProcessInteractive())
	{
		// ��������� ��������������� ����������
		return HRESULT_FROM_WIN32(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
	}
	// ��������� ��������������
	ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

	// �������� ��������� ��������������
	HRESULT hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ��������� ��������������
		*pRetVal = pAuthentication.Detach(); return S_OK; 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::GenerateRandom(long cb, BSTR* pRetVal)
{$
	// ������������� ��������� ������
	HRESULT hr = BaseObject()->GenerateRandom(cb, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::Factory::GenerateRandom(void* pvData, size_t cbData) const
try {$
	// ��������� ������ ������
	if (cbData == 0) return; ATL::CComBSTR bstrRandom; 

	// ������������� ��������� ������
	HRESULT hr = BaseObject()->GenerateRandom((long)cbData, &bstrRandom); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������������� ��������� ������
	std::vector<BYTE> random = DecodeBase64(bstrRandom); 

	// ��������� ������ ������
	if (random.size() < cbData) AE_CHECK_WINERROR(ERROR_INVALID_STATE); 

	// ����������� ��������� ������
	memcpy(pvData, &random[0], cbData); 
}
// ��� ������������� ������ ��������� ����������
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); }

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordEncrypt(
	BSTR cultureOID, BSTR password, BSTR data, BSTR* pRetVal)
{$
	// ����������� ������ �� ������
	HRESULT hr = BaseObject()->PasswordEncrypt(cultureOID, password, data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordDecrypt(
	BSTR password, BSTR data, BSTR* pRetVal)
{$
	// ������������ ������ �� ������
	HRESULT hr = BaseObject()->PasswordDecrypt(password, data, pRetVal); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Factory::PasswordEncrypt(
	const wchar_t* szCultureOID, const wchar_t* szPassword, 
	const void* pvData, size_t cbData) const 
try {$
	// ������������ ������
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ����������� ������ �� ������
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->PasswordEncrypt( 
			ATL::CComBSTR(szCultureOID), ATL::CComBSTR(szPassword), 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrDecrypted); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

std::vector<BYTE> Aladdin::CAPI::COM::Factory::PasswordDecrypt(
	const wchar_t* szPassword, const void* pvData, size_t cbData) const 
try {$
	// ������������ ������
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ������������ ������ �� ������
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->PasswordDecrypt( 
			ATL::CComBSTR(szPassword), 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� �������� ������ �� ��������� Base-64
	return DecodeBase64(bstrDecrypted); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodeCertificate(
	BSTR encoded, Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ��������������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// ������������� ���������� �� ��������� Base-64
	HRESULT hr = BaseObject()->DecodeCertificate(encoded, &pCertificate); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ���������� ��������� �����
		*pRetVal = new Certificate(pCertificate); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::Factory::DecodeCertificate(
	const void* pvEncoded, size_t cbEncoded) const
try {$
	// ��������������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvEncoded, cbEncoded); 

	// ������������� ���������� �� ��������� Base-64
	HRESULT hr = BaseObject()->DecodeCertificate(
		ATL::CComBSTR(encoded.c_str()), &pCertificate
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// ������� ���������� ��������� �����
	return std::shared_ptr<ICertificate>(
		new Certificate(pCertificate), Deleter<Certificate>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodePrivateKey( 
	BSTR encoded, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ��������������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������������� ������ ����
	HRESULT hr = BaseObject()->DecodePrivateKey(encoded, &pPrivateKey); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ������ ������� �����
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::DecodePrivateKey(
	const wchar_t* szEncoded, void* hwnd) const
try {$
	// ��������������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������������� ������ ����
	HRESULT hr = BaseObject()->DecodePrivateKey(ATL::CComBSTR(szEncoded), &pPrivateKey); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); if (hwnd)
	{
		// ��� ���������� ����������������� ����������
		if (!IsProcessInteractive())
		{
			// ��������� ��������������� ����������
			AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
		}
		// ��������� ��������������
		ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

		// �������� ��������� ��������������
		hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

		// ��������� ���������� ������
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// ���������� ������ ��������������
		hr = pPrivateKey->put_Authentication(pAuthentication);

		// ��������� ���������� ������
		AE_CHECK_COM(pPrivateKey, __uuidof(Aladdin_CAPI_COM::IPrivateKey), hr);  
	}
	// ������� ������ ������� �����
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodePKCS12(
	BSTR encoded, BSTR password, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ��������������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������������� ������ ���� PKCS12 �� ��������� Base-64
	HRESULT hr = BaseObject()->DecodePKCS12(
		encoded, password, &pPrivateKey
	); 
	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ������ ����
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::DecodePKCS12(
	const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const
try {$
	// ��������������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvEncoded, cbEncoded); 

	// ������������� ������ ���� PKCS12 �� ��������� Base-64
	HRESULT hr = BaseObject()->DecodePKCS12(
		ATL::CComBSTR(encoded.c_str()), ATL::CComBSTR(szPassword), &pPrivateKey
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// ������� ������ ����
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::FindVerifyCertificate( 
    BSTR data, SAFEARRAY* certificates, Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ��������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// ����� ���������� ��� �������� ������� � ��������� Base-64
	HRESULT hr = BaseObject()->FindVerifyCertificate(
		data, certificates, &pCertificate
	); 
	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ��������� ����������
		*pRetVal = new Certificate(pCertificate); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::Factory::FindVerifyCertificate(
	const void* pvData, size_t cbData, 
    const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const
try {$
	// ��������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ������� ������� �������
	SAFEARRAYBOUND saBound = { (ULONG)cCertificates, 0 };

	// ������� ������
	SAFEARRAY* saEncodedCertificates = ::SafeArrayCreate(VT_BSTR, 1, &saBound); 

	// ��������� ���������� ������
	if (!saEncodedCertificates) { AE_CHECK_HRESULT(E_OUTOFMEMORY); }
	try { 
		// ��� ���� ��������� �������
		for (LONG i = 0; i < (LONG)saBound.cElements; i++)
		{
			// ������������ ����������
			std::wstring encodedCertificate = EncodeBase64(
				&pEncodedCertificates[i][0], pEncodedCertificates[i].size()
			); 
			// �������� ����� ���������� �������
			ATL::CComBSTR bstrEncodedCertificate(encodedCertificate.c_str()); 

			// ����������� �������� ��������
			AE_CHECK_HRESULT(::SafeArrayPutElement(
				saEncodedCertificates, &i, bstrEncodedCertificate
			)); 
		}
		// ����� ���������� ��� �������� ������� � ��������� Base-64
		HRESULT hr = BaseObject()->FindVerifyCertificate(
			ATL::CComBSTR(encoded.c_str()), saEncodedCertificates, &pCertificate
		); 
		// ��������� ���������� ������
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// ���������� ���������� �������
		::SafeArrayDestroy(saEncodedCertificates); 
	}
	// ���������� ���������� �������
	catch (...) { ::SafeArrayDestroy(saEncodedCertificates); throw; }

	// ������� ��������� ����������
	return std::shared_ptr<ICertificate>(
		new Certificate(pCertificate), Deleter<Certificate>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::FindDecryptPrivateKey( 
    BSTR data, SAFEARRAY* privateKeys, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ��������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ����� ������ ���� ��� ������������� ������ � ��������� Base-64
	HRESULT hr = BaseObject()->FindDecryptPrivateKey(
		data, privateKeys, &pPrivateKey
	); 
	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ��������� ����
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::FindDecryptPrivateKey(
	const void* pvData, size_t cbData, void* hwnd, 
    const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const
try {$
	// ��������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������������ ������ � ��������� Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// ������� ������� �������
	SAFEARRAYBOUND saBound = { (ULONG)cPrivateKeys, 0 };

	// ������� ������
	SAFEARRAY* saEncodedKeys = ::SafeArrayCreate(VT_BSTR, 1, &saBound); 

	// ��������� ���������� ������
	if (!saEncodedKeys) { AE_CHECK_HRESULT(E_OUTOFMEMORY); }
	try { 
		// ��� ���� ��������� �������
		for (LONG i = 0; i < (LONG)saBound.cElements; i++)
		{
			// �������� ����� ���������� �������
			ATL::CComBSTR bstrEncodedKey(pEncodedPrivateKeys[i].c_str()); 

			// ����������� �������� ��������
			AE_CHECK_HRESULT(::SafeArrayPutElement(saEncodedKeys, &i, bstrEncodedKey)); 
		}
		// ����� ������ ���� ��� ������������� ������ � ��������� Base-64
		HRESULT hr = BaseObject()->FindDecryptPrivateKey(
			ATL::CComBSTR(encoded.c_str()), saEncodedKeys, &pPrivateKey
		); 
		// ��������� ���������� ������
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// ���������� ���������� �������
		::SafeArrayDestroy(saEncodedKeys); if (hwnd)
		{
			// ��� ���������� ����������������� ����������
			if (!IsProcessInteractive())
			{
				// ��������� ��������������� ����������
				AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
			}
			// ��������� ��������������
			ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

			// �������� ��������� ��������������
			hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

			// ��������� ���������� ������
			AE_CHECK_COM(BaseObject(), GetIID(), hr); 

			// ���������� ������ ��������������
			hr = pPrivateKey->put_Authentication(pAuthentication);

			// ��������� ���������� ������
			AE_CHECK_COM(pPrivateKey, __uuidof(Aladdin_CAPI_COM::IPrivateKey), hr);  
		}
	}
	// ���������� ���������� �������
	catch (...) { ::SafeArrayDestroy(saEncodedKeys); throw; }

	// ������� ��������� ����
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::EnumeratePrivateKeys( 
    void* hwnd, Aladdin_CAPI_COM::KeyUsage keyUsage, 
	VARIANT_BOOL systemOnly, SAFEARRAY** pRetVal)
{$
	// ����������� ������ �����
	HRESULT hr = BaseObject()->EnumeratePrivateKeys(
		hwnd, keyUsage, systemOnly, pRetVal
	); 
	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::vector<std::wstring> Aladdin::CAPI::COM::Factory::EnumeratePrivateKeys(
	void* hwnd, bool systemOnly) const
{$
	// ����������� ������ �����
	SAFEARRAY* saEncodedKeys; HRESULT hr = 
		BaseObject()->EnumeratePrivateKeys(hwnd, 
			Aladdin_CAPI_COM::KeyUsage::None, systemOnly, &saEncodedKeys
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);
	try {
		// ���������� ����������� �������
		LONG lBound; LONG uBound; 
		AE_CHECK_HRESULT(::SafeArrayGetLBound(saEncodedKeys, 1, &lBound));
		AE_CHECK_HRESULT(::SafeArrayGetUBound(saEncodedKeys, 1, &uBound));

		// �������� ������ ���������� �������
		std::vector<std::wstring> encodedKeys(uBound - lBound + 1); 

		// ��� ���� ������ ������
		for (LONG i = lBound; i <= uBound; i++)
		{
			// �������� �������� ������� �����
			ATL::CComBSTR bstrEncodedKey; 
			AE_CHECK_HRESULT(::SafeArrayGetElement(saEncodedKeys, &i, &bstrEncodedKey)); 

			// ��������� �������������� �������������
			encodedKeys[i - lBound] = bstrEncodedKey; 
		}
		// ���������� ���������� �������
		::SafeArrayDestroy(saEncodedKeys); return encodedKeys; 
	}
	// ���������� ��������� ����������
	catch(...) { ::SafeArrayDestroy(saEncodedKeys); throw; }
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::SelectPrivateKeySSL( 
    void* hwnd, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; if (!IsProcessInteractive())
	{
		// ��������� ��������������� ����������
		return HRESULT_FROM_WIN32(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
	}
	// ��������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ������� ������ ���� 
	HRESULT hr = BaseObject()->SelectPrivateKeySSL(hwnd, &pPrivateKey); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ��������� ����
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// ��������� ��������������� ����������
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// ��������� ������ ����
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// ����� ������ ����
	HRESULT hr = BaseObject()->SelectPrivateKeySSL(hwnd, &pPrivateKey); 

	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// ������� ��������� ����
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}

std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::COM::Factory::Marshal() const 
{
	// �������� ������ ������� GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	AE_CHECK_HRESULT(pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	)); 
	// �������� ������ �� ������� �����������
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	HRESULT hr = pGIT->GetInterfaceFromGlobal(
		dwCookie, __uuidof(Aladdin_CAPI_COM::IFactory), (void**)&pFactory
	); 
	// ��������� ���������� ������ 
	AE_CHECK_COM(pGIT, __uuidof(IGlobalInterfaceTable), hr);

	// ������� ��������� �������
	return std::shared_ptr<Aladdin::CAPI::IFactory>(
		new Factory(pFactory, dwCookie), Deleter<Factory>()
	); 
}

///////////////////////////////////////////////////////////////////////////
// ����� ����� � ����������� ���
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Entry::CreateFactory( 
	LCID lcid, BSTR fileName, Aladdin_CAPI_COM::IFactory** pRetVal)
{$
	// ��������� ������� ���������
	if (!pRetVal) return E_POINTER; 

	// ����������� ������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 

	// ������� ������� ����������	
	HRESULT hr = BaseObject()->CreateFactory(lcid, fileName, &pFactory); 

	// ��������� ���������� ������
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// ������� ��������� �������
		*pRetVal = new Factory(pFactory); 
	} 
	// ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IFactory> 
Aladdin::CAPI::COM::Entry::CreateFactory(
	LCID lcid, PCWSTR szFileName) const 
try {$
	// ����������� ������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 

	// ������� ������� ����������	
	HRESULT hr = BaseObject()->CreateFactory(
		lcid, ATL::CComBSTR(szFileName), &pFactory
	); 
	// ��������� ���������� ������
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// ������� ��������� �������
	return std::shared_ptr<IFactory>(
		new Factory(pFactory), Deleter<Factory>()
	); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ����������
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::ClassFactoryNET::CreateInstance( 
    IUnknown* pUnkFactory, REFIID riid, void** ppvObject)
{$
	// ������� ������� �������
	HRESULT hr = base_type::CreateInstance(pUnkFactory, riid, ppvObject); if (FAILED(hr)) return hr; 

    // ��������� ���������� ��������������
    if (!InlineIsEqualGUID(riid, __uuidof(Aladdin_CAPI_COM::IEntry))) return hr; 
	try {
	    // ������� ��������������� ������
		Entry* pEntry = new Entry((Aladdin_CAPI_COM::IEntry*)(IUnknown*)*ppvObject); 

		// ������� ��������������� ������
		((IUnknown*)*ppvObject)->Release(); *ppvObject = pEntry; return hr; 
	}
	// ���������� ��������� ������
	catch (const windows_exception& e) { hr = e.value(); } catch (...) { hr = E_FAIL; }

	// ���������� ���������� �������
	((IUnknown*)*ppvObject)->Release(); return hr; 
}
