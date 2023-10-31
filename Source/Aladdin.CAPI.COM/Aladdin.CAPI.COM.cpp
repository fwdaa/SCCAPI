#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp" 
#include <atlenc.h>

///////////////////////////////////////////////////////////////////////////////
// Определения Windows
///////////////////////////////////////////////////////////////////////////////
#include <wincred.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "credui.lib" )
#pragma comment(lib, "Aladdin.CAPI.COM.lib" )

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.COM.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Признак интерактивности приложения
///////////////////////////////////////////////////////////////////////////////
static bool IsProcessInteractive()
{
	// получить рабочий стол приложения
	HWINSTA hStation = ::GetProcessWindowStation();

	// проверить наличие рабочего стола
	if (hStation == NULL) return true; USEROBJECTFLAGS uof = { 0 };

	// получить свойства рабочего стола
	if (::GetUserObjectInformationW(hStation, UOI_FLAGS, 
		&uof, sizeof(USEROBJECTFLAGS), nullptr))
	{
		// проверить неинтерактивность рабочего стола
		if ((uof.dwFlags & WSF_VISIBLE) == 0) return false;
	}
	return true;
}
///////////////////////////////////////////////////////////////////////////////
// Реализация IUnknown
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
Aladdin::CAPI::COM::UnknownObject<Interface>::UnknownObject(
	Interface* pObject, bool registerGIT) : dwCookieGIT(0)
{
	// сохранить переданные параметры 
	this->pObject = pObject; cRef = 1; if (!registerGIT) return; 

	// получить объект таблицы GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	AE_CHECK_HRESULT(pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	)); 
	// зарегистрировать объект в таблице 
	AE_CHECK_HRESULT(pGIT->RegisterInterfaceInGlobal(
		pObject, GetIID(), &dwCookieGIT
	)); 
}

template <class Interface>
Aladdin::CAPI::COM::UnknownObject<Interface>::~UnknownObject() 
{ 
	// проверить необходимость удаления из таблицы 
	ATLASSERT(cRef == 1); if (dwCookieGIT == 0) return; 

	// получить объект таблицы GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	HRESULT hr = pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	); 
	// отменить регистрацию объекта 
	if (SUCCEEDED(hr)) pGIT->RevokeInterfaceFromGlobal(dwCookieGIT); 
}

///////////////////////////////////////////////////////////////////////////////
// Вызов Dispose при освобождении объекта
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetTypeInfoCount(
	UINT *pctinfo)
{$
	// вызвать базовый метод
	HRESULT hr = BaseObject()->GetTypeInfoCount(pctinfo); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetTypeInfo( 
	UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo)
{$
	// вызвать базовый метод
	HRESULT hr = BaseObject()->GetTypeInfo(iTInfo, lcid, ppTInfo); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::GetIDsOfNames( 
	REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId)
{$
	// вызвать базовый метод
	HRESULT hr = BaseObject()->GetIDsOfNames(riid, rgszNames, cNames, lcid, rgDispId); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

template <class Interface>
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DispatchObject<Interface>::Invoke( 
	DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, 
	DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr)
{$
	// вызвать базовый метод
	HRESULT hr = BaseObject()->Invoke(dispIdMember, riid, 
		lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr
	); 
	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), IID_IDispatch, hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

///////////////////////////////////////////////////////////////////////////
// Отличимое имя
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DistinctName::get_Encoded(BSTR* pRetVal)
{$
	// закодировать отличимое имя в кодировку Base-64
	HRESULT hr = BaseObject()->get_Encoded(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::DistinctName::Encoded() const
{$
	// закодировать отличимое имя в кодировку Base-64
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->get_Encoded(&bstrEncoded); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::DistinctName::ToString(BSTR* pRetVal)
{$
	// получить строковое представление отличимого имени
	HRESULT hr = BaseObject()->ToString(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::DistinctName::ToString() const
{$
	// получить строковое представление отличимого имени
	ATL::CComBSTR bstrName; HRESULT hr = BaseObject()->ToString(&bstrName); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть строковое представление
	return std::wstring(bstrName); 
}

///////////////////////////////////////////////////////////////////////////////
// Освобождаемый сертификат
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Encoded(BSTR *pRetVal)
{$
	// закодировать сертификат в кодировку Base-64
	HRESULT hr = BaseObject()->get_Encoded(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::Encoded() const
{
	// закодировать сертификат в кодировку Base-64
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->get_Encoded(&bstrEncoded); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Issuer(
	Aladdin_CAPI_COM::IDistinctName** pRetVal)
{$
	// получить издателя сертификата
	HRESULT hr = BaseObject()->get_Issuer(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::COM::Certificate::Issuer() const
{$
	// получить издателя сертификата
	ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> pName; 
	HRESULT hr = BaseObject()->get_Issuer(&pName); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть имя издателя
	return std::shared_ptr<IDistinctName>(
		new DistinctName(pName), Deleter<DistinctName>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_Subject(
	Aladdin_CAPI_COM::IDistinctName** pRetVal)
{$
	// получить субъекта сертификата
	HRESULT hr = BaseObject()->get_Subject(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IDistinctName> 
Aladdin::CAPI::COM::Certificate::Subject() const
{$
	// получить субъекта сертификата
	ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> pName; 
	HRESULT hr = BaseObject()->get_Subject(&pName); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть имя субъекта
	return std::shared_ptr<IDistinctName>(
		new DistinctName(pName), Deleter<DistinctName>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_KeyOID(BSTR* pRetVal)
{$
	// получить идентификатор (OID) ключа
	HRESULT hr = BaseObject()->get_KeyOID(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::get_KeyUsage(
	Aladdin_CAPI_COM::KeyUsage *pRetVal)
{$
	// получить способ использования ключа
	HRESULT hr = BaseObject()->get_KeyUsage(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::Certificate::KeyOID() const
try {$
	// получить идентификатор (OID) ключа
	ATL::CComBSTR bstrKeyOID;  
	HRESULT hr = BaseObject()->get_KeyOID(&bstrKeyOID); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
	
	// вернуть идентификатор ключа
	return std::wstring(bstrKeyOID); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::wstring(); 
}

Aladdin::CAPI::KeyUsage Aladdin::CAPI::COM::Certificate::KeyUsage() const
{$
	// получить способ использования ключа
	Aladdin_CAPI_COM::KeyUsage keyUsage; 
	HRESULT hr = BaseObject()->get_KeyUsage(&keyUsage); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть назначение ключа
	return static_cast<CAPI::KeyUsage>(keyUsage); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::Encrypt(
	BSTR data, BSTR *pRetVal)
{$
	// зашифровать данные в кодировке Base-64
	HRESULT hr = BaseObject()->Encrypt(data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::Encrypt(
	const void* pvData, size_t cbData) const 
try {$
	// закодироать данные в кодировку Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// зашифровать данные в кодировке Base-64
	ATL::CComBSTR bstrEncrypted; HRESULT hr = 
		BaseObject()->Encrypt(
			ATL::CComBSTR(encoded.c_str()), &bstrEncrypted
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrEncrypted); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Certificate::VerifySign(
	BSTR data, BSTR *pRetVal)
{$
	// проверить подпись данных в кодировке Base-64
	HRESULT hr = BaseObject()->VerifySign(data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Certificate::VerifySign(
	const void* pvData, size_t cbData) const
try {$
	// закодироать данные в кодировку Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// проверить подпись данных в кодировке Base-64
	ATL::CComBSTR bstrVerified; HRESULT hr = 
		BaseObject()->VerifySign(
			ATL::CComBSTR(encoded.c_str()), &bstrVerified
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrVerified); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////////
// Освобождаемый личный ключ
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::ToString(BSTR *pRetVal)
{$
	// закодировать личный ключ
	HRESULT hr = BaseObject()->ToString(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::PrivateKey::ToString() const
{$
	// закодировать личный ключ
	ATL::CComBSTR bstrEncoded; HRESULT hr = BaseObject()->ToString(&bstrEncoded); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть строковое представление
	return std::wstring(bstrEncoded); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::get_Certificate(
	Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// сертификат открытого ключа
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// получить сертификат открытого ключа
	HRESULT hr = BaseObject()->get_Certificate(&pCertificate); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
	
		// вернуть сертификат открытого ключа
		*pRetVal = new CAPI::COM::Certificate(pCertificate); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::PrivateKey::Certificate() const
{$
	// сертификат открытого ключа
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// получить сертификат открытого ключа
	HRESULT hr = BaseObject()->get_Certificate(&pCertificate); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 

	// вернуть сертификат открытого ключа
	return std::shared_ptr<ICertificate>(
		new COM::Certificate(pCertificate), Deleter<COM::Certificate>()
	); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::SetCertificateContext(
	void* pCertificateContext)
{$
	// связать контекст сертификата с ключом
	HRESULT hr = BaseObject()->SetCertificateContext(pCertificateContext); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::PrivateKey::SetCertificateContext(PCCERT_CONTEXT pCertificateContext) const
{$
	// связать контекст сертификата с ключом
	HRESULT hr = BaseObject()->SetCertificateContext((void*)pCertificateContext); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::put_Authentication(
	Aladdin_CAPI_COM::IAuthentication* pAuthentication)
{$
	// установить способ аутентификации
	HRESULT hr = BaseObject()->put_Authentication(pAuthentication); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::put_Password(BSTR password)
{$
	// указать пароль контейнера
	HRESULT hr = BaseObject()->put_Password(password); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::PrivateKey::SetPassword(const wchar_t* szPassword)
try {$
	// указать пароль контейнера
	HRESULT hr = BaseObject()->put_Password(ATL::CComBSTR(szPassword)); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);  
}
// обработать возможную ошибку
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); }

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::Encrypt( 
	Aladdin_CAPI_COM::ICertificate* pCertificate, BSTR data, BSTR* pRetVal)
{$
	// зашифровать данные в кодировке Base-64
	HRESULT hr = BaseObject()->Encrypt(pCertificate, data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::Encrypt(
	const CAPI::ICertificate* pCertificate, 
	const void* pvData, size_t cbData) const
try {$
	// преобразовать тип ключа
	Aladdin_CAPI_COM::ICertificate* pComCertificate = 
		static_cast<COM::Certificate*>(
			const_cast<CAPI::ICertificate*>(pCertificate)
	); 
	// закодировать данные в кодировку Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// зашифровать данные в кодировке Base-64
	ATL::CComBSTR bstrEncrypted; HRESULT hr = 
		BaseObject()->Encrypt(pComCertificate, 
			ATL::CComBSTR(encoded.c_str()), &bstrEncrypted
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrEncrypted); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::Decrypt(
	BSTR data, BSTR *pRetVal)
{$
	// расшифровать данные в кодировке Base-64
	HRESULT hr = BaseObject()->Decrypt(data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::Decrypt(
	const void* pvData, size_t cbData) const
try {$
	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// расшифровать данные в кодировке Base-64
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->Decrypt( 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrDecrypted); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::PrivateKey::SignData(
	BSTR data, BSTR *pRetVal)
{$
	// подписать данные в кодировке Base-64
	HRESULT hr = BaseObject()->SignData(data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
} 

std::vector<BYTE> Aladdin::CAPI::COM::PrivateKey::SignData(
	const void* pvData, size_t cbData) const
try {$
	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// подписать данные в кодировке Base-64
	ATL::CComBSTR bstrSigned; HRESULT hr = 
		BaseObject()->SignData( 
			ATL::CComBSTR(encoded.c_str()), &bstrSigned
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrSigned); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////
// Освобождаемая фабрика алгоритмов
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::get_LCID(long *pRetVal)
{$
	// идентификатор локализации
	HRESULT hr = BaseObject()->get_LCID(pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::wstring Aladdin::CAPI::COM::Factory::PasswordAuthenticate(
	void* hwnd, const wchar_t* szTarget, const wchar_t* szUser, 
	size_t attempts, pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// проверить интерактивность приложения
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// указать способ выполнения функции
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// при необходимости
	WCHAR szFixedUser[] = L"USER"; if (szUser && *szUser) dwFlags |= CREDUI_FLAGS_KEEP_USERNAME; 
	else { 
		// запретить ввод имени пользователя
		szUser = szFixedUser; dwFlags |= CREDUI_FLAGS_PASSWORD_ONLY_OK; 
	}
	// скопировать заголовок диалога
	WCHAR szCaption[CREDUI_MAX_CAPTION_LENGTH + 1] = {0}; wcsncpy_s(
		szCaption, sizeof(szCaption) / sizeof(WCHAR), szTarget, wcslen(szTarget)
	); 
	// скопировать имя пользователя 
	WCHAR szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = {0}; wcsncpy_s(
		szUserName, sizeof(szUserName) / sizeof(WCHAR), szUser, wcslen(szUser)
	); 
	// выделить память для пароля
	WCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = {0}; 
	
	// указать начальные условия
	DWORD code = ERROR_SUCCESS; std::wstring error; 
	
	// для указанного числа попыток
	for (size_t i = attempts; i != 0; i--)
	{
		// указать параметры отображения /* TODO */
		CREDUI_INFOW uiInfo = { sizeof(uiInfo), (HWND)hwnd, error.c_str(), szCaption }; 

		// выполнить диалог с пользователем 
		code = ::CredUIPromptForCredentialsW(&uiInfo, szCaption, NULL, code, 
			szUserName, (DWORD)(sizeof(szUserName) / sizeof(WCHAR)),
			szPassword, (DWORD)(sizeof(szPassword) / sizeof(WCHAR)), NULL, dwFlags
		);
		// проверить отсутствие ошибок
		if (code == ERROR_CANCELLED) break; AE_CHECK_WINERROR(code); 
		try {
			// выполнить функцию обратного вызова
			(*pfnAuthenticate)(szTarget, szUserName, szPassword, pvData); 
			
			// вернуть имя пользователя
			return szUser ? std::wstring(szUserName) : std::wstring(L"\0", 1); 
		}
		// при возникновении ошибки
		catch (const com_exception& e) { code = e.value(); error = L""; 

			// получить интерфейс описания ошибки
			if (IErrorInfo* pErrorInfo = e.GetErrorInfo())
			{
				// получить описание ошибки
				BSTR bstrDescription;
				if (SUCCEEDED(pErrorInfo->GetDescription(&bstrDescription)))
				{
					// сохранить сообщеие об ошибке
					error = bstrDescription; ::SysFreeString(bstrDescription);
				}
				// освободить интерфейс
				pErrorInfo->Release(); 
			}
			// сохранить сообщение об ошибке
			if (error.empty()) error = to_unicode(e.what()); if (i == 1) throw; 
		}
		// при возникновении ошибки
		catch (const system_exception& e) { code = e.value(); 

			// сохранить сообщение об ошибке
			error = to_unicode(e.what()); if (i == 1) throw; 
		}
		// при возникновении ошибки
		catch (const std::exception& e) { code = E_FAIL;

			// сохранить сообщение об ошибке
			error = to_unicode(e.what()); if (i == 1) throw; 
		}
	}
	// операция отменена
	return std::wstring(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordAuthentication(
	void* hwnd, Aladdin_CAPI_COM::IAuthentication** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; if (!IsProcessInteractive())
	{
		// проверить интерактивность приложения
		return HRESULT_FROM_WIN32(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
	}
	// парольная аутентификация
	ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

	// получить парольную аутентификацию
	HRESULT hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть парольную аутентификацию
		*pRetVal = pAuthentication.Detach(); return S_OK; 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::GenerateRandom(long cb, BSTR* pRetVal)
{$
	// сгенерировать случайные данные
	HRESULT hr = BaseObject()->GenerateRandom(cb, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

void Aladdin::CAPI::COM::Factory::GenerateRandom(void* pvData, size_t cbData) const
try {$
	// проверить размер данных
	if (cbData == 0) return; ATL::CComBSTR bstrRandom; 

	// сгенерировать случайные данные
	HRESULT hr = BaseObject()->GenerateRandom((long)cbData, &bstrRandom); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// раскодировать случайные данные
	std::vector<BYTE> random = DecodeBase64(bstrRandom); 

	// проверить размер данных
	if (random.size() < cbData) AE_CHECK_WINERROR(ERROR_INVALID_STATE); 

	// скопировать случайные данные
	memcpy(pvData, &random[0], cbData); 
}
// при возникновении ошибки выбросить исключение
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); }

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordEncrypt(
	BSTR cultureOID, BSTR password, BSTR data, BSTR* pRetVal)
{$
	// зашифровать данные на пароле
	HRESULT hr = BaseObject()->PasswordEncrypt(cultureOID, password, data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::PasswordDecrypt(
	BSTR password, BSTR data, BSTR* pRetVal)
{$
	// расшифровать данные на пароле
	HRESULT hr = BaseObject()->PasswordDecrypt(password, data, pRetVal); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<BYTE> Aladdin::CAPI::COM::Factory::PasswordEncrypt(
	const wchar_t* szCultureOID, const wchar_t* szPassword, 
	const void* pvData, size_t cbData) const 
try {$
	// закодировать данные
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// зашифровать данные на пароле
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->PasswordEncrypt( 
			ATL::CComBSTR(szCultureOID), ATL::CComBSTR(szPassword), 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrDecrypted); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

std::vector<BYTE> Aladdin::CAPI::COM::Factory::PasswordDecrypt(
	const wchar_t* szPassword, const void* pvData, size_t cbData) const 
try {$
	// закодировать данные
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// расшифровать данные на пароле
	ATL::CComBSTR bstrDecrypted; HRESULT hr = 
		BaseObject()->PasswordDecrypt( 
			ATL::CComBSTR(szPassword), 
			ATL::CComBSTR(encoded.c_str()), &bstrDecrypted
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// извлечь бинарные данные из кодировки Base-64
	return DecodeBase64(bstrDecrypted); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodeCertificate(
	BSTR encoded, Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// раскодированный сертификат
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// раскодировать сертификат из кодировки Base-64
	HRESULT hr = BaseObject()->DecodeCertificate(encoded, &pCertificate); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть сертификат открытого ключа
		*pRetVal = new Certificate(pCertificate); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::Factory::DecodeCertificate(
	const void* pvEncoded, size_t cbEncoded) const
try {$
	// раскодированный сертификат
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvEncoded, cbEncoded); 

	// раскодировать сертификат из кодировки Base-64
	HRESULT hr = BaseObject()->DecodeCertificate(
		ATL::CComBSTR(encoded.c_str()), &pCertificate
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// вернуть сертификат открытого ключа
	return std::shared_ptr<ICertificate>(
		new Certificate(pCertificate), Deleter<Certificate>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodePrivateKey( 
	BSTR encoded, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// раскодированный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// раскодировать личный ключ
	HRESULT hr = BaseObject()->DecodePrivateKey(encoded, &pPrivateKey); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть объект личного ключа
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::DecodePrivateKey(
	const wchar_t* szEncoded, void* hwnd) const
try {$
	// раскодированный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// раскодировать личный ключ
	HRESULT hr = BaseObject()->DecodePrivateKey(ATL::CComBSTR(szEncoded), &pPrivateKey); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); if (hwnd)
	{
		// при отсутствии пользовательского интерфейса
		if (!IsProcessInteractive())
		{
			// проверить интерактивность приложения
			AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
		}
		// парольная аутентификация
		ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

		// получить парольную аутентификацию
		hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

		// проверить отсутствие ошибок
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// установить способ аутентификации
		hr = pPrivateKey->put_Authentication(pAuthentication);

		// проверить отсутствие ошибок
		AE_CHECK_COM(pPrivateKey, __uuidof(Aladdin_CAPI_COM::IPrivateKey), hr);  
	}
	// вернуть объект личного ключа
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::DecodePKCS12(
	BSTR encoded, BSTR password, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// раскодированный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// раскодировать личный ключ PKCS12 из кодировки Base-64
	HRESULT hr = BaseObject()->DecodePKCS12(
		encoded, password, &pPrivateKey
	); 
	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть личный ключ
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::DecodePKCS12(
	const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const
try {$
	// раскодированный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvEncoded, cbEncoded); 

	// раскодировать личный ключ PKCS12 из кодировки Base-64
	HRESULT hr = BaseObject()->DecodePKCS12(
		ATL::CComBSTR(encoded.c_str()), ATL::CComBSTR(szPassword), &pPrivateKey
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// вернуть личный ключ
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::FindVerifyCertificate( 
    BSTR data, SAFEARRAY* certificates, Aladdin_CAPI_COM::ICertificate** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// найденный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// найти сертификат для проверки подписи в кодировке Base-64
	HRESULT hr = BaseObject()->FindVerifyCertificate(
		data, certificates, &pCertificate
	); 
	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть найденный сертификат
		*pRetVal = new Certificate(pCertificate); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::ICertificate> 
Aladdin::CAPI::COM::Factory::FindVerifyCertificate(
	const void* pvData, size_t cbData, 
    const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const
try {$
	// найденный сертификат
	ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> pCertificate; 

	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// указать границы массива
	SAFEARRAYBOUND saBound = { (ULONG)cCertificates, 0 };

	// создать массив
	SAFEARRAY* saEncodedCertificates = ::SafeArrayCreate(VT_BSTR, 1, &saBound); 

	// проверить отсутствие ошибок
	if (!saEncodedCertificates) { AE_CHECK_HRESULT(E_OUTOFMEMORY); }
	try { 
		// для всех элементов массива
		for (LONG i = 0; i < (LONG)saBound.cElements; i++)
		{
			// закодировать сертификат
			std::wstring encodedCertificate = EncodeBase64(
				&pEncodedCertificates[i][0], pEncodedCertificates[i].size()
			); 
			// выделить буфер требуемого размера
			ATL::CComBSTR bstrEncodedCertificate(encodedCertificate.c_str()); 

			// скопировать значение элемента
			AE_CHECK_HRESULT(::SafeArrayPutElement(
				saEncodedCertificates, &i, bstrEncodedCertificate
			)); 
		}
		// найти сертификат для проверки подписи в кодировке Base-64
		HRESULT hr = BaseObject()->FindVerifyCertificate(
			ATL::CComBSTR(encoded.c_str()), saEncodedCertificates, &pCertificate
		); 
		// проверить отсутствие ошибок
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// освободить выделенные ресурсы
		::SafeArrayDestroy(saEncodedCertificates); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::SafeArrayDestroy(saEncodedCertificates); throw; }

	// вернуть найденный сертификат
	return std::shared_ptr<ICertificate>(
		new Certificate(pCertificate), Deleter<Certificate>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::FindDecryptPrivateKey( 
    BSTR data, SAFEARRAY* privateKeys, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// найденный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// найти личный ключ для расшифрования данных в кодировке Base-64
	HRESULT hr = BaseObject()->FindDecryptPrivateKey(
		data, privateKeys, &pPrivateKey
	); 
	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть найденный ключ
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::FindDecryptPrivateKey(
	const void* pvData, size_t cbData, void* hwnd, 
    const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const
try {$
	// найденный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// закодировать данные в кодировке Base-64
	std::wstring encoded = EncodeBase64(pvData, cbData); 

	// указать границы массива
	SAFEARRAYBOUND saBound = { (ULONG)cPrivateKeys, 0 };

	// создать массив
	SAFEARRAY* saEncodedKeys = ::SafeArrayCreate(VT_BSTR, 1, &saBound); 

	// проверить отсутствие ошибок
	if (!saEncodedKeys) { AE_CHECK_HRESULT(E_OUTOFMEMORY); }
	try { 
		// для всех элементов массива
		for (LONG i = 0; i < (LONG)saBound.cElements; i++)
		{
			// выделить буфер требуемого размера
			ATL::CComBSTR bstrEncodedKey(pEncodedPrivateKeys[i].c_str()); 

			// скопировать значение элемента
			AE_CHECK_HRESULT(::SafeArrayPutElement(saEncodedKeys, &i, bstrEncodedKey)); 
		}
		// найти личный ключ для расшифрования данных в кодировке Base-64
		HRESULT hr = BaseObject()->FindDecryptPrivateKey(
			ATL::CComBSTR(encoded.c_str()), saEncodedKeys, &pPrivateKey
		); 
		// проверить отсутствие ошибок
		AE_CHECK_COM(BaseObject(), GetIID(), hr); 

		// освободить выделенные ресурсы
		::SafeArrayDestroy(saEncodedKeys); if (hwnd)
		{
			// при отсутствии пользовательского интерфейса
			if (!IsProcessInteractive())
			{
				// проверить интерактивность приложения
				AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
			}
			// парольная аутентификация
			ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> pAuthentication; 

			// получить парольную аутентификацию
			hr = BaseObject()->PasswordAuthentication(hwnd, &pAuthentication); 

			// проверить отсутствие ошибок
			AE_CHECK_COM(BaseObject(), GetIID(), hr); 

			// установить способ аутентификации
			hr = pPrivateKey->put_Authentication(pAuthentication);

			// проверить отсутствие ошибок
			AE_CHECK_COM(pPrivateKey, __uuidof(Aladdin_CAPI_COM::IPrivateKey), hr);  
		}
	}
	// освободить выделенные ресурсы
	catch (...) { ::SafeArrayDestroy(saEncodedKeys); throw; }

	// вернуть найденный ключ
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::EnumeratePrivateKeys( 
    void* hwnd, Aladdin_CAPI_COM::KeyUsage keyUsage, 
	VARIANT_BOOL systemOnly, SAFEARRAY** pRetVal)
{$
	// перечислить личные ключи
	HRESULT hr = BaseObject()->EnumeratePrivateKeys(
		hwnd, keyUsage, systemOnly, pRetVal
	); 
	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); } 

	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::vector<std::wstring> Aladdin::CAPI::COM::Factory::EnumeratePrivateKeys(
	void* hwnd, bool systemOnly) const
{$
	// перечислить личные ключи
	SAFEARRAY* saEncodedKeys; HRESULT hr = 
		BaseObject()->EnumeratePrivateKeys(hwnd, 
			Aladdin_CAPI_COM::KeyUsage::None, systemOnly, &saEncodedKeys
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);
	try {
		// определить размерность массива
		LONG lBound; LONG uBound; 
		AE_CHECK_HRESULT(::SafeArrayGetLBound(saEncodedKeys, 1, &lBound));
		AE_CHECK_HRESULT(::SafeArrayGetUBound(saEncodedKeys, 1, &uBound));

		// выделить список требуемого размера
		std::vector<std::wstring> encodedKeys(uBound - lBound + 1); 

		// для всех личных ключей
		for (LONG i = lBound; i <= uBound; i++)
		{
			// получить описание личного ключа
			ATL::CComBSTR bstrEncodedKey; 
			AE_CHECK_HRESULT(::SafeArrayGetElement(saEncodedKeys, &i, &bstrEncodedKey)); 

			// сохранить закодированное представление
			encodedKeys[i - lBound] = bstrEncodedKey; 
		}
		// освободить выделенные ресурсы
		::SafeArrayDestroy(saEncodedKeys); return encodedKeys; 
	}
	// обработать возможное исключение
	catch(...) { ::SafeArrayDestroy(saEncodedKeys); throw; }
}

HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Factory::SelectPrivateKeySSL( 
    void* hwnd, Aladdin_CAPI_COM::IPrivateKey** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; if (!IsProcessInteractive())
	{
		// проверить интерактивность приложения
		return HRESULT_FROM_WIN32(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION); 
	}
	// выбранный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// выбрать личный ключ 
	HRESULT hr = BaseObject()->SelectPrivateKeySSL(hwnd, &pPrivateKey); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть выбранный ключ
		*pRetVal = new PrivateKey(pPrivateKey); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::COM::Factory::SelectPrivateKeySSL(void* hwnd) const
{$
	// проверить интерактивность приложения
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// найденный личный ключ
	ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> pPrivateKey; 

	// найти личный ключ
	HRESULT hr = BaseObject()->SelectPrivateKeySSL(hwnd, &pPrivateKey); 

	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr);

	// вернуть выбранный ключ
	return std::shared_ptr<IPrivateKey>(
		new PrivateKey(pPrivateKey), Deleter<PrivateKey>()
	); 
}

std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::COM::Factory::Marshal() const 
{
	// получить объект таблицы GIT
	ATL::CComPtr<IGlobalInterfaceTable> pGIT; 
	AE_CHECK_HRESULT(pGIT.CoCreateInstance(
		CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER
	)); 
	// получить объект из таблицы интерфейсов
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	HRESULT hr = pGIT->GetInterfaceFromGlobal(
		dwCookie, __uuidof(Aladdin_CAPI_COM::IFactory), (void**)&pFactory
	); 
	// проверить отсутствие ошибок 
	AE_CHECK_COM(pGIT, __uuidof(IGlobalInterfaceTable), hr);

	// вернуть созданную фабрику
	return std::shared_ptr<Aladdin::CAPI::IFactory>(
		new Factory(pFactory, dwCookie), Deleter<Factory>()
	); 
}

///////////////////////////////////////////////////////////////////////////
// Точка входа в управляемый код
///////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::Entry::CreateFactory( 
	LCID lcid, BSTR fileName, Aladdin_CAPI_COM::IFactory** pRetVal)
{$
	// проверить наличие указателя
	if (!pRetVal) return E_POINTER; 

	// создаваемая фабрика алгоритмов
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 

	// создать фабрику алгоритмов	
	HRESULT hr = BaseObject()->CreateFactory(lcid, fileName, &pFactory); 

	// проверить отсутствие ошибок
	try { AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
		// вернуть созданную фабрику
		*pRetVal = new Factory(pFactory); 
	} 
	// обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}

std::shared_ptr<Aladdin::CAPI::IFactory> 
Aladdin::CAPI::COM::Entry::CreateFactory(
	LCID lcid, PCWSTR szFileName) const 
try {$
	// создаваемая фабрика алгоритмов
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 

	// создать фабрику алгоритмов	
	HRESULT hr = BaseObject()->CreateFactory(
		lcid, ATL::CComBSTR(szFileName), &pFactory
	); 
	// проверить отсутствие ошибок
	AE_CHECK_COM(BaseObject(), GetIID(), hr); 
		
	// вернуть созданную фабрику
	return std::shared_ptr<IFactory>(
		new Factory(pFactory), Deleter<Factory>()
	); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика компонента
///////////////////////////////////////////////////////////////////////////////
HRESULT STDMETHODCALLTYPE Aladdin::CAPI::COM::ClassFactoryNET::CreateInstance( 
    IUnknown* pUnkFactory, REFIID riid, void** ppvObject)
{$
	// вызвать базовую функцию
	HRESULT hr = base_type::CreateInstance(pUnkFactory, riid, ppvObject); if (FAILED(hr)) return hr; 

    // проверить совпадение идентификатора
    if (!InlineIsEqualGUID(riid, __uuidof(Aladdin_CAPI_COM::IEntry))) return hr; 
	try {
	    // указать перехватывающий объект
		Entry* pEntry = new Entry((Aladdin_CAPI_COM::IEntry*)(IUnknown*)*ppvObject); 

		// вернуть перехватывающий объект
		((IUnknown*)*ppvObject)->Release(); *ppvObject = pEntry; return hr; 
	}
	// обработать возможную ошибку
	catch (const windows_exception& e) { hr = e.value(); } catch (...) { hr = E_FAIL; }

	// освободить выделенные ресурсы
	((IUnknown*)*ppvObject)->Release(); return hr; 
}
