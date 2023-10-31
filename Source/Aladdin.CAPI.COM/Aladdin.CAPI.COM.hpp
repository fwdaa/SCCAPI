#pragma once
#include "Aladdin.CAPI.COM.h"
#include "factory.h"

namespace Aladdin { namespace CAPI { namespace COM 
{
///////////////////////////////////////////////////////////////////////////////
// ������ �������� ������ �� COM-������
///////////////////////////////////////////////////////////////////////////////
template <class ClassName>
class Deleter
{
	// ������� ������ �� COM-������
	public: template <class I> void operator()(I* ptr) 
	{ 
		// ������� ������ �� COM-������
		static_cast<ClassName*>(ptr)->Release(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ���������� IUnknown
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
class UnknownObject : public Interface
{
	// ����� ����� � ����������� ��� � ������� ������
	private: ATL::CComPtr<Interface> pObject; LONG cRef; DWORD dwCookieGIT;

	// �����������
	public: UnknownObject(Interface* pObject, bool registerGIT = false); 
	// ����������
	public: virtual ~UnknownObject(); 

	// ������� ������
	protected: Interface* BaseObject() const { return (Interface*)pObject; }
	// ������������� ����������
	protected: REFIID GetIID() const { return __uuidof(Interface); }

	// ������������� � ������� ����������� 
	protected: DWORD CookieGIT() const { return dwCookieGIT; }

	///////////////////////////////////////////////////////////////////////////
	// ������ IUnknown
	///////////////////////////////////////////////////////////////////////////
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // ��������� ������������ ������
        if (!ppvObject) return E_POINTER; *ppvObject = 0; 

        // ��� ��������� ����������
        if (InlineIsEqualGUID(riid, GetIID()) || 
			InlineIsEqualGUID(riid, IID_IUnknown))
        {
            // ������� ������� �� ������
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
    // ��������� ������� ������
    public: virtual ULONG STDMETHODCALLTYPE AddRef() override { return ++cRef; }

    // ��������� ������� ������
    public: virtual ULONG STDMETHODCALLTYPE Release() override
    {
        // ��������� ������� ������ � ������� ������
		if (cRef == 1) { delete this; return 0; } else return --cRef; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// ���������� IDispatch 
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
class DispatchObject : public UnknownObject<Interface>
{
	// �����������
	public: DispatchObject(Interface* pObject, bool registerGIT = false) 
		
		// ��������� ���������� ��������� 
		: UnknownObject<Interface>(pObject, registerGIT) {}

	///////////////////////////////////////////////////////////////////////////
	// ������ IDispatch
	///////////////////////////////////////////////////////////////////////////
    public: virtual HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *pctinfo); 

    public: virtual HRESULT STDMETHODCALLTYPE GetTypeInfo( 
		UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) override; 

    public: virtual HRESULT STDMETHODCALLTYPE GetIDsOfNames( 
		REFIID riid, LPOLESTR *rgszNames, UINT cNames, 
		LCID lcid, DISPID *rgDispId) override; 

    public: virtual HRESULT STDMETHODCALLTYPE Invoke( 
		DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, 
		DISPPARAMS *pDispParams, VARIANT *pVarResult, 
		EXCEPINFO *pExcepInfo, UINT *puArgErr) override; 

	///////////////////////////////////////////////////////////////////////////
	// ������ IUnknown
	///////////////////////////////////////////////////////////////////////////
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // ��������� ������������ ������
        if (ppvObject == 0) return E_POINTER; *ppvObject = 0; 

        // ��� ��������� ����������
        if (InlineIsEqualGUID(riid, GetIID())      || 
			InlineIsEqualGUID(riid, IID_IDispatch) || 
			InlineIsEqualGUID(riid, IID_IUnknown ))
        {
            // ������� ������� �� ������
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// ������ ��������������
///////////////////////////////////////////////////////////////////////////////
class Authentication : public UnknownObject<Aladdin_CAPI_COM::IAuthentication>
{
	// ��� �������� ������ 
	private: typedef UnknownObject<Aladdin_CAPI_COM::IAuthentication> base_type; 

	// �����������
	public: Authentication(Aladdin_CAPI_COM::IAuthentication* pObject) : base_type(pObject) {}
};

///////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////
class DistinctName : public DispatchObject<Aladdin_CAPI_COM::IDistinctName>, public CAPI::IDistinctName
{
	// ��� �������� ������ 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IDistinctName> base_type; 

	// �����������
	public: DistinctName(Aladdin_CAPI_COM::IDistinctName* pDistinctName) : base_type(pDistinctName) {}

	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

	// �������� ������������� 
	public: virtual HRESULT STDMETHODCALLTYPE get_Encoded(BSTR* pRetVal) override;
	// ��������� �������������
    public: virtual HRESULT STDMETHODCALLTYPE ToString(BSTR* pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� C++-����������
	///////////////////////////////////////////////////////////////////////////

	// �������� ������������� 
    public: virtual std::vector<BYTE> Encoded() const override; 
	// ��������� �������������
    public: virtual std::wstring ToString() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������
///////////////////////////////////////////////////////////////////////////////
class Certificate : public DispatchObject<Aladdin_CAPI_COM::ICertificate>, public CAPI::ICertificate
{
	// ��� �������� ������ 
	private: typedef DispatchObject<Aladdin_CAPI_COM::ICertificate> base_type; 

	// �����������
	public: Certificate(Aladdin_CAPI_COM::ICertificate* pCertificate) : base_type(pCertificate) {}
	// ����������
	public: virtual ~Certificate() { BaseObject()->Dispose(); }

	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

	// ����� �������� 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// ������������ ����������
    public: virtual HRESULT STDMETHODCALLTYPE get_Encoded(BSTR *pRetVal) override; 

	// ������������� (OID) �����
    public: virtual HRESULT STDMETHODCALLTYPE get_KeyOID(BSTR *pRetVal) override; 
	// �������� �������� �����������
    public: virtual HRESULT STDMETHODCALLTYPE get_Issuer(Aladdin_CAPI_COM::IDistinctName** pRetVal) override; 
    // �������� �������� �����������
    public: virtual HRESULT STDMETHODCALLTYPE get_Subject(Aladdin_CAPI_COM::IDistinctName** pRetVal) override;
	// �������� ������ ������������� �����
	public: virtual HRESULT STDMETHODCALLTYPE get_KeyUsage(Aladdin_CAPI_COM::KeyUsage *pRetVal) override; 

	// ����������� ������
    public: virtual HRESULT STDMETHODCALLTYPE Encrypt(BSTR data, BSTR *pRetVal) override; 
    // ��������� ������� ������
    public: virtual HRESULT STDMETHODCALLTYPE VerifySign(BSTR data, BSTR *pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� C++-����������
	///////////////////////////////////////////////////////////////////////////

	// �������� ������������� 
    public: virtual std::vector<BYTE> Encoded() const override; 

	// ������������� (OID) �����
	public: virtual std::wstring KeyOID() const override;
	// �������� � ������� �����������
	public: virtual std::shared_ptr<CAPI::IDistinctName> Issuer () const override; 
    public: virtual std::shared_ptr<CAPI::IDistinctName> Subject() const override; 
	// ������ ������������� �����������
	public: virtual enum CAPI::KeyUsage KeyUsage() const override;

	// ����������� ������    
    public: virtual std::vector<BYTE> Encrypt(
		const void* pvData, size_t cbData) const override;
        
	// ��������� �������
	public: virtual std::vector<BYTE> VerifySign(
		const void* pvData, size_t cbData) const override;
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public DispatchObject<Aladdin_CAPI_COM::IPrivateKey>, public CAPI::IPrivateKey
{
	// ��� �������� ������ 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IPrivateKey> base_type; 

	// �����������
	public: PrivateKey(Aladdin_CAPI_COM::IPrivateKey* pPrivateKey) : base_type(pPrivateKey) {}
	// ����������
	public: virtual ~PrivateKey() { BaseObject()->Dispose(); }

	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

	// ����� �������� 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// ������������ ������ ����
    public: virtual HRESULT STDMETHODCALLTYPE ToString(BSTR *pRetVal) override; 

	// �������� ���������� ��������� �����
    public: virtual HRESULT STDMETHODCALLTYPE get_Certificate(
		Aladdin_CAPI_COM::ICertificate **pRetVal) override; 
	// ������� �������� ����������� � ������
	public: virtual HRESULT STDMETHODCALLTYPE SetCertificateContext(
		void* pCertificateContext) override;

	// ���������� ������ ��������������
	public: virtual HRESULT STDMETHODCALLTYPE put_Authentication(
		Aladdin_CAPI_COM::IAuthentication* pAuthentication) override; 
	// ������� ������ ����������
	public: virtual HRESULT STDMETHODCALLTYPE put_Password(BSTR password) override; 

	// ����������� ������
    public: virtual HRESULT STDMETHODCALLTYPE Encrypt( 
		Aladdin_CAPI_COM::ICertificate *cert, BSTR data, BSTR *pRetVal) override; 
	// ������������ ������
    public: virtual HRESULT STDMETHODCALLTYPE Decrypt(BSTR data, BSTR *pRetVal) override; 
	// ��������� ������
    public: virtual HRESULT STDMETHODCALLTYPE SignData(BSTR data, BSTR *pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� C++-����������
	///////////////////////////////////////////////////////////////////////////

	// ��������� �������������
	public: virtual std::wstring ToString() const override; 
	// ���������� ��������� �����
	public: virtual std::shared_ptr<CAPI::ICertificate> Certificate() const override;
	// ������� ���������� � ������
	public: virtual void SetCertificateContext(PCCERT_CONTEXT) const override;  

	// ������� ������ ����������
	public: virtual void SetPassword(const wchar_t* szPassword) override;  

	// ����������� ������    
    public: virtual std::vector<BYTE> Encrypt(
		const CAPI::ICertificate* pCertificate, 
		const void* pvData, size_t cbData) const override;

	// ������������ ������    
	public: virtual std::vector<BYTE> Decrypt(
		const void* pvData, size_t cbData) const override;

	// ��������� ������        
	public: virtual std::vector<BYTE> SignData(
		const void* pvData, size_t cbData) const override;
}; 

///////////////////////////////////////////////////////////////////////////
// ������������� ������� ����������
///////////////////////////////////////////////////////////////////////////
class Factory : public DispatchObject<Aladdin_CAPI_COM::IFactory>, public CAPI::IFactory
{
	// ��� �������� ������ 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IFactory> base_type; 

	// �����������
	public: Factory(Aladdin_CAPI_COM::IFactory* pFactory) 
		
		// ��������� ���������� ��������� 
		: base_type(pFactory, true) { dwCookie = CookieGIT(); }

	// �����������
	public: Factory(Aladdin_CAPI_COM::IFactory* pFactory, DWORD dwCookie) 
		
		// ��������� ���������� ��������� 
		: base_type(pFactory, false) { this->dwCookie = dwCookie; }

	// ����������
	public: virtual ~Factory() { if (!CookieGIT()) BaseObject()->Dispose(); } 

	// �������� ��������� ������� ������
	public: virtual std::shared_ptr<CAPI::IFactory> Marshal() const override; 

	private: DWORD dwCookie; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

	// ����� �������� 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// ������������� �����������
    public: virtual HRESULT STDMETHODCALLTYPE get_LCID(long *pRetVal) override; 

	// ������������� ��������� ������
	public: virtual HRESULT STDMETHODCALLTYPE GenerateRandom(long cb, BSTR* pRetVal) override; 

	// ������������� ��������� ��������������
	public: virtual HRESULT STDMETHODCALLTYPE PasswordAuthentication(
		void* hwnd, Aladdin_CAPI_COM::IAuthentication** pRetVal) override; 

	// ����������� ������ �� ������
	public: virtual HRESULT STDMETHODCALLTYPE PasswordEncrypt(
		BSTR cultureOID, BSTR password, BSTR data, BSTR* pRetVal) override; 
	// ������������ ������ �� ������
	public: virtual HRESULT STDMETHODCALLTYPE PasswordDecrypt(
		BSTR password, BSTR data, BSTR* pRetVal) override; 

	// ������������� ����������
    public: virtual HRESULT STDMETHODCALLTYPE DecodeCertificate(
		BSTR encoded, Aladdin_CAPI_COM::ICertificate** pRetVal) override; 
	// ������������� ������ ����
    public: virtual HRESULT STDMETHODCALLTYPE DecodePrivateKey( 
		BSTR encoded, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override; 
    // ������������� ��������� PKCS12
    public: virtual HRESULT STDMETHODCALLTYPE DecodePKCS12(
		BSTR encoded, BSTR password, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override;

	// ����� ���������� ��� �������� �������
    public: virtual HRESULT STDMETHODCALLTYPE FindVerifyCertificate( 
        BSTR data, SAFEARRAY* certificates, Aladdin_CAPI_COM::ICertificate** pRetVal) override; 
	// ����� ������ ���� ��� �������������
    public: virtual HRESULT STDMETHODCALLTYPE FindDecryptPrivateKey( 
        BSTR data, SAFEARRAY* privateKeys, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override; 

    // ����������� ������ �����
	public: virtual HRESULT STDMETHODCALLTYPE EnumeratePrivateKeys( 
        void* hwnd, Aladdin_CAPI_COM::KeyUsage keyUsage, 
		VARIANT_BOOL systemOnly, SAFEARRAY** pRetVal) override; 
	// ������� ������ ���� 
    public: virtual HRESULT STDMETHODCALLTYPE SelectPrivateKeySSL( 
        void* hwnd, Aladdin_CAPI_COM::IPrivateKey **pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� C++-����������
	///////////////////////////////////////////////////////////////////////////

	// ��������� ��������������
	public: virtual std::wstring PasswordAuthenticate(void*, const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const override; 

	// ������������� ��������� ������
	public: virtual void GenerateRandom(void* pvData, size_t cbData) const override; 

	// ����������� ������ �� ������
	public: virtual std::vector<BYTE> PasswordEncrypt(
		const wchar_t* szCultureOID, const wchar_t* szPassword, 
		const void* pvData, size_t cbData) const override; 
	// ������������ ������ �� ������
	public: virtual std::vector<BYTE> PasswordDecrypt(
		const wchar_t* szPassword, const void* pvData, size_t cbData) const override; 

	// ������������� ����������
	public: virtual std::shared_ptr<CAPI::ICertificate> DecodeCertificate(
		const void* pvEncoded, size_t cbEncoded) const override;  
    // ������� ������ ������� �����
    public: virtual std::shared_ptr<CAPI::IPrivateKey> DecodePrivateKey(
		const wchar_t* szEncoded, void* hwnd) const override;
    // ������������� ��������� PKCS12
    public: virtual std::shared_ptr<CAPI::IPrivateKey> DecodePKCS12(
		const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const override;

	// ����� ���������� ��� �������� �������
	public: virtual std::shared_ptr<ICertificate> FindVerifyCertificate(
		const void* pvData, size_t cbData, 
        const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const override;
	// ����� ���� ��� �������������
	public: virtual std::shared_ptr<CAPI::IPrivateKey> FindDecryptPrivateKey(
		const void* pvData, size_t cbData, void* hwnd, 
        const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const override;

    // ����������� ������ �����    
	public: virtual std::vector<std::wstring> 
		EnumeratePrivateKeys(void* hwnd, bool systemOnly) const override;
	// ������� ������ ����
    public: virtual std::shared_ptr<CAPI::IPrivateKey> 
		SelectPrivateKeySSL(void* hwnd) const override;
}; 

///////////////////////////////////////////////////////////////////////////
// ����� ����� � ����������� ���
///////////////////////////////////////////////////////////////////////////
class Entry : public DispatchObject<Aladdin_CAPI_COM::IEntry>
{
	// ��� �������� ������ 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IEntry> base_type; 

	// �����������
	public: Entry(Aladdin_CAPI_COM::IEntry* pEntry) : base_type(pEntry) {}

	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

	// ������� ������� ����������
    public: virtual HRESULT STDMETHODCALLTYPE CreateFactory( 
		LCID lcid, BSTR fileName, Aladdin_CAPI_COM::IFactory **pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// ���������� C++-����������
	///////////////////////////////////////////////////////////////////////////

	// ������� ������� ����������
	public: std::shared_ptr<CAPI::IFactory> CreateFactory(
		LCID lcid, PCWSTR fileName) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ����������
///////////////////////////////////////////////////////////////////////////////
class ClassFactoryNET : public ::ClassFactoryNET<Aladdin_CAPI_COM::IClassFactoryNET>
{
	// ������� ��� �������� ������
	private: typedef ::ClassFactoryNET<Aladdin_CAPI_COM::IClassFactoryNET> base_type; 

    // �����������/����������
	public: ClassFactoryNET(volatile LONG* pLocks) : base_type(pLocks) {}

    // ������� ������
    public: virtual HRESULT STDMETHODCALLTYPE CreateInstance( 
        IUnknown *pUnkfactory, REFIID riid, void **ppvObject) override; 

	// ������� ����������� �����������
    protected: virtual CONST COM_DESC* Components() const override; 
};
}}}

