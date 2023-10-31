#pragma once
#include "Aladdin.CAPI.COM.h"
#include "factory.h"

namespace Aladdin { namespace CAPI { namespace COM 
{
///////////////////////////////////////////////////////////////////////////////
// Способ удаления ссылки на COM-объект
///////////////////////////////////////////////////////////////////////////////
template <class ClassName>
class Deleter
{
	// удалить ссылку на COM-объект
	public: template <class I> void operator()(I* ptr) 
	{ 
		// удалить ссылку на COM-объект
		static_cast<ClassName*>(ptr)->Release(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Реализация IUnknown
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
class UnknownObject : public Interface
{
	// точка входа в управляемый код и счетчик ссылок
	private: ATL::CComPtr<Interface> pObject; LONG cRef; DWORD dwCookieGIT;

	// конструктор
	public: UnknownObject(Interface* pObject, bool registerGIT = false); 
	// деструктор
	public: virtual ~UnknownObject(); 

	// базовый объект
	protected: Interface* BaseObject() const { return (Interface*)pObject; }
	// идентификатор интерфейса
	protected: REFIID GetIID() const { return __uuidof(Interface); }

	// идентификатор в таблице интерфейсов 
	protected: DWORD CookieGIT() const { return dwCookieGIT; }

	///////////////////////////////////////////////////////////////////////////
	// Методы IUnknown
	///////////////////////////////////////////////////////////////////////////
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // проверить корректность данных
        if (!ppvObject) return E_POINTER; *ppvObject = 0; 

        // при поддержке интерфейса
        if (InlineIsEqualGUID(riid, GetIID()) || 
			InlineIsEqualGUID(riid, IID_IUnknown))
        {
            // вернуть указать на объект
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
    // увеличить счетчик ссылок
    public: virtual ULONG STDMETHODCALLTYPE AddRef() override { return ++cRef; }

    // уменьшить счетчик ссылок
    public: virtual ULONG STDMETHODCALLTYPE Release() override
    {
        // уменьшить счетчик ссылок и удалить объект
		if (cRef == 1) { delete this; return 0; } else return --cRef; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Реализация IDispatch 
///////////////////////////////////////////////////////////////////////////////
template <class Interface>
class DispatchObject : public UnknownObject<Interface>
{
	// конструктор
	public: DispatchObject(Interface* pObject, bool registerGIT = false) 
		
		// сохранить переданные параметры 
		: UnknownObject<Interface>(pObject, registerGIT) {}

	///////////////////////////////////////////////////////////////////////////
	// Методы IDispatch
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
	// Методы IUnknown
	///////////////////////////////////////////////////////////////////////////
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // проверить корректность данных
        if (ppvObject == 0) return E_POINTER; *ppvObject = 0; 

        // при поддержке интерфейса
        if (InlineIsEqualGUID(riid, GetIID())      || 
			InlineIsEqualGUID(riid, IID_IDispatch) || 
			InlineIsEqualGUID(riid, IID_IUnknown ))
        {
            // вернуть указать на объект
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации
///////////////////////////////////////////////////////////////////////////////
class Authentication : public UnknownObject<Aladdin_CAPI_COM::IAuthentication>
{
	// тип базового класса 
	private: typedef UnknownObject<Aladdin_CAPI_COM::IAuthentication> base_type; 

	// конструктор
	public: Authentication(Aladdin_CAPI_COM::IAuthentication* pObject) : base_type(pObject) {}
};

///////////////////////////////////////////////////////////////////////////
// Отличимое имя
///////////////////////////////////////////////////////////////////////////
class DistinctName : public DispatchObject<Aladdin_CAPI_COM::IDistinctName>, public CAPI::IDistinctName
{
	// тип базового класса 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IDistinctName> base_type; 

	// конструктор
	public: DistinctName(Aladdin_CAPI_COM::IDistinctName* pDistinctName) : base_type(pDistinctName) {}

	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// бинарное представление 
	public: virtual HRESULT STDMETHODCALLTYPE get_Encoded(BSTR* pRetVal) override;
	// строковое представление
    public: virtual HRESULT STDMETHODCALLTYPE ToString(BSTR* pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация C++-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// бинарное представление 
    public: virtual std::vector<BYTE> Encoded() const override; 
	// строковое представление
    public: virtual std::wstring ToString() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Сертификат
///////////////////////////////////////////////////////////////////////////////
class Certificate : public DispatchObject<Aladdin_CAPI_COM::ICertificate>, public CAPI::ICertificate
{
	// тип базового класса 
	private: typedef DispatchObject<Aladdin_CAPI_COM::ICertificate> base_type; 

	// конструктор
	public: Certificate(Aladdin_CAPI_COM::ICertificate* pCertificate) : base_type(pCertificate) {}
	// деструктор
	public: virtual ~Certificate() { BaseObject()->Dispose(); }

	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// вызов запрещен 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// закодировать сертификат
    public: virtual HRESULT STDMETHODCALLTYPE get_Encoded(BSTR *pRetVal) override; 

	// идентификатор (OID) ключа
    public: virtual HRESULT STDMETHODCALLTYPE get_KeyOID(BSTR *pRetVal) override; 
	// получить издателя сертификата
    public: virtual HRESULT STDMETHODCALLTYPE get_Issuer(Aladdin_CAPI_COM::IDistinctName** pRetVal) override; 
    // получить субъекта сертификата
    public: virtual HRESULT STDMETHODCALLTYPE get_Subject(Aladdin_CAPI_COM::IDistinctName** pRetVal) override;
	// получить способ использования ключа
	public: virtual HRESULT STDMETHODCALLTYPE get_KeyUsage(Aladdin_CAPI_COM::KeyUsage *pRetVal) override; 

	// зашифровать данные
    public: virtual HRESULT STDMETHODCALLTYPE Encrypt(BSTR data, BSTR *pRetVal) override; 
    // проверить подпись данных
    public: virtual HRESULT STDMETHODCALLTYPE VerifySign(BSTR data, BSTR *pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация C++-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// бинарное представление 
    public: virtual std::vector<BYTE> Encoded() const override; 

	// идентификатор (OID) ключа
	public: virtual std::wstring KeyOID() const override;
	// издатель и субъект сертификата
	public: virtual std::shared_ptr<CAPI::IDistinctName> Issuer () const override; 
    public: virtual std::shared_ptr<CAPI::IDistinctName> Subject() const override; 
	// способ использования сертификата
	public: virtual enum CAPI::KeyUsage KeyUsage() const override;

	// зашифровать данные    
    public: virtual std::vector<BYTE> Encrypt(
		const void* pvData, size_t cbData) const override;
        
	// проверить подпись
	public: virtual std::vector<BYTE> VerifySign(
		const void* pvData, size_t cbData) const override;
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public DispatchObject<Aladdin_CAPI_COM::IPrivateKey>, public CAPI::IPrivateKey
{
	// тип базового класса 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IPrivateKey> base_type; 

	// конструктор
	public: PrivateKey(Aladdin_CAPI_COM::IPrivateKey* pPrivateKey) : base_type(pPrivateKey) {}
	// деструктор
	public: virtual ~PrivateKey() { BaseObject()->Dispose(); }

	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// вызов запрещен 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// закодировать личный ключ
    public: virtual HRESULT STDMETHODCALLTYPE ToString(BSTR *pRetVal) override; 

	// получить сертификат открытого ключа
    public: virtual HRESULT STDMETHODCALLTYPE get_Certificate(
		Aladdin_CAPI_COM::ICertificate **pRetVal) override; 
	// связать контекст сертификата с ключом
	public: virtual HRESULT STDMETHODCALLTYPE SetCertificateContext(
		void* pCertificateContext) override;

	// установить способ аутентификации
	public: virtual HRESULT STDMETHODCALLTYPE put_Authentication(
		Aladdin_CAPI_COM::IAuthentication* pAuthentication) override; 
	// указать пароль контейнера
	public: virtual HRESULT STDMETHODCALLTYPE put_Password(BSTR password) override; 

	// зашифровать данные
    public: virtual HRESULT STDMETHODCALLTYPE Encrypt( 
		Aladdin_CAPI_COM::ICertificate *cert, BSTR data, BSTR *pRetVal) override; 
	// расшифровать данные
    public: virtual HRESULT STDMETHODCALLTYPE Decrypt(BSTR data, BSTR *pRetVal) override; 
	// подписать данные
    public: virtual HRESULT STDMETHODCALLTYPE SignData(BSTR data, BSTR *pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация C++-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// строковое представление
	public: virtual std::wstring ToString() const override; 
	// сертификат открытого ключа
	public: virtual std::shared_ptr<CAPI::ICertificate> Certificate() const override;
	// связать сертификат с ключом
	public: virtual void SetCertificateContext(PCCERT_CONTEXT) const override;  

	// указать пароль контейнера
	public: virtual void SetPassword(const wchar_t* szPassword) override;  

	// зашифровать данные    
    public: virtual std::vector<BYTE> Encrypt(
		const CAPI::ICertificate* pCertificate, 
		const void* pvData, size_t cbData) const override;

	// расшифровать данные    
	public: virtual std::vector<BYTE> Decrypt(
		const void* pvData, size_t cbData) const override;

	// подписать данные        
	public: virtual std::vector<BYTE> SignData(
		const void* pvData, size_t cbData) const override;
}; 

///////////////////////////////////////////////////////////////////////////
// Освобождаемая фабрика алгоритмов
///////////////////////////////////////////////////////////////////////////
class Factory : public DispatchObject<Aladdin_CAPI_COM::IFactory>, public CAPI::IFactory
{
	// тип базового класса 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IFactory> base_type; 

	// конструктор
	public: Factory(Aladdin_CAPI_COM::IFactory* pFactory) 
		
		// сохранить переданные параметры 
		: base_type(pFactory, true) { dwCookie = CookieGIT(); }

	// конструктор
	public: Factory(Aladdin_CAPI_COM::IFactory* pFactory, DWORD dwCookie) 
		
		// сохранить переданные параметры 
		: base_type(pFactory, false) { this->dwCookie = dwCookie; }

	// деструктор
	public: virtual ~Factory() { if (!CookieGIT()) BaseObject()->Dispose(); } 

	// передать указатель другому потоку
	public: virtual std::shared_ptr<CAPI::IFactory> Marshal() const override; 

	private: DWORD dwCookie; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// вызов запрещен 
	public: virtual HRESULT STDMETHODCALLTYPE Dispose() override { return E_ACCESSDENIED; }

	// идентификатор локализации
    public: virtual HRESULT STDMETHODCALLTYPE get_LCID(long *pRetVal) override; 

	// сгенерировать случайные данные
	public: virtual HRESULT STDMETHODCALLTYPE GenerateRandom(long cb, BSTR* pRetVal) override; 

	// интерактивная парольная аутентификация
	public: virtual HRESULT STDMETHODCALLTYPE PasswordAuthentication(
		void* hwnd, Aladdin_CAPI_COM::IAuthentication** pRetVal) override; 

	// зашифровать данные на пароле
	public: virtual HRESULT STDMETHODCALLTYPE PasswordEncrypt(
		BSTR cultureOID, BSTR password, BSTR data, BSTR* pRetVal) override; 
	// расшифровать данные на пароле
	public: virtual HRESULT STDMETHODCALLTYPE PasswordDecrypt(
		BSTR password, BSTR data, BSTR* pRetVal) override; 

	// раскодировать сертификат
    public: virtual HRESULT STDMETHODCALLTYPE DecodeCertificate(
		BSTR encoded, Aladdin_CAPI_COM::ICertificate** pRetVal) override; 
	// раскодировать личный ключ
    public: virtual HRESULT STDMETHODCALLTYPE DecodePrivateKey( 
		BSTR encoded, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override; 
    // раскодировать контейнер PKCS12
    public: virtual HRESULT STDMETHODCALLTYPE DecodePKCS12(
		BSTR encoded, BSTR password, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override;

	// найти сертификат для проверки подписи
    public: virtual HRESULT STDMETHODCALLTYPE FindVerifyCertificate( 
        BSTR data, SAFEARRAY* certificates, Aladdin_CAPI_COM::ICertificate** pRetVal) override; 
	// найти личный ключ для расшифрования
    public: virtual HRESULT STDMETHODCALLTYPE FindDecryptPrivateKey( 
        BSTR data, SAFEARRAY* privateKeys, Aladdin_CAPI_COM::IPrivateKey** pRetVal) override; 

    // перечислить личные ключи
	public: virtual HRESULT STDMETHODCALLTYPE EnumeratePrivateKeys( 
        void* hwnd, Aladdin_CAPI_COM::KeyUsage keyUsage, 
		VARIANT_BOOL systemOnly, SAFEARRAY** pRetVal) override; 
	// выбрать личный ключ 
    public: virtual HRESULT STDMETHODCALLTYPE SelectPrivateKeySSL( 
        void* hwnd, Aladdin_CAPI_COM::IPrivateKey **pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация C++-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// выполнить аутентификацию
	public: virtual std::wstring PasswordAuthenticate(void*, const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const override; 

	// сгенерировать случайные данные
	public: virtual void GenerateRandom(void* pvData, size_t cbData) const override; 

	// зашифровать данные на пароле
	public: virtual std::vector<BYTE> PasswordEncrypt(
		const wchar_t* szCultureOID, const wchar_t* szPassword, 
		const void* pvData, size_t cbData) const override; 
	// расшифровать данные на пароле
	public: virtual std::vector<BYTE> PasswordDecrypt(
		const wchar_t* szPassword, const void* pvData, size_t cbData) const override; 

	// раскодировать сертификат
	public: virtual std::shared_ptr<CAPI::ICertificate> DecodeCertificate(
		const void* pvEncoded, size_t cbEncoded) const override;  
    // создать объект личного ключа
    public: virtual std::shared_ptr<CAPI::IPrivateKey> DecodePrivateKey(
		const wchar_t* szEncoded, void* hwnd) const override;
    // раскодировать контейнер PKCS12
    public: virtual std::shared_ptr<CAPI::IPrivateKey> DecodePKCS12(
		const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const override;

	// найти сертификат для проверки подписи
	public: virtual std::shared_ptr<ICertificate> FindVerifyCertificate(
		const void* pvData, size_t cbData, 
        const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const override;
	// найти ключ для расшифрования
	public: virtual std::shared_ptr<CAPI::IPrivateKey> FindDecryptPrivateKey(
		const void* pvData, size_t cbData, void* hwnd, 
        const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const override;

    // перечислить личные ключи    
	public: virtual std::vector<std::wstring> 
		EnumeratePrivateKeys(void* hwnd, bool systemOnly) const override;
	// выбрать личный ключ
    public: virtual std::shared_ptr<CAPI::IPrivateKey> 
		SelectPrivateKeySSL(void* hwnd) const override;
}; 

///////////////////////////////////////////////////////////////////////////
// Точка входа в управляемый код
///////////////////////////////////////////////////////////////////////////
class Entry : public DispatchObject<Aladdin_CAPI_COM::IEntry>
{
	// тип базового класса 
	private: typedef DispatchObject<Aladdin_CAPI_COM::IEntry> base_type; 

	// конструктор
	public: Entry(Aladdin_CAPI_COM::IEntry* pEntry) : base_type(pEntry) {}

	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// создать фабрику алгоритмов
    public: virtual HRESULT STDMETHODCALLTYPE CreateFactory( 
		LCID lcid, BSTR fileName, Aladdin_CAPI_COM::IFactory **pRetVal) override; 

	///////////////////////////////////////////////////////////////////////////
	// Реализация C++-интерфейса
	///////////////////////////////////////////////////////////////////////////

	// создать фабрику алгоритмов
	public: std::shared_ptr<CAPI::IFactory> CreateFactory(
		LCID lcid, PCWSTR fileName) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика компонента
///////////////////////////////////////////////////////////////////////////////
class ClassFactoryNET : public ::ClassFactoryNET<Aladdin_CAPI_COM::IClassFactoryNET>
{
	// указать тип базового класса
	private: typedef ::ClassFactoryNET<Aladdin_CAPI_COM::IClassFactoryNET> base_type; 

    // конструктор/деструктор
	public: ClassFactoryNET(volatile LONG* pLocks) : base_type(pLocks) {}

    // создать объект
    public: virtual HRESULT STDMETHODCALLTYPE CreateInstance( 
        IUnknown *pUnkfactory, REFIID riid, void **ppvObject) override; 

	// таблица регистрации компонентов
    protected: virtual CONST COM_DESC* Components() const override; 
};
}}}

