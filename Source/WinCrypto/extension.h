#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace Extension { 

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////

// получить X.509-представление открытого ключа
std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID);
std::vector<BYTE> CspExportPublicKey(HCRYPTKEY  hKey,                      PCSTR szKeyOID);

// импортировать X.509-представление открытого ключа
HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID);

// получить PKCS8-представление личного ключа из контейнера  
std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID);

// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec, 
	const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags
);
// получить X.509-представление открытого ключа для описателя 
std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec);

// импортировать X.509-представление открытого ключа
BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec);

// получить PKCS8-представление личного ключа
std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec); 

// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR szProvider,
	const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec
); 
// получить X.509-представление открытого ключа для описателя 
std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec); 

// импортировать X.509-представление открытого ключа
NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec);

// получить PKCS8-представление личного ключа
std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec); 

// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
	const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec
);

///////////////////////////////////////////////////////////////////////////////
// Интерфейс расширения 
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory { virtual ~IKeyFactory() {}

	// получить X.509-представление открытого ключа для BLOB
	virtual std::vector<BYTE> CspEncodePublicKey(PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const; 

	// получить BLOB открытого ключа для X.509-представления
	virtual std::vector<BYTE> CspConvertPublicKey(const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const; 

	// получить X.509-представление открытого ключа
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const;
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTKEY  hKey,                      PCSTR szKeyOID) const;

	// импортировать X.509-представление открытого ключа
	virtual HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const;

	// получить PKCS8-представление личного ключа из контейнера  
	virtual std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const;

	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec, 
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags) const;

	// получить X.509-представление открытого ключа для описателя 
	virtual std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const;

	// импортировать X.509-представление открытого ключа
	virtual BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const;

	// получить PKCS8-представление личного ключа
	virtual std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE, PCSTR, DWORD) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR, const CERT_PUBLIC_KEY_INFO*, const CRYPT_PRIVATE_KEY_INFO*, DWORD) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return NULL; 
	}
	// получить X.509-представление открытого ключа для описателя 
	virtual std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const;

	// импортировать X.509-представление открытого ключа
	virtual NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const;

	// получить PKCS8-представление личного ключа
	virtual std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const;

	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
		const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const;
};

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public IPublicKey 
{ 
	// тип импорта CSP
	public: virtual const wchar_t* TypeCSP() const { return nullptr; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// тип импорта CNG
	public: virtual const wchar_t* TypeCNG() const { return BCRYPT_PUBLIC_KEY_BLOB; }
	// параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const 
	{ 
		// параметры при импорте
		return std::shared_ptr<NCryptBufferDesc>(); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair 
{ 
	// тип импорта CSP
	public: virtual const wchar_t* TypeCSP() const { return nullptr; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// тип импорта CNG
	public: virtual const wchar_t* TypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }
	// параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const 
	{ 
		// параметры при импорте
		return std::shared_ptr<NCryptBufferDesc>(); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Функции расширения для известных типов ключей
///////////////////////////////////////////////////////////////////////////////
struct KeyFactory : IKeyFactory
{
	// тип экспорта CSP
	virtual DWORD ExportFlagsCSP() const { return 0; } 

	// тип экспорта CNG
	virtual PCWSTR ExportPublicTypeCNG () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	virtual PCWSTR ExportPrivateTypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }

	// получить дополнительные данные для описателя
	virtual std::shared_ptr<void> GetAuxDataCNG(BCRYPT_KEY_HANDLE hKey, ULONG magic) const { return std::shared_ptr<void>(); }
	virtual std::shared_ptr<void> GetAuxDataCNG(NCRYPT_KEY_HANDLE hKey, ULONG magic) const { return std::shared_ptr<void>(); }

	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(const CERT_PUBLIC_KEY_INFO&) const = 0; 
	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR, const PUBLICKEYSTRUC*, size_t) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR, LPCVOID, const BCRYPT_KEY_BLOB*, size_t) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// раскодировать пару ключей
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(const CRYPT_PRIVATE_KEY_INFO&, const CERT_PUBLIC_KEY_INFO*) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// раскодировать пару ключей
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(PCSTR, const BLOBHEADER*, size_t) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// раскодировать пару ключей
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(PCSTR, LPCVOID, const BCRYPT_KEY_BLOB*, size_t) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// получить X.509-представление открытого ключа для BLOB
	virtual std::vector<BYTE> CspEncodePublicKey(PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// получить X.509-представление открытого ключа для BLOB
		return DecodePublicKey(szKeyOID, pBlob, cbBlob)->Encode(); 
	}
	// получить BLOB открытого ключа для X.509-представления
	virtual std::vector<BYTE> CspConvertPublicKey(const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const override
	{
		// получить BLOB открытого ключа для X.509-представления
		return DecodePublicKey(*pInfo)->BlobCSP(algID); 
	}
	// получить X.509-представление открытого ключа из контейнера  
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const override;

	// получить X.509-представление открытого ключа для описателя 
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTKEY hKey, PCSTR szKeyOID) const override;

	// импортировать X.509-представление открытого ключа
	virtual HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const override;

	// получить PKCS8-представление личного ключа из контейнера  
	virtual std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const override;

	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec,
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags) const override;

	// получить X.509-представление открытого ключа для описателя 
	virtual std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const override;

	// импортировать X.509-представление открытого ключа
	virtual BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const override;

	// получить PKCS8-представление личного ключа
	virtual std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const override;

	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR szProvider, 
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const override;

	// получить X.509-представление открытого ключа для описателя 
	virtual std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const override;

	// импортировать X.509-представление открытого ключа
	virtual NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const override;

	// получить PKCS8-представление личного ключа
	virtual std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const override;

	// импортировать X.509- и PKCS8-представление пары клюючей в контейнер
	virtual void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
		const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const override;
};

///////////////////////////////////////////////////////////////////////////////
// Зарегистрированная информация для OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// получить зарегистрированную информацию
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}
// найти информацию открытого ключа 
WINCRYPT_CALL PCCRYPT_OID_INFO FindPublicKeyOID(PCSTR szKeyOID, DWORD keySpec); 

///////////////////////////////////////////////////////////////////////////////
// Тип атрибута или расширения. Задает соответствие OID и отображаемого имени. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
	// перечислить зарегистрированные типы атрибутов
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: AttributeType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
 		// указать отображаемое имя 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	} 
	// идентификатор атрибута
	public: const char* OID() const { return _strOID.c_str(); }
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип атрибута RDN. Задает соответствие OID, символьного X.500-идентификатора 
// для OID, а также списка допустимых типов CERT_RDN_*, отсортированного в 
// порядке предпочтения.
///////////////////////////////////////////////////////////////////////////////
class RDNAttributeType : public AttributeType
{
	// перечислить зарегистрированные атрибуты RDN
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// зарегистрировать тип атрибута RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// отменить регистрацию тип атрибута RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// конструктор
	public: RDNAttributeType(const char* szOID) : AttributeType(szOID) {}

	// допустимые типы значений атрибута
	public: WINCRYPT_CALL std::vector<DWORD> ValueTypes() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип политики сертификата. Задает соответствие OID и отображаемого имени. 
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: CertificatePolicyType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
		// указать отображаемое имя 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// идентификатор способа использования
	public: const char* OID() const { return _strOID.c_str(); }
	// отображаемое имя 
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип расширенного использования ключа. Задает соответствие OID и 
// отображаемого имени. 
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: EnhancedKeyUsageType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
		// указать отображаемое имя 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// идентификатор способа использования
	public: const char* OID() const { return _strOID.c_str(); }
	// описание способа использования
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Значение в реестре для функций расширения
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionRegistryValue : public RegistryValueImpl
{
	// имя функции и идентификатор OID
	private: std::string _strFuncName; std::string _strOID; PCSTR _szOID; 

	// тип кодирования и имя значения  
	private: DWORD _dwEncodingType; std::wstring _szValue; 

	// тип и содержимое значения 
	private: DWORD _type; std::vector<BYTE> _value; 

	// конструктор
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, 
		PCWSTR szValue, DWORD type, LPCVOID pvValue, DWORD cbValue)

		// сохранить переданные параметры
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), 

		// сохранить переданные параметры
		_type(type), _value((CONST BYTE*)pvValue, (CONST BYTE*)pvValue + cbValue) 
	{
		// скопировать строковое представление OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// конструктор
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, PCWSTR szValue)

		// сохранить переданные параметры
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), _type(REG_NONE) 
	{
		// скопировать строковое представление OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// получить тип и размер параметра 
	protected: virtual DWORD GetType(PDWORD pcb) const override; 

	// получить значение параметра
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 

	// установить значение параметра
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Вызываемая функция расширения
///////////////////////////////////////////////////////////////////////////////
class FunctionExtension : public IFunctionExtension
{
	// описатель функции и ее адрес
	private: HCRYPTOIDFUNCADDR _hFuncAddr; PVOID _pvFuncAddr; BOOL _fClose; 

	// конструктор
	public: FunctionExtension(HCRYPTOIDFUNCADDR hFuncAddr, PVOID pvFuncAddr, BOOL fClose = FALSE)

		// сохранить переданные параметры
		: _hFuncAddr(hFuncAddr), _pvFuncAddr(pvFuncAddr), _fClose(fClose) {}

	// деструктор 
	public: virtual ~FunctionExtension() 
	{
		// уменьшить счетчик ссылок функции 
		if (_fClose && _hFuncAddr) ::CryptFreeOIDFunctionAddress(_hFuncAddr, 0); 
	}
	// адрес вызываемой функции расширения 
	public: virtual PVOID Address() const override { return _pvFuncAddr; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения для OID
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionOID : public IFunctionExtensionOID
{
	// описатель набора и имя функции
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 
	// тип кодирования и идентификатор OID
	private: DWORD _dwEncodingType; std::string _strOID; PCSTR _szOID;

	// конструктор
	public: FunctionExtensionOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)

		// сохранить ипереданные параметры 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID) 
	{
		// скопировать строковое представление
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// конструктор
	public: FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID); 

	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// тип кодирования 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID функции расширения 
	public: virtual PCSTR OID         () const override { return _szOID;               } 

	// перечислить параметры регистрации
	public: virtual std::vector<std::wstring> EnumRegistryValues() const override; 
	// получить параметр регистрации
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// получить параметр регистрации
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// перечислить установленные функции
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override;
	// установить функцию расширения 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения по умолчанию
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionDefaultOID : public IFunctionExtensionDefaultOID
{
	// описатель набора, имя функции и тип кодирования
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; DWORD _dwEncodingType;

	// конструктор
	public: FunctionExtensionDefaultOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType)

		// сохранить ипереданные параметры 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType) {}

	// конструктор
	public: FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType); 

	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// тип кодирования 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID функции расширения 
	public: virtual PCSTR OID         () const override { return CRYPT_DEFAULT_OID;    } 

	// перечислить параметры регистрации
	public: virtual std::vector<std::wstring> EnumRegistryValues() const override; 

	// получить параметр регистрации
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// получить параметр регистрации
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// получить список зарегистрированных модулей 
	public: virtual std::vector<std::wstring> EnumModules() const override; 
	// зарегистрировать модуль 
	public: virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const override; 
	// отменить регистрацию модуля 
	public: virtual void RemoveModule(PCWSTR szModule) const override; 

	// перечислить установленные функции
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override; 
	// установить функцию расширения 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const override; 
	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения 
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionSet : public IFunctionExtensionSet
{
	// описатель набора и имя функции
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 

	// конструктор
	public: FunctionExtensionSet(PCSTR szFuncName); 
	
	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 

	// получить набор функций расширения по умолчанию
	public: virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const override 
	{
		// получить набор функций расширения по умолчанию
		return std::shared_ptr<IFunctionExtensionDefaultOID>(
			new FunctionExtensionDefaultOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType)
		); 
	}
	// перечислить наборы функций расширения для OID
	public: virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const override; 

	// зарегистрировать функцию расширения для OID
	public: virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const override; 
	// отменить регистрацию функции расширения для OID
	public: virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const override; 
 
	// получить набор функций расширения для OID
	public: virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const override
	{
		// получить набор функций расширения для OID
		return std::shared_ptr<IFunctionExtensionOID>(
			new FunctionExtensionOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType, szOID)
		); 
	}
};
}}}
