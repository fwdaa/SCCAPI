#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace Extension { 

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
BOOL CryptDllEncodePublicKeyAndParameters(
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	PVOID							pvBlob,					// [in    ] закодированный буфер в формате BLOB
	DWORD							cbBlob,					// [in    ] размер закодированного буфера
	DWORD							dwFlags,				// [in    ] зарезервировано на будущее
	PVOID							pvAuxInfo,				// [in    ] зарезервировано на будущее
	PVOID*							ppvKey,					// [   out] закодированный ключ в кодировке X.509      (LocalAlloc)
	PDWORD							pcbKey,					// [   out] размер закодированного ключа
	PVOID*							ppvParams,				// [   out] закодированные параметры в кодировке X.509 (LocalAlloc)
	PDWORD							pcbParams				// [   out] размер закодированных параметров
); 
BOOL CryptDllConvertPublicKeyInfo(
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
	ALG_ID							algID,					// [in    ] идентификатор алгоритма
	DWORD							dwFlags,				// [in    ] зарезервировано на будущее
	PVOID*							ppvBlob,				// [   out] закодированный буфер в формате BLOB
	PDWORD							pcbBlob					// [   out] размер закодированного буфера
); 
BOOL CryptDllExportPublicKeyInfoEx(
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE	hProviderOrKey,			// [in    ] описатель провайдера или ключа
	DWORD							dwKeySpec,				// [in    ] слот ключа для провайдера
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] назначение ключа
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllExportPublicKeyInfoEx(
	HCRYPTKEY						hKey,					// [in    ] описатель провайдера или ключа
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] назначение ключа
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllExportPrivateKeyInfoEx(
	HCRYPTPROV						hProvider,				// [in    ] описатель провайдера
	DWORD							dwKeySpec,				// [in    ] слот ключа для провайдера
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] 0 (при pInfo = 0) или 0x8000
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCRYPT_PRIVATE_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке PKCS8
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllExportPrivateKeyInfoEx(
	HCRYPTKEY						hKey,					// [in    ] описатель провайдера или ключа
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] 0 (при pInfo = 0) или 0x8000
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCRYPT_PRIVATE_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке PKCS8
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllExportPublicKeyInfoEx2(
	NCRYPT_KEY_HANDLE				hKey,					// [in    ] описатель провайдера или ключа
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] назначение ключа
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllImportPublicKeyInfoEx(
	HCRYPTPROV						hProvider,				// [in    ] описатель провайдера
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
	ALG_ID							algID,					// [in    ] идентификатор алгориитма
	DWORD							dwFlags,				// [in    ] зарезервировано на будущее
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	HCRYPTKEY*						phPublicKey				// [   out] описатель импортированного ключа
);
BOOL CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
	BCRYPT_KEY_HANDLE				hKey,					// [in    ] описатель открытого ключа
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,				// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,				// [in    ] назначение ключа
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
	PDWORD							pcbInfo					// [in/out] размер описания ключа
);
BOOL CryptDllImportPublicKeyInfoEx2(
	PCWSTR							szProvider,				// [in    ] имя провайдера 
	DWORD							dwEncoding,				// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
	DWORD							dwFlags,				// [in    ] назначение ключа
	PVOID							pvAuxInfo,				// [in    ] дополнительные данные
	BCRYPT_KEY_HANDLE*				phPublicKey				// [   out] описатель импортированного ключа
);
///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public ::Crypto::IPublicKey 
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
class KeyPair : public ::Crypto::IKeyPair 
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

/*
///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
BOOL WINAPI CryptDllImportPrivateKeyInfoEx(
    HCRYPTPROV						hCryptProv,				// [in    ] описатель провайдера
    PCRYPT_PRIVATE_KEY_INFO			pPrivateKeyInfo,		// [in    ] описание ключа в кодировке PKCS8
    DWORD							dwFlags,				// [in    ] флаги способа импорта ключа
    PVOID							pvAuxInfo				// [in    ] дополнительные данные
);
*/
///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
struct KeyFactory { virtual ~KeyFactory() {}

	// тип экспорта CSP
	virtual DWORD ExportFlagsCSP() const { return 0; } 

	// тип экспорта CNG
	virtual PCWSTR ExportPublicTypeCNG () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	virtual PCWSTR ExportPrivateTypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }

	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(const CERT_PUBLIC_KEY_INFO&) const = 0; 
	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR szOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// раскодировать пару ключей
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(PCSTR szOID, const BLOBHEADER* pBlob, size_t cbBlob) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// раскодировать открытый ключ
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const
	{
		// функция должна быть переопределена
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// функции расширения 
	BOOL CryptDllEncodePublicKeyAndParameters(
		PCSTR							pszKeyOID,				// [in    ] идентификатор ключа (OID)
		PVOID							pvBlob,					// [in    ] закодированный буфер в формате BLOB
		DWORD							cbBlob,					// [in    ] размер закодированного буфера
		DWORD							dwFlags,				// [in    ] зарезервировано на будущее
		PVOID							pvAuxInfo,				// [in    ] зарезервировано на будущее
		PVOID*							ppvKey,					// [   out] закодированный ключ в кодировке X.509      (LocalAlloc)
		PDWORD							pcbKey,					// [   out] размер закодированного ключа
		PVOID*							ppvParams,				// [   out] закодированные параметры в кодировке X.509 (LocalAlloc)
		PDWORD							pcbParams				// [   out] размер закодированных параметров
	) const; 
	BOOL CryptDllConvertPublicKeyInfo(
		CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
		ALG_ID							algID,					// [in    ] идентификатор алгоритма
		DWORD							dwFlags,				// [in    ] зарезервировано на будущее
		PVOID*							ppvBlob,				// [   out] закодированный буфер в формате BLOB
		PDWORD							pcbBlob					// [   out] размер закодированного буфера
	) const; 
	BOOL CryptDllExportPublicKeyInfoEx(
		HCRYPTKEY						hKey,					// [in    ] описатель ключа
		PCSTR							pszKeyOID,				// [in    ] идентификатор ключа (OID)
		DWORD							dwFlags,				// [in    ] назначение ключа
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
		PDWORD							pcbInfo					// [in/out] размер описания ключа
	) const;
	BOOL CryptDllExportPrivateKeyInfoEx(
		HCRYPTKEY						hKey,					// [in    ] описатель ключа
		PCSTR							pszKeyOID,				// [in    ] идентификатор ключа (OID)
		DWORD							dwFlags,                // [in    ] 0 (при pcbPrivateKeyInfo = 0) или 0x8000
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		PCRYPT_PRIVATE_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке PKCS8
		PDWORD							pcbInfo					// [in/out] размер описания ключа
	) const;
	BOOL CryptDllExportPublicKeyInfoEx2(
		NCRYPT_KEY_HANDLE				hKey,					// [in    ] описатель провайдера
		PCSTR							pszKeyOID,				// [in    ] идентификатор ключа (OID)
		DWORD							dwFlags,				// [in    ] назначение ключа
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
		PDWORD							pcbInfo					// [in/out] размер описания ключа
	) const;
	BOOL CryptDllImportPublicKeyInfoEx(
		HCRYPTPROV						hProvider,				// [in    ] описатель провайдера
		CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
		ALG_ID							algID,					// [in    ] идентификатор алгориитма
		DWORD							dwFlags,				// [in    ] зарезервировано на будущее
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		HCRYPTKEY*						phPublicKey				// [   out] описатель импортированного ключа
	) const;
	BOOL CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
		BCRYPT_KEY_HANDLE				hKey,					// [in    ] описатель открытого ключа
		PCSTR							pszKeyOID,				// [in    ] идентификатор ключа (OID)
		DWORD							dwFlags,				// [in    ] назначение ключа
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] описание ключа в кодировке X.509
		PDWORD							pcbInfo					// [in/out] размер описания ключа
	) const;
	BOOL CryptDllImportPublicKeyInfoEx2(
		PCWSTR							szProvider,				// [in    ] имя провайдера 
		CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] описание ключа в кодировке X.509
		DWORD							dwFlags,				// [in    ] назначение ключа
		PVOID							pvAuxInfo,				// [in    ] дополнительные данные
		BCRYPT_KEY_HANDLE*				phKey					// [   out] описатель импортированного ключа
	) const;
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
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 
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
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 

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

