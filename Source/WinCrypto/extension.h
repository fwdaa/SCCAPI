#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace Extension { 

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////

// �������� X.509-������������� ��������� �����
std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID);
std::vector<BYTE> CspExportPublicKey(HCRYPTKEY  hKey,                      PCSTR szKeyOID);

// ������������� X.509-������������� ��������� �����
HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID);

// �������� PKCS8-������������� ������� ����� �� ����������  
std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID);

// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec, 
	const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags
);
// �������� X.509-������������� ��������� ����� ��� ��������� 
std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec);

// ������������� X.509-������������� ��������� �����
BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec);

// �������� PKCS8-������������� ������� �����
std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec); 

// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR szProvider,
	const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec
); 
// �������� X.509-������������� ��������� ����� ��� ��������� 
std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec); 

// ������������� X.509-������������� ��������� �����
NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec);

// �������� PKCS8-������������� ������� �����
std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec); 

// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
	const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec
);

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory { virtual ~IKeyFactory() {}

	// �������� X.509-������������� ��������� ����� ��� BLOB
	virtual std::vector<BYTE> CspEncodePublicKey(PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const; 

	// �������� BLOB ��������� ����� ��� X.509-�������������
	virtual std::vector<BYTE> CspConvertPublicKey(const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const; 

	// �������� X.509-������������� ��������� �����
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const;
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTKEY  hKey,                      PCSTR szKeyOID) const;

	// ������������� X.509-������������� ��������� �����
	virtual HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const;

	// �������� PKCS8-������������� ������� ����� �� ����������  
	virtual std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const;

	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec, 
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags) const;

	// �������� X.509-������������� ��������� ����� ��� ��������� 
	virtual std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const;

	// ������������� X.509-������������� ��������� �����
	virtual BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const;

	// �������� PKCS8-������������� ������� �����
	virtual std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE, PCSTR, DWORD) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR, const CERT_PUBLIC_KEY_INFO*, const CRYPT_PRIVATE_KEY_INFO*, DWORD) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return NULL; 
	}
	// �������� X.509-������������� ��������� ����� ��� ��������� 
	virtual std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const;

	// ������������� X.509-������������� ��������� �����
	virtual NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const;

	// �������� PKCS8-������������� ������� �����
	virtual std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const;

	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
		const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const;
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public IPublicKey 
{ 
	// ��� ������� CSP
	public: virtual const wchar_t* TypeCSP() const { return nullptr; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// ��� ������� CNG
	public: virtual const wchar_t* TypeCNG() const { return BCRYPT_PUBLIC_KEY_BLOB; }
	// ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const 
	{ 
		// ��������� ��� �������
		return std::shared_ptr<NCryptBufferDesc>(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair 
{ 
	// ��� ������� CSP
	public: virtual const wchar_t* TypeCSP() const { return nullptr; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
	// ��� ������� CNG
	public: virtual const wchar_t* TypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }
	// ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const 
	{ 
		// ��������� ��� �������
		return std::shared_ptr<NCryptBufferDesc>(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::vector<BYTE>(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� ��� ��������� ����� ������
///////////////////////////////////////////////////////////////////////////////
struct KeyFactory : IKeyFactory
{
	// ��� �������� CSP
	virtual DWORD ExportFlagsCSP() const { return 0; } 

	// ��� �������� CNG
	virtual PCWSTR ExportPublicTypeCNG () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	virtual PCWSTR ExportPrivateTypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }

	// �������� �������������� ������ ��� ���������
	virtual std::shared_ptr<void> GetAuxDataCNG(BCRYPT_KEY_HANDLE hKey, ULONG magic) const { return std::shared_ptr<void>(); }
	virtual std::shared_ptr<void> GetAuxDataCNG(NCRYPT_KEY_HANDLE hKey, ULONG magic) const { return std::shared_ptr<void>(); }

	// ������������� �������� ����
	virtual std::shared_ptr<PublicKey> DecodePublicKey(const CERT_PUBLIC_KEY_INFO&) const = 0; 
	// ������������� �������� ����
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR, const PUBLICKEYSTRUC*, size_t) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// ������������� �������� ����
	virtual std::shared_ptr<PublicKey> DecodePublicKey(PCSTR, LPCVOID, const BCRYPT_KEY_BLOB*, size_t) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::shared_ptr<PublicKey>(); 
	}
	// ������������� ���� ������
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(const CRYPT_PRIVATE_KEY_INFO&, const CERT_PUBLIC_KEY_INFO*) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// ������������� ���� ������
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(PCSTR, const BLOBHEADER*, size_t) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// ������������� ���� ������
	virtual std::shared_ptr<KeyPair> DecodeKeyPair(PCSTR, LPCVOID, const BCRYPT_KEY_BLOB*, size_t) const
	{
		// ������� ������ ���� ��������������
		ThrowNotSupported(); return std::shared_ptr<KeyPair>(); 
	}
	// �������� X.509-������������� ��������� ����� ��� BLOB
	virtual std::vector<BYTE> CspEncodePublicKey(PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// �������� X.509-������������� ��������� ����� ��� BLOB
		return DecodePublicKey(szKeyOID, pBlob, cbBlob)->Encode(); 
	}
	// �������� BLOB ��������� ����� ��� X.509-�������������
	virtual std::vector<BYTE> CspConvertPublicKey(const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const override
	{
		// �������� BLOB ��������� ����� ��� X.509-�������������
		return DecodePublicKey(*pInfo)->BlobCSP(algID); 
	}
	// �������� X.509-������������� ��������� ����� �� ����������  
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const override;

	// �������� X.509-������������� ��������� ����� ��� ��������� 
	virtual std::vector<BYTE> CspExportPublicKey(HCRYPTKEY hKey, PCSTR szKeyOID) const override;

	// ������������� X.509-������������� ��������� �����
	virtual HCRYPTKEY CspImportPublicKey(HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const override;

	// �������� PKCS8-������������� ������� ����� �� ����������  
	virtual std::vector<BYTE> CspExportPrivateKey(HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const override;

	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual HCRYPTKEY CspImportKeyPair(HCRYPTPROV hContainer, DWORD keySpec,
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags) const override;

	// �������� X.509-������������� ��������� ����� ��� ��������� 
	virtual std::vector<BYTE> BCryptExportPublicKey(BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const override;

	// ������������� X.509-������������� ��������� �����
	virtual BCRYPT_KEY_HANDLE BCryptImportPublicKey(PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const override;

	// �������� PKCS8-������������� ������� �����
	virtual std::vector<BYTE> BCryptExportPrivateKey(BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const override;

	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual BCRYPT_KEY_HANDLE BCryptImportKeyPair(PCWSTR szProvider, 
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const override;

	// �������� X.509-������������� ��������� ����� ��� ��������� 
	virtual std::vector<BYTE> NCryptExportPublicKey(NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec) const override;

	// ������������� X.509-������������� ��������� �����
	virtual NCRYPT_KEY_HANDLE NCryptImportPublicKey(NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const override;

	// �������� PKCS8-������������� ������� �����
	virtual std::vector<BYTE> NCryptExportPrivateKey(NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const override;

	// ������������� X.509- � PKCS8-������������� ���� ������� � ���������
	virtual void NCryptImportKeyPair(NCRYPT_KEY_HANDLE hKeyPair,
		const CERT_PUBLIC_KEY_INFO*	pPublicInfo, const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const override;
};

///////////////////////////////////////////////////////////////////////////////
// ������������������ ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// �������� ������������������ ����������
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}
// ����� ���������� ��������� ����� 
WINCRYPT_CALL PCCRYPT_OID_INFO FindPublicKeyOID(PCSTR szKeyOID, DWORD keySpec); 

///////////////////////////////////////////////////////////////////////////////
// ��� �������� ��� ����������. ������ ������������ OID � ������������� �����. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
	// ����������� ������������������ ���� ���������
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� ��������
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: AttributeType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
 		// ������� ������������ ��� 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	} 
	// ������������� ��������
	public: const char* OID() const { return _strOID.c_str(); }
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� �������� RDN. ������ ������������ OID, ����������� X.500-�������������� 
// ��� OID, � ����� ������ ���������� ����� CERT_RDN_*, ���������������� � 
// ������� ������������.
///////////////////////////////////////////////////////////////////////////////
class RDNAttributeType : public AttributeType
{
	// ����������� ������������������ �������� RDN
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// ���������������� ��� �������� RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// �������� ����������� ��� �������� RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// �����������
	public: RDNAttributeType(const char* szOID) : AttributeType(szOID) {}

	// ���������� ���� �������� ��������
	public: WINCRYPT_CALL std::vector<DWORD> ValueTypes() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� �������� �����������. ������ ������������ OID � ������������� �����. 
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: CertificatePolicyType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
		// ������� ������������ ��� 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// ������������� ������� �������������
	public: const char* OID() const { return _strOID.c_str(); }
	// ������������ ��� 
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� ������������ ������������� �����. ������ ������������ OID � 
// ������������� �����. 
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<std::string> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: EnhancedKeyUsageType(const char* szOID) : _strOID(szOID), _name(L"OID.")
	{
		// ������� ������������ ��� 
		for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// ������������� ������� �������������
	public: const char* OID() const { return _strOID.c_str(); }
	// �������� ������� �������������
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionRegistryValue : public RegistryValueImpl
{
	// ��� ������� � ������������� OID
	private: std::string _strFuncName; std::string _strOID; PCSTR _szOID; 

	// ��� ����������� � ��� ��������  
	private: DWORD _dwEncodingType; std::wstring _szValue; 

	// ��� � ���������� �������� 
	private: DWORD _type; std::vector<BYTE> _value; 

	// �����������
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, 
		PCWSTR szValue, DWORD type, LPCVOID pvValue, DWORD cbValue)

		// ��������� ���������� ���������
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), 

		// ��������� ���������� ���������
		_type(type), _value((CONST BYTE*)pvValue, (CONST BYTE*)pvValue + cbValue) 
	{
		// ����������� ��������� ������������� OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �����������
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, PCWSTR szValue)

		// ��������� ���������� ���������
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), _type(REG_NONE) 
	{
		// ����������� ��������� ������������� OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �������� ��� � ������ ��������� 
	protected: virtual DWORD GetType(PDWORD pcb) const override; 

	// �������� �������� ���������
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 

	// ���������� �������� ���������
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtension : public IFunctionExtension
{
	// ��������� ������� � �� �����
	private: HCRYPTOIDFUNCADDR _hFuncAddr; PVOID _pvFuncAddr; BOOL _fClose; 

	// �����������
	public: FunctionExtension(HCRYPTOIDFUNCADDR hFuncAddr, PVOID pvFuncAddr, BOOL fClose = FALSE)

		// ��������� ���������� ���������
		: _hFuncAddr(hFuncAddr), _pvFuncAddr(pvFuncAddr), _fClose(fClose) {}

	// ���������� 
	public: virtual ~FunctionExtension() 
	{
		// ��������� ������� ������ ������� 
		if (_fClose && _hFuncAddr) ::CryptFreeOIDFunctionAddress(_hFuncAddr, 0); 
	}
	// ����� ���������� ������� ���������� 
	public: virtual PVOID Address() const override { return _pvFuncAddr; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionOID : public IFunctionExtensionOID
{
	// ��������� ������ � ��� �������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 
	// ��� ����������� � ������������� OID
	private: DWORD _dwEncodingType; std::string _strOID; PCSTR _szOID;

	// �����������
	public: FunctionExtensionOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)

		// ��������� ����������� ��������� 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID) 
	{
		// ����������� ��������� �������������
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �����������
	public: FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID); 

	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// ��� ����������� 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID ������� ���������� 
	public: virtual PCSTR OID         () const override { return _szOID;               } 

	// ����������� ��������� �����������
	public: virtual std::vector<std::wstring> EnumRegistryValues() const override; 
	// �������� �������� �����������
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// �������� �������� �����������
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// ����������� ������������� �������
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override;
	// ���������� ������� ���������� 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionDefaultOID : public IFunctionExtensionDefaultOID
{
	// ��������� ������, ��� ������� � ��� �����������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; DWORD _dwEncodingType;

	// �����������
	public: FunctionExtensionDefaultOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType)

		// ��������� ����������� ��������� 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType) {}

	// �����������
	public: FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType); 

	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// ��� ����������� 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID ������� ���������� 
	public: virtual PCSTR OID         () const override { return CRYPT_DEFAULT_OID;    } 

	// ����������� ��������� �����������
	public: virtual std::vector<std::wstring> EnumRegistryValues() const override; 

	// �������� �������� �����������
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// �������� �������� �����������
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// �������� ������ ������������������ ������� 
	public: virtual std::vector<std::wstring> EnumModules() const override; 
	// ���������������� ������ 
	public: virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const override; 
	// �������� ����������� ������ 
	public: virtual void RemoveModule(PCWSTR szModule) const override; 

	// ����������� ������������� �������
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override; 
	// ���������� ������� ���������� 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const override; 
	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionSet : public IFunctionExtensionSet
{
	// ��������� ������ � ��� �������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 

	// �����������
	public: FunctionExtensionSet(PCSTR szFuncName); 
	
	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 

	// �������� ����� ������� ���������� �� ���������
	public: virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const override 
	{
		// �������� ����� ������� ���������� �� ���������
		return std::shared_ptr<IFunctionExtensionDefaultOID>(
			new FunctionExtensionDefaultOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType)
		); 
	}
	// ����������� ������ ������� ���������� ��� OID
	public: virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const override; 

	// ���������������� ������� ���������� ��� OID
	public: virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const override; 
	// �������� ����������� ������� ���������� ��� OID
	public: virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const override; 
 
	// �������� ����� ������� ���������� ��� OID
	public: virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const override
	{
		// �������� ����� ������� ���������� ��� OID
		return std::shared_ptr<IFunctionExtensionOID>(
			new FunctionExtensionOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType, szOID)
		); 
	}
};
}}}
