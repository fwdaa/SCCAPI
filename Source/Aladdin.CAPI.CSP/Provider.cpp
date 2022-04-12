#include "stdafx.h"
#include "Provider.h"
#include "Container.h"
#include "Rand.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������� ����������
///////////////////////////////////////////////////////////////////////////
typedef BOOL (WINAPI* CRYPT_DLL_ENCODE_PUBLIC_KEY_AND_PARAMETERS)(
	DWORD dwEncoding,	            // [ in] ������ ����������� �����
	PCSTR pszOID,		            // [ in] ������������� ����� (OID)
	PVOID pvBlob,		            // [ in] ����� � ����������� �� ���������
	DWORD cbBlob,		            // [ in] ������ ������ � �����������
	DWORD dwFlags,		            // [ in] ��������������� �� �������
	PVOID pvAux,		            // [ in] ��������������� �� �������
	PVOID* ppvKey,		            // [out] �������������� ����
	PDWORD pcbKey,		            // [out] ������ ��������������� �����
	PVOID* ppvParams,	            // [out] �������������� ���������
	PDWORD pcbParams	            // [out] ������ �������������� ����������
);
typedef BOOL (WINAPI* CRYPT_DLL_CONVERT_PUBLIC_KEY_INFO)(
	DWORD dwEncoding,				// [ in] ������ ����������� �����
	PCERT_PUBLIC_KEY_INFO pInfo,	// [ in] �������������� ����
	ALG_ID algID,					// [ in] ������������� ���������
	DWORD dwFlags,					// [ in] ��������������� �� �������
	PVOID* ppvBlob,					// [out] �������������� �����
	PDWORD pcbBlob					// [out] ������ ��������������� ������
);
///////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::Provider::Provider(DWORD type, String^ name, bool sspi)
{$ 
	this->type = type;

	// ������� ��������� ����������
	handle   .Attach(gcnew ProviderHandle(type, name, CRYPT_VERIFYCONTEXT | CRYPT_SILENT, sspi)); 
	handleGUI.Attach(gcnew ProviderHandle(type, name, CRYPT_VERIFYCONTEXT               , sspi)); 

	// ������� ������ ������ ����������� ������
	keyFactories = gcnew Dictionary<String^, KeyFactory^>(); 
}

Aladdin::CAPI::CSP::Provider::~Provider() { $ } 

Aladdin::CAPI::IRandFactory^ 
Aladdin::CAPI::CSP::Provider::CreateRandFactory(SecurityObject^ scope, bool strong)
{$ 
	// ��� ������������� ����������
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// ������� ������� ����������� ����������
		return RefObject::AddRef((Container^)scope); 
	}
	// ������� ������� �����������
	else return RefObject::AddRef(this); 
} 

Aladdin::CAPI::IRand^ Aladdin::CAPI::CSP::Provider::CreateRand(Object^ window)
{$ 
	// ��� �������� ������������� ����
	HWND hwnd = NULL; if (window != nullptr)
	{
		// ������� ��������� ����
		hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 
	}
	// ������� ��������� ��������� ������
	if (hwnd == NULL) return gcnew Rand(handle.Get(), window);

	// ������� ��������� ��������� ������
	else return gcnew HardwareRand(handleGUI.Get(), window);
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportKey(
	Container^ container, KeyHandle^ hPrivateKey, 
	IntPtr pBlob, DWORD cbBlob, DWORD flags)
{$
	// ��� ����� �� ����������
	if (container != nullptr)
	{
		// ������������� ����
		return container->ImportKey(hPrivateKey, pBlob, cbBlob, flags);
	}
	else {
		// ������������� ����
		return Handle->ImportKey(hPrivateKey, pBlob, cbBlob, flags);
	}
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportKeyPair(
	Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
    // �������� �� ��������������
    throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportPublicKey(
	ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
	// ������������� ������������� �����
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, keyType); 

    // ������������ �������� ����
    ASN1::ISO::PKIX::SubjectPublicKeyInfo^ info = publicKey->Encoded; 

	// �������� �������������� ����
	array<BYTE>^ encoded = info->Encoded; DWORD cbEncoded = encoded->Length; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cbInfo = 0; 
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, 0, &cbInfo
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, pInfo, &cbInfo
	)); 
	// ����������� �������-����������
	HCRYPTOIDFUNCSET hFuncSet = ::CryptInitOIDFunctionSet("CryptDllConvertPublicKeyInfo", 0);

	// ��������� ���������� ������
	AE_CHECK_WINAPI(hFuncSet != 0); HCRYPTOIDFUNCADDR hFuncAddr;

	// �������� ������� ����������
	CRYPT_DLL_CONVERT_PUBLIC_KEY_INFO pvFuncAddress;  
	
    // ���������� ����� �������-����������
    AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(hFuncSet, 
		X509_ASN_ENCODING, pInfo->Algorithm.pszObjId, 0, (PVOID*)&pvFuncAddress, &hFuncAddr));
	try {
		// �������� �������������� �������� �����
		PVOID pvBlob; DWORD cbBlob; AE_CHECK_WINAPI((*pvFuncAddress)(
			X509_ASN_ENCODING, pInfo, algID, 0, &pvBlob, &cbBlob
		));
        // ��������� ������ �����
        return hContext->ImportKey(nullptr, IntPtr(pvBlob), cbBlob, 0); 
	}
	// ���������� ���������� �������
	finally { ::CryptFreeOIDFunctionAddress(hFuncAddr, 0); } 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CSP::Provider::ExportPublicKey(KeyHandle^ hPublicKey)
{$
    PVOID pvParams; DWORD cbParams; PVOID pvKey; DWORD cbKey; 

	// �������� ������������� �����
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// ������������ �������������
	array<BYTE>^ encodedOID = Encoding::UTF8->GetBytes(keyOID);

	// �������� ������ ��� ��������������
	std::vector<CHAR> szOID(encodedOID->Length + 1, 0); 

	// ����������� �������������
	Marshal::Copy(encodedOID, 0, IntPtr(&szOID[0]), encodedOID->Length); 

	// ����������� �������-����������
	HCRYPTOIDFUNCSET hFuncSet = ::CryptInitOIDFunctionSet(
		"CryptDllEncodePublicKeyAndParameters", 0
	); 
    // ��������� ���������� ������
    AE_CHECK_WINAPI(hFuncSet != 0); HCRYPTOIDFUNCADDR hFuncAddr;

	// �������� ������� ����������
	CRYPT_DLL_ENCODE_PUBLIC_KEY_AND_PARAMETERS pvFuncAddress;  

	// ���������� ����� �������-����������
	AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(hFuncSet, 
        X509_ASN_ENCODING, &szOID[0], 0, (PVOID*)&pvFuncAddress, &hFuncAddr
    ));
	try {
	    // ���������� ������ ������
	    DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	    // �������� ������ ��� ��������� ��������
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	    // �������������� �������� ����
	    cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(ptrBlob), cbBlob);

		// �������� �������������� �������� �����
		AE_CHECK_WINAPI((*pvFuncAddress)(X509_ASN_ENCODING, &szOID[0], 
			ptrBlob, cbBlob, 0, 0, &pvKey, &cbKey, &pvParams, &cbParams
		));
	}
	// ���������� ���������� �������
	finally { ::CryptFreeOIDFunctionAddress(hFuncAddr, 0); } 

    // ��� ������� �������������� ����������
    ASN1::IEncodable^ encodedParams = nullptr; if (cbParams > 0)
    {
        // �������� ����� ���������� �������
		array<BYTE>^ params = gcnew array<BYTE>(cbParams); 

		// ������� �������������� ���������
		Marshal::Copy(IntPtr(pvParams), params, 0, cbParams);

		// ������������� ���������
		encodedParams = ASN1::Encodable::Decode(params); 
    }
    // �������� ������ ��� ��������������� �����
    array<BYTE>^ key = gcnew array<BYTE>(cbKey); 
	
    // ������� �������������� ����
	Marshal::Copy(IntPtr(pvKey), key, 0, cbKey);

	// ������������ ����
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(key, cbKey * 8); 

	// ������������ ��������� � ���������������
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
    );  
	// ������� �������������� ���� � �����������
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::CSP::Provider::GetPrivateKey(SecurityObject^ scope, 
	IPublicKey^ publicKey, KeyHandle^ hKeyPair, DWORD keyType)
{
	// ������� ������������� �����
	array<BYTE>^ keyID = gcnew array<BYTE>{ (BYTE)keyType }; 

	// ������� ������ ����
	return gcnew PrivateKey(this, scope, publicKey, hKeyPair, keyID, keyType); 
}
