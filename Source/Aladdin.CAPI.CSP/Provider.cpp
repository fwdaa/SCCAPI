#include "stdafx.h"
#include "Provider.h"
#include "Container.h"
#include "Rand.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Прототип функции расширения
///////////////////////////////////////////////////////////////////////////
typedef BOOL (WINAPI* CRYPT_DLL_ENCODE_PUBLIC_KEY_AND_PARAMETERS)(
	DWORD dwEncoding,	            // [ in] способ кодирования ключа
	PCSTR pszOID,		            // [ in] идентификатор ключа (OID)
	PVOID pvBlob,		            // [ in] буфер с информацией об алгоритме
	DWORD cbBlob,		            // [ in] размер буфера с информацией
	DWORD dwFlags,		            // [ in] зарезервировано на будущее
	PVOID pvAux,		            // [ in] зарезервировано на будущее
	PVOID* ppvKey,		            // [out] закодированный ключ
	PDWORD pcbKey,		            // [out] размер закодированного ключа
	PVOID* ppvParams,	            // [out] закодированные параметры
	PDWORD pcbParams	            // [out] размер закодированных параметров
);
typedef BOOL (WINAPI* CRYPT_DLL_CONVERT_PUBLIC_KEY_INFO)(
	DWORD dwEncoding,				// [ in] способ кодирования ключа
	PCERT_PUBLIC_KEY_INFO pInfo,	// [ in] закодированный ключ
	ALG_ID algID,					// [ in] идентификатор алгоритма
	DWORD dwFlags,					// [ in] зарезервировано на будущее
	PVOID* ppvBlob,					// [out] закодированный буфер
	PDWORD pcbBlob					// [out] размер закодированного буфера
);
///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::Provider::Provider(DWORD type, String^ name, bool sspi)
{$ 
	this->type = type;

	// открыть описатели провайдера
	handle   .Attach(gcnew ProviderHandle(type, name, CRYPT_VERIFYCONTEXT | CRYPT_SILENT, sspi)); 
	handleGUI.Attach(gcnew ProviderHandle(type, name, CRYPT_VERIFYCONTEXT               , sspi)); 

	// создать список фабрик кодирования ключей
	keyFactories = gcnew Dictionary<String^, KeyFactory^>(); 
}

Aladdin::CAPI::CSP::Provider::~Provider() { $ } 

Aladdin::CAPI::IRandFactory^ 
Aladdin::CAPI::CSP::Provider::CreateRandFactory(SecurityObject^ scope, bool strong)
{$ 
	// при использовании контейнера
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// указать фабрику генераторов контейнера
		return RefObject::AddRef((Container^)scope); 
	}
	// указать фабрику генераторов
	else return RefObject::AddRef(this); 
} 

Aladdin::CAPI::IRand^ Aladdin::CAPI::CSP::Provider::CreateRand(Object^ window)
{$ 
	// при указании родительского окна
	HWND hwnd = NULL; if (window != nullptr)
	{
		// извлечь описатель окна
		hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 
	}
	// создать генератор случайных данных
	if (hwnd == NULL) return gcnew Rand(handle.Get(), window);

	// создать генератор случайных данных
	else return gcnew HardwareRand(handleGUI.Get(), window);
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportKey(
	Container^ container, KeyHandle^ hPrivateKey, 
	IntPtr pBlob, DWORD cbBlob, DWORD flags)
{$
	// для ключа из контейнера
	if (container != nullptr)
	{
		// импортировать ключ
		return container->ImportKey(hPrivateKey, pBlob, cbBlob, flags);
	}
	else {
		// импортировать ключ
		return Handle->ImportKey(hPrivateKey, pBlob, cbBlob, flags);
	}
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportKeyPair(
	Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
    // операция не поддерживается
    throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Provider::ImportPublicKey(
	ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
	// преобразовать идентификатор ключа
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, keyType); 

    // закодировать открытый ключ
    ASN1::ISO::PKIX::SubjectPublicKeyInfo^ info = publicKey->Encoded; 

	// получить закодированный ключ
	array<BYTE>^ encoded = info->Encoded; DWORD cbEncoded = encoded->Length; 

	// получить адрес буфера
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cbInfo = 0; 
	
	// определить требуемый размер памяти
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, 0, &cbInfo
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// раскодировать открытый ключ
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, 
		ptrEncoded, cbEncoded, CRYPT_DECODE_NOCOPY_FLAG, pInfo, &cbInfo
	)); 
	// перечислить функции-расширения
	HCRYPTOIDFUNCSET hFuncSet = ::CryptInitOIDFunctionSet("CryptDllConvertPublicKeyInfo", 0);

	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(hFuncSet != 0); HCRYPTOIDFUNCADDR hFuncAddr;

	// объявить функцию расширения
	CRYPT_DLL_CONVERT_PUBLIC_KEY_INFO pvFuncAddress;  
	
    // определить адрес функции-расширения
    AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(hFuncSet, 
		X509_ASN_ENCODING, pInfo->Algorithm.pszObjId, 0, (PVOID*)&pvFuncAddress, &hFuncAddr));
	try {
		// получить закодированное значение ключа
		PVOID pvBlob; DWORD cbBlob; AE_CHECK_WINAPI((*pvFuncAddress)(
			X509_ASN_ENCODING, pInfo, algID, 0, &pvBlob, &cbBlob
		));
        // выполнить импорт ключа
        return hContext->ImportKey(nullptr, IntPtr(pvBlob), cbBlob, 0); 
	}
	// освободить выделенные ресурсы
	finally { ::CryptFreeOIDFunctionAddress(hFuncAddr, 0); } 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CSP::Provider::ExportPublicKey(KeyHandle^ hPublicKey)
{$
    PVOID pvParams; DWORD cbParams; PVOID pvKey; DWORD cbKey; 

	// получить идентификатор ключа
	String^ keyOID = ConvertKeyOID(hPublicKey->GetLong(KP_ALGID, 0)); 

	// закодировать идентификатор
	array<BYTE>^ encodedOID = Encoding::UTF8->GetBytes(keyOID);

	// выделить память для идентификатора
	std::vector<CHAR> szOID(encodedOID->Length + 1, 0); 

	// скопировать идентификатор
	Marshal::Copy(encodedOID, 0, IntPtr(&szOID[0]), encodedOID->Length); 

	// перечислить функции-расширения
	HCRYPTOIDFUNCSET hFuncSet = ::CryptInitOIDFunctionSet(
		"CryptDllEncodePublicKeyAndParameters", 0
	); 
    // проверить отсутствие ошибок
    AE_CHECK_WINAPI(hFuncSet != 0); HCRYPTOIDFUNCADDR hFuncAddr;

	// объявить функцию расширения
	CRYPT_DLL_ENCODE_PUBLIC_KEY_AND_PARAMETERS pvFuncAddress;  

	// определить адрес функции-расширения
	AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(hFuncSet, 
        X509_ASN_ENCODING, &szOID[0], 0, (PVOID*)&pvFuncAddress, &hFuncAddr
    ));
	try {
	    // определить размер буфера
	    DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	    // выделить память для структуры экспорта
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	    // экспортировать открытый ключ
	    cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(ptrBlob), cbBlob);

		// получить закодированное значение ключа
		AE_CHECK_WINAPI((*pvFuncAddress)(X509_ASN_ENCODING, &szOID[0], 
			ptrBlob, cbBlob, 0, 0, &pvKey, &cbKey, &pvParams, &cbParams
		));
	}
	// освободить выделенные ресурсы
	finally { ::CryptFreeOIDFunctionAddress(hFuncAddr, 0); } 

    // при наличии закодированных параметров
    ASN1::IEncodable^ encodedParams = nullptr; if (cbParams > 0)
    {
        // выделить буфер требуемого размера
		array<BYTE>^ params = gcnew array<BYTE>(cbParams); 

		// извлечь закодированные параметры
		Marshal::Copy(IntPtr(pvParams), params, 0, cbParams);

		// раскодировать параметры
		encodedParams = ASN1::Encodable::Decode(params); 
    }
    // выделить память для закодированного ключа
    array<BYTE>^ key = gcnew array<BYTE>(cbKey); 
	
    // извлечь закодированный ключ
	Marshal::Copy(IntPtr(pvKey), key, 0, cbKey);

	// закодировать ключ
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(key, cbKey * 8); 

	// закодировать параметры с идентификатором
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
    );  
	// вернуть закодированный ключ с параметрами
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::CSP::Provider::GetPrivateKey(SecurityObject^ scope, 
	IPublicKey^ publicKey, KeyHandle^ hKeyPair, DWORD keyType)
{
	// указать идентификатор ключа
	array<BYTE>^ keyID = gcnew array<BYTE>{ (BYTE)keyType }; 

	// создать личный ключ
	return gcnew PrivateKey(this, scope, publicKey, hKeyPair, keyID, keyType); 
}
