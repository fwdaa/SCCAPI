#include "stdafx.h"
#include "Generator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Generator.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CSP::KeyPairGenerator::Generate(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD keyType = AT_KEYEXCHANGE;

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// указать идентификатор
	if ((keyUsage & signMask) != KeyUsage::None) keyType = AT_SIGNATURE; 
	if ((keyUsage & keyxMask) != KeyUsage::None) keyType = AT_KEYEXCHANGE; 

	// сгенерировать пару ключей
	Using<KeyHandle^> hKeyPair(Generate(nullptr, keyOID, keyType, 0)); 

	// экспортировать открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
        Provider->ExportPublicKey(hKeyPair.Get()); 

    // раскодировать открытый ключ
    CAPI::IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// получить личный ключ
	Using<IPrivateKey^> privateKey(Provider->GetPrivateKey(
		Scope, publicKey, hKeyPair.Get(), keyType
	)); 
    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CSP::KeyPairGenerator::Generate(
	array<BYTE>^ keyID, String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
{$
    // проверить указание контейнера
    if (dynamic_cast<Container^>(Scope) == nullptr) return Generate(keyOID, keyUsage);  

	// преобразовать тип контейнера
	Container^ container = (Container^)Scope; 

	// при указании идентификатора
	DWORD keyType = 0; if (keyID != nullptr)
	{
		// проверить корректность идентификатора
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID); keyType = keyID[0];
	}
	// определить тип ключа 
	if (keyType == 0) keyType = container->GetKeyType(keyOID, keyUsage); 

	// при ошибке выбросить исключение
	if (keyType == 0) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // указать признак экспортируемости
    DWORD flags = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None) ? CRYPT_EXPORTABLE : 0; 

	// сгенерировать пару ключей
	Using<KeyHandle^> hKeyPair(Generate(container, keyOID, keyType, flags)); 

	// экспортировать открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// раскодировать открытый ключ
	IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// получить личный ключ
	Using<CSP::PrivateKey^> privateKey(Provider->GetPrivateKey(
		container, publicKey, hKeyPair.Get(), keyType
	)); 
	// вернуть созданную пару ключей
	return gcnew KeyPair(publicKey, privateKey.Get(), privateKey.Get()->KeyID);  
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::KeyPairGenerator::Generate(CSP::Container^ container, ALG_ID algID, DWORD flags)
{$
	// сгенерировать эфемерный ключ
	if (container == nullptr) return Provider->Handle->GenerateKey(algID, flags);

	// при указании родительского окна
	IntPtr hwnd = IntPtr::Zero; if (Rand->Window != nullptr)
	{
		// извлечь описатель окна
		hwnd = ((IWin32Window^)Rand->Window)->Handle; 
	}
	// сгенерировать ключ в контейнере
	return container->GenerateKeyPair(hwnd, algID, flags);
}
