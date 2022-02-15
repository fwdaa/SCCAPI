#include "stdafx.h"
#include "Generator.h"
#include "Provider.h"
#include "Key.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Generator.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
//////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD keyID = AT_KEYEXCHANGE; 

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// указать идентификатор
	if ((keyUsage & signMask) != KeyUsage::None) keyID = AT_SIGNATURE; 
	if ((keyUsage & keyxMask) != KeyUsage::None) keyID = AT_KEYEXCHANGE; 

	// сгенерировать пару ключей
	Using<NKeyHandle^> hKeyPair(Generate(nullptr, keyOID, keyID, TRUE));

	// экспортировать открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
        Provider->ExportPublicKey(hKeyPair.Get()); 

    // раскодировать открытый ключ
    CAPI::IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo);
 
	// получить личный ключ
	Using<IPrivateKey^> privateKey(Provider->GetPrivateKey(Scope, publicKey, hKeyPair.Get())); 

    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

Aladdin::CAPI::KeyPair^ Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(
	array<BYTE>^ keyID, String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
{$
    // проверить указание контейнера
    if (dynamic_cast<Container^>(Scope) == nullptr) return Generate(keyOID, keyUsage); 

	// преобразовать тип контейнера
	Container^ container = (Container^)Scope; if (keyID != nullptr)
	{
		// проверить корректность идентификатора
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID);
	}
	// создать идентификатор ключа 
	else keyID = container->GetKeyID(keyUsage); 
    
    // при ошибке выбросить исключение
    if (keyID == nullptr) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // указать признак экспортируемости
    BOOL exportable = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None);  

	// сгенерировать пару ключей
	Using<NKeyHandle^> hKeyPair(Generate(container, keyOID, keyID[0], exportable));

    // получить открытый ключ
    CAPI::IPublicKey^ publicKey = container->GetPublicKey(keyID);

    // получить личный ключ 
	Using<CAPI::IPrivateKey^> privateKey(container->GetPrivateKey(keyID)); 

    // вернуть созданную пару ключей
    return gcnew KeyPair(publicKey, privateKey.Get(), keyID);  
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::NKeyPairGenerator::Generate(Container^ container, String^ alg, 
	DWORD keyType, BOOL exportable, Action<Handle^>^ action, DWORD flags)
{$
	// при указании родительского окна
	IntPtr hwnd = IntPtr::Zero; if (Rand->Window != nullptr)
	{
		// извлечь описатель окна
		hwnd = ((IWin32Window^)Rand->Window)->Handle; 
	}
    // выполнить генерацию пары в контейнере
    if (container != nullptr) return container->GenerateKeyPair(hwnd, alg, keyType, exportable, action, flags);  

	// определить режим создания ключа
	DWORD createFlags = flags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);

	// определить режим завершения создания ключа
	DWORD finalizeFlags = (flags & ~createFlags) | NCRYPT_SILENT_FLAG; 
	
	// создать ключ
	Using<NKeyHandle^> hKey(Provider->Handle->StartCreateKey(nullptr, alg, keyType, flags));

	// выполнить дополнительные настройки
	if (action != nullptr) action(hKey.Get()); 
		
	// указать тип параметра
	if (exportable) { String^ paramName = NCRYPT_EXPORT_POLICY_PROPERTY; 

		// указать способ экспорта
		DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; 

		// указать допустимость экспорта ключа
		hKey.Get()->SetParam(paramName, IntPtr(&policy), sizeof(policy), NCRYPT_SILENT_FLAG); 
	}
	// завершить создание ключевой пары
	hKey.Get()->Finalize(finalizeFlags); return hKey.Detach();
}
