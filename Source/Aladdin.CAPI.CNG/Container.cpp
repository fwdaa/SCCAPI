#include "stdafx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::Container::Container(ProviderStore^ store, 
	String^ name, DWORD mode) : CAPI::Container(store, name)
{$
	// указать родное имя контейнера
	String^ nativeName = store->GetNativeContainerName(name); 

	// указать режим открытия
	this->mode = mode | NCRYPT_SILENT_FLAG; keyType = 0; 
	
	// для всех ключей
	for (DWORD type = AT_KEYEXCHANGE; type <= AT_SIGNATURE; type++)
	{
		// получить описатель ключевой пары
		hKeyPair.Attach(Provider->Handle->OpenKey(nativeName, type, this->mode)); 

		// проверить наличие ключа
		if (hKeyPair.Get() != nullptr) { keyType = type; break; }
	}
}

Aladdin::CAPI::CNG::Container::~Container() { $ }

///////////////////////////////////////////////////////////////////////
// Признак необходимости аутентификации
///////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CNG::Container::IsAuthenticationRequired(Exception^ e)
{$
	// проверить режим открытия
	if ((mode & NCRYPT_SILENT_FLAG) == 0) return false; 

	// вызвать базовую реализацию
	return Store->IsAuthenticationRequired(e); 
}

///////////////////////////////////////////////////////////////////////
// Операции с личным ключом контейнера
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Container::CompleteGenerateKeyPair(
	IntPtr hwnd, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{
	// выполнить дополнительные действия
	if (action != nullptr) action(hKeyPair.Get()); if (exportable)
	{ 
		// указать тип параметра
		String^ paramName = gcnew String(NCRYPT_EXPORT_POLICY_PROPERTY); 

		// указать способ экспорта
		DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; 

		// указать признак постоянного параметра
		DWORD persistFlags = NCRYPT_SILENT_FLAG | NCRYPT_PERSIST_FLAG; 

		// указать допустимость экспорта ключа
		hKeyPair.Get()->SetParam(paramName, IntPtr(&policy), sizeof(policy), persistFlags); 
	}
	// при указании описателя окна
	if ((mode & NCRYPT_SILENT_FLAG) != 0 || hwnd == IntPtr::Zero) 
	{
		// завершить создание ключевой пары
		hKeyPair.Get()->Finalize(flags);
	}
	else { 
		// указать описатель окна
		hKeyPair.Get()->SetParam(NCRYPT_WINDOW_HANDLE_PROPERTY, IntPtr(&hwnd), hwnd.Size, 0); 
		try { 
			// завершить создание ключевой пары
			hKeyPair.Get()->Finalize(flags); hwnd = IntPtr::Zero; 
		}
		// сбросить описатель окна
		finally { hKeyPair.Get()->SetParam(NCRYPT_WINDOW_HANDLE_PROPERTY, IntPtr(&hwnd), hwnd.Size, 0); }
	}
}

Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Container::GenerateKeyPair(IntPtr hwnd, 
	String^ alg, DWORD keyType, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{$
	if (hKeyPair.Get() != nullptr)
	{
		// проверить совпадение типа
		if (this->keyType != keyType) throw gcnew Win32Exception(NTE_BAD_TYPE);
			
		// удалить ключ
		else DeleteKeyPair(gcnew array<BYTE> { (BYTE)keyType }); 
	}
	// определить режим создания ключа
	DWORD createFlags = flags & NCRYPT_OVERWRITE_KEY_FLAG;

	// определить режим завершения создания ключа
	DWORD finalizeFlags = (flags & ~createFlags) | NCRYPT_SILENT_FLAG; 

	// указать родное имя контейнера
	String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 

   	// создать ключ
    hKeyPair.Attach(Provider->Handle->StartCreateKey(
		nativeName, alg, keyType, (mode & ~NCRYPT_SILENT_FLAG) | createFlags
	));
	try { 
		// создать прокси
		Container^ container = (Container^)Proxy::SecurityObjectProxy::Create(this); 

		// установить параметры ключевой пары
		container->CompleteGenerateKeyPair(hwnd, exportable, action, finalizeFlags); 

		// установить тип ключа
		this->keyType = keyType; return hKeyPair.Get(); 
	}
	// обработать возможную ошибку
	catch (Exception^) { hKeyPair.Close(); throw; } 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::Container::ImportKeyPair(
	IntPtr hwnd, NKeyHandle^ hImportKey, DWORD keyType, String^ typeBlob, 
	IntPtr ptrBlob, DWORD cbBlob, BOOL exportable, Action<CNG::Handle^>^ action, DWORD flags)
{$
	if (hKeyPair.Get() != nullptr)
	{
		// проверить совпадение типа
		if (this->keyType != keyType) throw gcnew Win32Exception(NTE_BAD_TYPE);
			
		// удалить ключ
		else DeleteKeyPair(gcnew array<BYTE> { (BYTE)keyType }); 
	}
	// определить режим создания ключа
	DWORD importFlags = flags & NCRYPT_OVERWRITE_KEY_FLAG;

	// определить режим завершения создания ключа
	DWORD finalizeFlags = (flags & ~importFlags) | NCRYPT_SILENT_FLAG; 

	// указать родное имя контейнера
	String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 

   	// импортировать ключ
    hKeyPair.Attach(Provider->Handle->StartImportKeyPair(nativeName, 
		hImportKey, typeBlob, ptrBlob, cbBlob, (mode & ~NCRYPT_SILENT_FLAG) | importFlags
	));
	try { 
		// создать прокси
		Container^ container = (Container^)Proxy::SecurityObjectProxy::Create(this); 

		// установить параметры ключевой пары
		container->CompleteGenerateKeyPair(hwnd, exportable, action, finalizeFlags); 

		// установить тип ключа
		this->keyType = keyType; return hKeyPair.Get(); 
	}
	// обработать возможное исключение
	catch (Exception^) { hKeyPair.Close(); throw; } 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::ExportKey(
    NKeyHandle^ hKey, NKeyHandle^ hExportKey, String^ blobType, DWORD flags)
{$
	// указать режим функции
	flags |= (mode & NCRYPT_SILENT_FLAG); 

    // определить размер буфера
    DWORD cbBlob = hKey->Export(hExportKey, blobType, flags, IntPtr::Zero, 0); 

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// экспортировать ключ
	cbBlob = hKey->Export(hExportKey, blobType, flags, IntPtr(ptrBlob), cbBlob);

	// изменить размер буфера
	Array::Resize(blob, cbBlob); return blob; 
}

Aladdin::CAPI::CNG::NSecretHandle^ 
Aladdin::CAPI::CNG::Container::AgreementSecret(
	NKeyHandle^ hPrivateKey, NKeyHandle^ hPublicKey, DWORD flags)
{$
	// указать режим функции
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// выполнить согласование ключа
	return hPrivateKey->AgreementSecret(hPublicKey, flags); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::Decrypt(
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// указать режим функции
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// расшифровать данные
	return hPrivateKey->Decrypt(padding, data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::SignHash(
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ hash, DWORD flags) 
{$
	// указать режим функции
	flags |= (mode & NCRYPT_SILENT_FLAG); 

	// подписать хэш-значение
	return hPrivateKey->SignHash(padding, hash, flags); 
}

///////////////////////////////////////////////////////////////////////
// Управление ключами контейнера
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Container::GetKeyID(KeyUsage keyUsage)
{$
	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 
	
	if (hKeyPair.Get() == nullptr) 
	{
		// создать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { AT_KEYEXCHANGE }; 

		// указать идентификатор
		if ((keyUsage & signMask) != KeyUsage::None) keyID[0] = AT_SIGNATURE; 
		if ((keyUsage & keyxMask) != KeyUsage::None) keyID[0] = AT_KEYEXCHANGE; return keyID; 
	}
	else { KeyUsage decodedUsage = KeyUsage::None;

		// скорректировать способ использования
		if ((keyUsage & keyxMask) != KeyUsage::None) keyUsage = keyUsage | keyxMask; 
		if ((keyUsage & signMask) != KeyUsage::None) keyUsage = keyUsage | signMask; 

		// создать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// указать использование ключа по умолчанию
		if (keyType == AT_KEYEXCHANGE) decodedUsage = decodedUsage | keyxMask; 
		if (keyType == AT_SIGNATURE  ) decodedUsage = decodedUsage | signMask; 

		// получить сертификат
		Certificate^ certificate = GetCertificate(keyID);

		// проверить наличие сертификата
		if (certificate != nullptr) { decodedUsage = decodedUsage | certificate->KeyUsage; 

			// удалить неиспользуемые биты
			decodedUsage = decodedUsage & (signMask | keyxMask); 
			
			// проверить совпадение способа использования
			if ((decodedUsage & keyUsage) != decodedUsage) keyID = nullptr;
		}
		return keyID; 
	}
}

array<array<BYTE>^>^ Aladdin::CAPI::CNG::Container::GetKeyIDs()
{$
	// проверить наличие идентификаторов
	if (keyType == 0) return gcnew array<array<BYTE>^>(0); 

	// создать идентификатор ключа
	array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

	// вернуть идентификатор
	return gcnew array<array<BYTE>^> { keyID }; 
}

array<array<BYTE>^>^ Aladdin::CAPI::CNG::Container::GetKeyIDs(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo)
{$
	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr) return gcnew array<array<BYTE>^>(0); 

	// создать список идентификаторов
	List<array<BYTE>^>^ keyIDs = gcnew List<array<BYTE>^>(); 

	// создать идентификатор
	array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType };
	
	// получить сертификат
	Certificate^ other = GetCertificate(keyID); if (other != nullptr)
	{
		// проверить способ использования
		if (other->PublicKeyInfo->Equals(keyInfo)) keyIDs->Add(keyID);
	}
	else {
		// получить информацию об открытом ключе
		ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
			Provider->ExportPublicKey(hKeyPair.Get()); 

		// проверить совпадение ключей
		if (publicKeyInfo->Equals(keyInfo)) keyIDs->Add(keyID); 
	}
	return keyIDs->ToArray(); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CNG::Container::GetPublicKeyInfo(array<BYTE>^ keyID)
{$
	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) 
	{
		// при ошибке выбросить исключение
		throw gcnew Win32Exception(NTE_NO_KEY); 
	}
	// получить информацию об открытом ключе
	return Provider->ExportPublicKey(hKeyPair.Get()); 
}

Aladdin::CAPI::IPublicKey^ 
Aladdin::CAPI::CNG::Container::GetPublicKey(array<BYTE>^ keyType)
{$
    // получить открытый ключ
    ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = GetPublicKeyInfo(keyType); 

    // проверить наличие открытого ключа
    if (publicKeyInfo == nullptr) return nullptr; 

    // раскодировать открытый ключ
    return Provider->DecodePublicKey(publicKeyInfo); 
}

Aladdin::CAPI::IPrivateKey^ Aladdin::CAPI::CNG::Container::GetPrivateKey(array<BYTE>^ keyID)
{$
	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY);

	// получить информацию об открытом ключе
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ keyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// раскодировать открытый ключ
	IPublicKey^ publicKey = Provider->DecodePublicKey(keyInfo);
 
	// вернуть личный ключ 
	return Provider->GetPrivateKey(this, publicKey, hKeyPair.Get()); 
}

///////////////////////////////////////////////////////////////////////
// Управление сертификатами
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CNG::Container::GetCertificate(array<BYTE>^ keyID)
{$
	// проверить наличие параметров
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) return nullptr; 

	// получить pзакодированный открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// получить сертификат
	return Store->GetCertificate(hKeyPair.Get(), publicKeyInfo); 
}

void Aladdin::CAPI::CNG::Container::SetCertificate(
	array<BYTE>^ keyID, Certificate^ certificate)
{$
	// проверить наличие параметров
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr || keyType != keyID[0]) gcnew Win32Exception(NTE_NO_KEY); 

	// сохранить сертификат в контейнер
	Store->SetCertificate(hKeyPair.Get(), certificate); 
}

array<BYTE>^ Aladdin::CAPI::CNG::Container::SetKeyPair(
	IRand^ rand, KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
{$
	// проверить наличие параметров
	if (keyPair == nullptr) throw gcnew ArgumentException(); 

	// получить идентификатор ключа
	array<BYTE>^ keyID = keyPair->KeyID; if (keyID != nullptr)
	{
		// проверить корректность идентификатора
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID);
	}
	// создать идентификатор ключа 
	else keyID = GetKeyID(keyUsage); 
    
    // при ошибке выбросить исключение
    if (keyID == nullptr) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);

    // указать признак экспортируемости
    BOOL exportable = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None);

	// при указании родительского окна
	IntPtr hwnd = IntPtr::Zero; if (rand->Window != nullptr)
	{
		// извлечь описатель окна
		hwnd = ((IWin32Window^)rand->Window)->Handle; 
	}
	// импортировать ключ в провайдер
	Provider->ImportKeyPair(this, hwnd, 
		keyID[0], exportable, keyPair->PublicKey, keyPair->PrivateKey
	); 
	return keyID;
}

void Aladdin::CAPI::CNG::Container::DeleteKeyPair(array<BYTE>^ keyID)
{$
	// проверить наличие параметров
	if (keyID == nullptr) throw gcnew ArgumentException(); 

	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr || keyType != keyID[0])
	{
		// при ошибке выбросить исключение
		throw gcnew Win32Exception(NTE_NO_KEY);
	}
	DeleteKeys(); 
}

void Aladdin::CAPI::CNG::Container::DeleteKeys()
{$
	// проверить наличие ключей
	if (hKeyPair.Get() == nullptr) return;
	try {
		// удалить пару ключей (даже при ошибке описатель некорректный)
		Provider->Handle->DeleteKey(hKeyPair.Get(), mode); 
		
		// сбросить описатель
		hKeyPair.Attach(nullptr); keyType = 0;
	}
	// при ошибке восстановить состояние
	catch (Exception^) { hKeyPair.Attach(nullptr); 
	 
		// указать родное имя контейнера
		String^ nativeName = Store->GetNativeContainerName(Name->ToString()); 
		try { 
			// получить описатель ключевой пары
			hKeyPair.Attach(Provider->Handle->OpenKey(nativeName, keyType, mode));
		}
		// обработать возможную ошибку
		catch (Exception^) { keyType = 0; } throw; 
    }
}
