#include "stdafx.h"
#include "Container.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::CSP::Container::CreateRand(Object^ window)
{$ 
	// при указании родительского окна
	HWND hwnd = NULL; if (window != nullptr)
	{
		// извлечь описатель окна
		hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 
	}
	// при наличии интерфейса пользователя
	if ((Mode & CRYPT_SILENT) == 0 && hwnd != NULL) 
	{
		// создать генератор случайных данных
		return gcnew HardwareRand(Handle, window);
	}
	// создать генератор случайных данных
	else return gcnew Rand(Handle, window);
}

///////////////////////////////////////////////////////////////////////
// Операции с описателем контейнера
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Container::AttachHandle(String^ nativeName, DWORD mode)
{$
	// создать контейнер заново
	handle = Provider->Handle->AcquireContainer(nativeName, mode); 

	// сохранить режим открытия
	this->mode = mode & ~CRYPT_NEWKEYSET; 

	// получить кэш аутентификации
	CredentialsManager^ credentialsManager = 
		ExecutionContext::GetProviderCache(Provider->Name); 
		
	// получить пароль из кэша
	Auth::PasswordCredentials^ credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// получить пароль из кэша
	if (credentials == nullptr) credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Store->Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// при наличии пароля в кэше	
	if (credentials != nullptr) { String^ password = credentials->Password; 

		// указать используемый пароль
		try { handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); } catch (Exception^) {}
	}
}

void Aladdin::CAPI::CSP::Container::DetachHandle()
{$
	// закрыть описатель
	CSP::Handle::Release(handle); handle = nullptr; 
}

void Aladdin::CAPI::CSP::Container::SetCertificateContext(PCCERT_CONTEXT pCertificateContext)
{$
	// создать буфер требуемого размера
	array<BYTE>^ content = gcnew array<BYTE>(pCertificateContext->cbCertEncoded); 

	// скопировать содержимое сертификата
	Marshal::Copy(IntPtr(pCertificateContext->pbCertEncoded), content, 0, content->Length); 

	// найти идентификатор ключа
	array<BYTE>^ keyID = GetKeyPair(gcnew CAPI::Certificate(content)); 

	// получить личный ключ
	Using<CSP::PrivateKey^> privateKey((CSP::PrivateKey^)GetPrivateKey(keyID)); 
	
	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(Provider->Name); 

	// определить имя контейнера
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(
		Store->GetNativeContainerName(Name->ToString())
	); 
	// создать информацию о контейнере
	CRYPT_KEY_PROV_INFO info = { const_cast<PWSTR>(szProvider), 
		const_cast<PWSTR>(szContainer), Provider->Type, 
		mode & CRYPT_MACHINE_KEYSET, 0, 0, privateKey.Get()->KeyType
	};
	// связать информацию о контейнере с контекстом
	AE_CHECK_WINAPI(::CertSetCertificateContextProperty(
		pCertificateContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &info
	)); 
}

///////////////////////////////////////////////////////////////////////
// Аутентификация объектов
///////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::Container::IsAuthenticationRequired(Exception^ e)
{$
	// проверить режим открытия
	if ((mode & CRYPT_SILENT) == 0) return false; 

	// вызвать базовую реализацию
	return Store->IsAuthenticationRequired(e); 
}

array<Aladdin::CAPI::Credentials^>^ Aladdin::CAPI::CSP::Container::Authenticate()
{$ 
	// вызвать базовую функцию
	array<Credentials^>^ results = CAPI::Container::Authenticate(); 

	// проверить необходимость переноса аутентификации
	if (!Store->HasAuthentication) return results; 

	// получить кэш аутентификации
	CredentialsManager^ credentialsManager = 
		ExecutionContext::GetProviderCache(Provider->Name); 

	// получить пароль из кэша
	Auth::PasswordCredentials^ credentials = 
		(Auth::PasswordCredentials^)credentialsManager->GetData(
			Store->Info, "USER", Auth::PasswordCredentials::typeid
	); 
	// при наличии пароля в кэше
	if (credentials != nullptr) { String^ password = credentials->Password; 
			
		// указать используемый пароль
		Handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
	}
	return results; 
}

///////////////////////////////////////////////////////////////////////
// Поиск объектов
///////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CSP::Container::GetKeyType(String^ keyOID, KeyUsage keyUsage)
{$
	DWORD spec = AT_KEYEXCHANGE;  

	KeyUsage signMask = KeyUsage::DigitalSignature | KeyUsage::CertificateSignature | 
		                KeyUsage::CrlSignature     | KeyUsage::NonRepudiation; 
	KeyUsage keyxMask = KeyUsage::KeyEncipherment  | KeyUsage::KeyAgreement; 

	// удалить неиспользуемые биты
	keyUsage = keyUsage & (signMask | keyxMask); 

	// в зависимости от способа использования
	if ((keyUsage & signMask) != KeyUsage::None) 
	{
		// скорректировать способ использования
		keyUsage = keyUsage | signMask; spec = AT_SIGNATURE; 
	}
	// в зависимости от способа использования
	if ((keyUsage & keyxMask) != KeyUsage::None) 
	{
		// скорректировать способ использования
		keyUsage = keyUsage | keyxMask; spec = AT_KEYEXCHANGE; 
	}
	// для всех возможных ключей
	for (DWORD keyType = AT_KEYEXCHANGE; keyType <= AT_SIGNATURE; keyType++)
	{
		// создать идентификатор
		array<BYTE>^ keyID = gcnew array<BYTE>(1) { (BYTE)keyType }; 

		// указать использование ключа по умолчанию
		KeyUsage decodedUsage = KeyUsage::None; 

		// указать использование ключа по умолчанию
		if (keyType == AT_KEYEXCHANGE) decodedUsage = decodedUsage | keyxMask; 
		if (keyType == AT_SIGNATURE  ) decodedUsage = decodedUsage | signMask; 

		// получить сертификат
		Certificate^ certificate = GetCertificate(keyID);
			
		// указать использование ключа по умолчанию
		if (certificate != nullptr) decodedUsage = decodedUsage | certificate->KeyUsage; 
				
		// удалить неиспользуемые биты
		decodedUsage = decodedUsage & (signMask | keyxMask); 

		// проверить совпадение способа использования
		if ((decodedUsage & keyUsage) == decodedUsage) return keyType; 
	}
	// перечислить все существующие ключи
	array<array<BYTE>^>^ keyIDs = GetKeyIDs(); 
	
	// проверить наличие ключей
	if (keyIDs->Length == 0) return spec; if (keyIDs->Length == 2) return 0;

	// указать сободный слот
	spec = (keyIDs[0][0] == AT_KEYEXCHANGE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 

	// при допустимости обмена
	if ((keyUsage & keyxMask) != KeyUsage::None)
	{
		// проверить наличие свободного места
		if (spec == AT_KEYEXCHANGE) return spec; 
	}
	// при допустимости подписи
	if ((keyUsage & signMask) != KeyUsage::None)
	{
		// проверить наличие свободного места
		if (spec == AT_SIGNATURE) return spec; 
	}
	// проверить отсутствие указания использования
	return (keyUsage == KeyUsage::None) ? spec : 0; 
}

array<array<BYTE>^>^ Aladdin::CAPI::CSP::Container::GetKeyIDs()
{$
	// создать список идентификаторов
	List<array<BYTE>^>^ keyIDs = gcnew List<array<BYTE>^>(); 

	// для всех возможных ключей
	for (DWORD keyType = AT_KEYEXCHANGE; keyType <= AT_SIGNATURE; keyType++)
	{
		// создать идентификатор
		array<BYTE>^ keyID = gcnew array<BYTE>(1) { (BYTE)keyType }; 

		// получить описатель открытого ключа
		KeyHandle^ hKeyPair = Handle->GetUserKey(keyType); 
		
		// проверить наличие ключа
		if (hKeyPair != nullptr) { CSP::Handle::Release(hKeyPair); keyIDs->Add(keyID); }
	}
	return keyIDs->ToArray(); 
}

Aladdin::CAPI::IPublicKey^ 
Aladdin::CAPI::CSP::Container::GetPublicKey(array<BYTE>^ keyID)
{$
	// получить описатель открытого ключа
	DWORD keyType; Using<KeyHandle^> hPublicKey(GetUserKey(keyID, OUT keyType)); 

	// проверить наличие открытого ключа
	if (hPublicKey.Get() == nullptr) return nullptr; 

	// получить открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hPublicKey.Get()); 

	// раскодировать открытый ключ
	return Provider->DecodePublicKey(publicKeyInfo); 
}

Aladdin::CAPI::IPrivateKey^ Aladdin::CAPI::CSP::Container::GetPrivateKey(array<BYTE>^ keyID)
{$
	// получить описатель личного ключа
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// проверить наличие ключа
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY);

	// получить открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// раскодировать открытый ключ
	IPublicKey^ publicKey = Provider->DecodePublicKey(publicKeyInfo); 

	// вернуть личный ключ 
	return Provider->GetPrivateKey(this, publicKey, hKeyPair.Get(), keyType); 
}

///////////////////////////////////////////////////////////////////////
// Управление сертификатами
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::Container::GetCertificate(array<BYTE>^ keyID) 
{$
	// получить описатель пары ключей
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// проверить наличие открытого ключа
	if (hKeyPair.Get() == nullptr) return nullptr; 

	// получить pзакодированный открытый ключ
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = 
		Provider->ExportPublicKey(hKeyPair.Get()); 

	// получить сертификат открытого ключа
	return Store->GetCertificate(hKeyPair.Get(), publicKeyInfo); 
}

void Aladdin::CAPI::CSP::Container::SetCertificateChain(
	array<BYTE>^ keyID, array<Certificate^>^ certificateChain)
{$
	// получить описатель пары ключей
	DWORD keyType; Using<KeyHandle^> hKeyPair(GetUserKey(keyID, OUT keyType)); 

	// проверить наличие открытого ключа
	if (hKeyPair.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY); 

	// установить сертификат открытого ключа
	return Store->SetCertificateChain(hKeyPair.Get(), certificateChain); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::SetKeyPair(
	IRand^ rand, KeyPair^ keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
{$
	// проверить наличие параметров
	if (keyPair == nullptr) throw gcnew ArgumentException(); 

	// при указании идентификатора
	DWORD keyType = 0; array<BYTE>^ keyID = keyPair->KeyID; if (keyID != nullptr)
	{
		// проверить корректность идентификатора
		if (keyID->Length != 1) throw gcnew Win32Exception(NTE_BAD_UID); keyType = keyID[0];
	}
	// определить тип ключа 
	if (keyType == 0) keyType = GetKeyType(keyPair->PublicKey->KeyOID, keyUsage); 

	// при ошибке выбросить исключение
	if (keyType == 0) throw gcnew Win32Exception(NTE_NO_MORE_ITEMS);
	
    // указать признак экспортируемости
    DWORD flags = ((keyFlags & KeyFlags::Exportable) != KeyFlags::None) ? CRYPT_EXPORTABLE : 0; 

	// импортировать ключ в провайдер
	Using<KeyHandle^> hKeyPair(Provider->ImportKeyPair(
		this, keyType, flags, keyPair->PublicKey, keyPair->PrivateKey
	));
	// создать ключ
	Using<PrivateKey^> cspPrivateKey(Provider->GetPrivateKey(
		this, keyPair->PublicKey, hKeyPair.Get(), keyType
	)); 
	// вернуть идентификатор ключа
	return cspPrivateKey.Get()->KeyID; 
}

void Aladdin::CAPI::CSP::Container::DeleteKeys() 
{$
	// удалить контейнер
	DetachHandle(); Store->DeleteObject(Name, Authentications); 

	// создать контейнер заново
	AttachHandle(Mode | CRYPT_NEWKEYSET); 
}

///////////////////////////////////////////////////////////////////////////
// Операции с личным ключом
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Container::GenerateKeyPair(
	IntPtr hwnd, ALG_ID algID, DWORD flags)
{$
	// при отсутствии активного окна
	if ((Mode & CRYPT_SILENT) != 0 || hwnd == IntPtr::Zero)
	{
		// сгенерировать ключ в контейнере
		return Handle->GenerateKey(algID, flags); 
	}
	else {
		// указать описатель окна
		HWND windowHandle = (hwnd != IntPtr::Zero) ? (HWND)hwnd.ToPointer() : ::GetActiveWindow(); 

		// установить активное окно
		Handle->SetParam(PP_CLIENT_HWND, IntPtr(&windowHandle), 0); 
		try {
			// сгенерировать ключ в контейнере
			windowHandle = NULL; return Handle->GenerateKey(algID, flags);
		}
		// сбросить активное окно
		finally { Handle->SetParam(PP_CLIENT_HWND, IntPtr(&windowHandle), 0); }
	}
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::Container::ImportKey(
	KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	// импортировать ключ в контейнер
	return Handle->ImportKey(hImportKey, ptrBlob, cbBlob, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::ExportKey(
    KeyHandle^ hKey, KeyHandle^ hExportKey, DWORD exportType, DWORD flags)
{$
	// определить размер буфера
	DWORD cbBlob = hKey->Export(hExportKey, exportType, flags, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// экспортировать ключ
	cbBlob = hKey->Export(hExportKey, exportType, flags, IntPtr(ptrBuffer), cbBlob);

	// изменить размер буфера
	Array::Resize(buffer, cbBlob); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::Decrypt(
	KeyHandle^ hKey, array<BYTE>^ data, DWORD flags)
{$
	// расшифровать данные
	return hKey->Decrypt(data, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::Container::SignHash(
	DWORD keyType, HashHandle^ hHash, DWORD flags) 
{$
	// подписать хэш-значение
	return Handle->SignHash(keyType, hHash, flags); 
}

