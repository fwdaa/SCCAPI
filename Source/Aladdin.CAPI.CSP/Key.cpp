#include "stdafx.h"
#include "Key.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Key.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::SecretKeyType::ConstructKey(
    ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) 
{$
    // задать фиксированный заголовок
    BLOBHEADER blobHeader = { PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, algID };

	// определить смещение ключа
	DWORD offsetKey = sizeof(BLOBHEADER) + sizeof(DWORD); 
	
	// определить требуемый размер буфера
	DWORD cbBlob = offsetKey + value->Length;
				 
	// выделить память для структуры импорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)(PBYTE)ptrBlob;  

	// скопировать заголовок и указать размер ключа
	*pBlob = blobHeader; *(PDWORD)(pBlob + 1) = value->Length;

    // скопировать содержимое ключа
    Array::Copy(value, 0, blob, offsetKey, value->Length); 

    // импортировать ключ в контекст
    return hContext->ImportKey(nullptr, IntPtr(pBlob), cbBlob, flags); 
}

array<BYTE>^ Aladdin::CAPI::CSP::SecretKeyType::GetKeyValue(
	ContextHandle^ hContext, KeyHandle^ hKey)
{$
	// определить размер буфера
	DWORD cbBlob = hKey->Export(nullptr, PLAINTEXTKEYBLOB, 0, IntPtr::Zero, 0);

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)(PBYTE)ptrBlob;  

	// экспортировать ключ
	cbBlob = hKey->Export(nullptr, PLAINTEXTKEYBLOB, 0, IntPtr(pBlob), cbBlob);

	// получить смещение ключа
	DWORD offsetKey = sizeof(BLOBHEADER) + sizeof(DWORD);

	// проверить размер буфера
	if (cbBlob < offsetKey) throw gcnew Win32Exception(NTE_BAD_DATA);

	// выделить память для ключа
	array<BYTE>^ key = gcnew array<BYTE>(*(PDWORD)(pBlob + 1));

	// проверить размер ключа
	if (cbBlob < offsetKey + key->Length) throw gcnew Win32Exception(NTE_BAD_DATA);

	// извлечь значение ключа
	Array::Copy(blob, offsetKey, key, 0, key->Length); return key; 
}

///////////////////////////////////////////////////////////////////////////
// Ключ шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKey::SecretKey(
	CSP::Provider^ provider, SecretKeyFactory^ keyFactory, KeyHandle^ hKey)
{   
	// сохранить переданные параметры
	this->provider = RefObject::AddRef(provider); 
	
	// сохранить переданные параметры
	this->hKey = CSP::Handle::AddRef(hKey); this->keyFactory = keyFactory; 
} 

Aladdin::CAPI::CSP::SecretKey::~SecretKey() 
{ 
	// освободить выделенные ресурсы
	CSP::Handle::Release(hKey); RefObject::Release(provider); 
} 

int Aladdin::CAPI::CSP::SecretKey::Length::get()
{
    // проверить наличие размера ключа
    if (value != nullptr) return value->Length; 

    // вернуть размер ключа
    return (Handle->GetLong(KP_KEYLEN, 0) + 7) / 8; 
}

array<BYTE>^ Aladdin::CAPI::CSP::SecretKey::Value::get()
try {$
	// проверить наличие значения
	if (value != nullptr) return value; 

	// получить тип ключа
	SecretKeyType^ keyType = provider->GetSecretKeyType(KeyFactory, Length); 

	// получить значение ключа
	value = keyType->GetKeyValue(provider->Handle, Handle); return value; 
}
// обработать возможную ошибку
catch (Exception^) { return nullptr; }

///////////////////////////////////////////////////////////////////////////
// Личный ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::PrivateKey::PrivateKey(Provider^ provider, SecurityObject^ scope, 
	IPublicKey^ publicKey, KeyHandle^ hPrivateKey, array<BYTE>^ keyID, DWORD keyType) 
		: CAPI::PrivateKey(provider, scope, publicKey->KeyOID)
{ 
	// сохранить переданные параметры
	this->parameters = publicKey->Parameters; this->keyID = keyID; 

	// сохранить переданные параметры
	this->hPrivateKey = nullptr; this->keyType = keyType; 

	// для эфемерного ключа сохранить описатель ключа
	if (Container == nullptr) this->hPrivateKey = Handle::AddRef(hPrivateKey); 
}  

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::PrivateKey::OpenHandle() 
{$ 
	// для эфемерного ключа увеличить счетчик ссылок описателя
	if (Container == nullptr) return Handle::AddRef(hPrivateKey);  
	else {
		// преобразовать тип контейнера
		CAPI::CSP::Container^ container = (CAPI::CSP::Container^)Container; 

		// получить описатель ключа
		DWORD keyType; return container->GetUserKey(keyID, OUT keyType); 
	}
}

/*
void Aladdin::CAPI::CSP::PrivateKey::SetCertificateContext(PCCERT_CONTEXT pCertificateContext)
{$
	// преобразовать тип объекта
	CSP::Container^ container = dynamic_cast<CSP::Container^>(Container); 

	// проверить тип объекта
	if (container == nullptr) AE_CHECK_WINERROR(NTE_BAD_KEY); 

	// связать контекст сертификата с ключом
	container->SetCertificateContext(pCertificateContext, keyType); 
}
*/

array<BYTE>^ Aladdin::CAPI::CSP::PrivateKey::Export(KeyHandle^ hExportKey, DWORD flags)
{$
	// для ключа контейнера
	if (dynamic_cast<CAPI::CSP::Container^>(Container) != nullptr)
	{
		// преобразовать тип контейнера
		CAPI::CSP::Container^ container = (CAPI::CSP::Container^)Container; 
		
		// получить описатель ключа
		Using<KeyHandle^> hPrivateKey(OpenHandle());

		// экспортировать ключ
		return container->ExportKey(hPrivateKey.Get(), hExportKey, PRIVATEKEYBLOB, flags); 
	}
	else {
		// определить размер буфера
		DWORD cbBlob = hPrivateKey->Export(hExportKey, PRIVATEKEYBLOB, flags, IntPtr::Zero, 0); 

		// выделить память для структуры экспорта
		array<BYTE>^ buffer = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

		// экспортировать ключ
		cbBlob = hPrivateKey->Export(hExportKey, PRIVATEKEYBLOB, flags, IntPtr(ptrBuffer), cbBlob);

		// изменить размер буфера
		Array::Resize(buffer, cbBlob); return buffer; 
	}
} 

