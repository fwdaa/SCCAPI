#include "stdafx.h"
#include "Container.h"
#include "Provider.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Установка активного ключа для контейнера
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KZ::CSP::Tumar::Container::SetActivePrivateKey::SetActivePrivateKey(
	Container^ container, CAPI::CSP::PrivateKey^ privateKey)
{$
	// сохранить переданные параметры
	hContainer = container->Handle; 

	// получить активный ключ подписи
	Using<CAPI::CSP::KeyHandle^> hActiveKey(hContainer->GetUserKey(privateKey->KeyType)); 

	// проверить корректность данных
	if (hActiveKey.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY); 

	// определить идентификатор ключа
	keyID = hActiveKey.Get()->GetParam(KP_KEY_SN, 0);  
	
	// получить описатель ключа
	Using<CAPI::CSP::KeyHandle^> hPrivateKey(privateKey->OpenHandle()); 
	
	// установить активный ключ
	hPrivateKey.Get()->SetParam(KP_USER_KEY, IntPtr::Zero, 0);  
}

Aladdin::CAPI::KZ::CSP::Tumar::Container::SetActivePrivateKey::~SetActivePrivateKey()
{$
	// восстановить активный ключ
	hContainer->SetParam(PP_CNT_ENTER_BY_SN, keyID, 0);
}

///////////////////////////////////////////////////////////////////////////
// Уникальное имя хранилища
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::KZ::CSP::Tumar::Container::GetUniqueID()
{$
    // получить подсистему смарт-карт
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Store->Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// получить уникальный идентификатор смарт-карты
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

///////////////////////////////////////////////////////////////////////////
// Указать пароль контейнера
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::KZ::CSP::Tumar::Container::IsAuthenticationRequired(Exception^ e)
{$
	// проверить тип исключения
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// определить код ошибки
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// проверить код ошибки
	return (code == NTE_SILENT_CONTEXT || code == NTE_PERM || code == NTE_BAD_KEY); 
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::SetPassword(String^ password) 
{$
	// получить описатель ключа
	CAPI::CSP::KeyHandle^ hKey = Handle->GetUserKey(AT_KEYEXCHANGE); 

	// проверить наличие ключа
	if (hKey != nullptr) { CAPI::CSP::Handle::Release(hKey); 
	
		// установить пароль на контейнер
		Handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
	}
	else {
		// получить описатель ключа
		hKey = Handle->GetUserKey(AT_SIGNATURE); 

		// проверить наличие ключа
		if (hKey != nullptr) { CAPI::CSP::Handle::Release(hKey);
		
			// установить пароль на контейнер
			Handle->SetString(PP_SIGNATURE_PIN, password, 0); 
		}
	}
	// создать структуру 
	ContInfoEx info; DWORD cb = sizeof(info); std::memset(&info, 0, cb);
	
	// закодировать пароль контейнера
	array<BYTE>^ encodedPassword = Encoding::UTF8->GetBytes(password); 

	// проверить размер пароля
	if (encodedPassword->Length >= sizeof(info.pass)) throw gcnew ArgumentException(); 

	// закодировать имя контейнера
	array<BYTE>^ encodedName = Encoding::UTF8->GetBytes(nativeName); 

	// скопировать имя контейнера
	Marshal::Copy(encodedName, 0, IntPtr(info.Url), encodedName->Length); 

	// получить информацию контейнера
	cb = Provider->Handle->GetParam(PP_URL_TO_PROF, IntPtr(&info), cb, 0); 

	// скопировать пароль контейнера
	Marshal::Copy(encodedPassword, 0, IntPtr(info.pass), encodedPassword->Length); 

	// получить информацию контейнера
	Provider->Handle->GetParam(PP_PROF_TO_URL, IntPtr(&info), cb, 0); 

	// определить размер полного имени и имени устройства
	for (cb = 0; cb < sizeof(info.Url) && info.Url[cb] != 0; cb++) {} 

	// выделить память для полного имени и имени считывателя
	encodedName = gcnew array<BYTE>(cb); Marshal::Copy(IntPtr(info.Url), encodedName, 0, cb);
	
	// определить полное имя
	nativeName = Encoding::UTF8->GetString(encodedName); 
	
	// закрыть описатель контейнера
	if (hKey == nullptr) { DetachHandle(); 
		
		// заново открыть контейнер 
		AttachHandle(nativeName, CRYPT_NEWKEYSET | CRYPT_SILENT);  
	}
}

///////////////////////////////////////////////////////////////////////////
// Управление ключами
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::KZ::CSP::Tumar::Container::GetKeyType(String^ keyOID, KeyUsage keyUsage)
{$
	// преобразовать идентификатор ключа
	ALG_ID algID = Provider->ConvertKeyOID(keyOID, 0); 

	// определить тип ключа
	return (GET_ALG_TYPE(algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 
}

array<array<BYTE>^>^ Aladdin::CAPI::KZ::CSP::Tumar::Container::GetKeyIDs()
{$
	// указать начальные условия
	DWORD maxSize = 0; DWORD flags = CRYPT_FIRST; 

	// получить размер буфера для ключевой пары
	while (DWORD cb = Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr::Zero, 0, flags))
	{
		// указать максимальный размер
		if (cb > maxSize) maxSize = cb; flags = 0; 
	}
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(maxSize); CNT_PRIVATE_KEY* pInfo = (CNT_PRIVATE_KEY*)&buffer[0];

	// создать список идентификаторов ключей
	List<array<BYTE>^>^ keyOIDs = gcnew List<array<BYTE>^>(); flags = CRYPT_FIRST; 
	
	// для всех ключей
	for (; Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr(pInfo), maxSize, flags); flags = 0)
	{
		// извлечь описатель ключа
		Using<CAPI::CSP::KeyHandle^> hKeyPair(
			gcnew CAPI::CSP::KeyHandle(Handle, pInfo->hKey, Handle->SSPI)
		); 
		// определить тип ключа
		DWORD keyType = (GET_ALG_TYPE(pInfo->algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 

		// выделить память для идентификатора
		array<BYTE>^ keyID = gcnew array<BYTE>(pInfo->serialNum.cbData); 

		// скопировать значение идентификатора
		Marshal::Copy(IntPtr(pInfo->serialNum.pbData), keyID, 0, keyID->Length); 
			
		// добавить идентификатор в список
		keyOIDs->Add(keyID);
	}
	return keyOIDs->ToArray(); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Container::GetUserKey(array<BYTE>^ keyID, DWORD% keyType)
{$
	// указать начальные условия
	DWORD maxSize = 0; DWORD flags = CRYPT_FIRST; 

	// получить размер буфера для ключевой пары
	while (DWORD cb = Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr::Zero, 0, flags))
	{
		// указать максимальный размер
		if (cb > maxSize) maxSize = cb; flags = 0; 
	}
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(maxSize); CNT_PRIVATE_KEY* pInfo = (CNT_PRIVATE_KEY*)&buffer[0];

	// выделить буфер для серийного номера
	std::vector<BYTE> serial(keyID->Length); flags = CRYPT_FIRST; 
	
	// скопировать серийный номер ключа
	Marshal::Copy(keyID, 0, IntPtr(&serial[0]), keyID->Length); 

	// для всех ключей
	for (; Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr(pInfo), maxSize, flags); flags = 0)
	{
		// извлечь описатель ключа
		Using<CAPI::CSP::KeyHandle^> hKeyPair(
			gcnew CAPI::CSP::KeyHandle(Handle, pInfo->hKey, Handle->SSPI)
		); 
		// проверить совпадение идентификаторов
		if (keyID->Length != pInfo->serialNum.cbData) continue; 
				
		// проверить совпадение идентификаторов
		if (std::memcmp(&serial[0], pInfo->serialNum.pbData, keyID->Length) != 0) continue; 

		// определить тип ключа
		keyType = (GET_ALG_TYPE(pInfo->algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 

		// вернуть описатель ключа
		return hKeyPair.Detach();
	}
	return nullptr;
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::DeleteKeyPair(array<BYTE>^ keyID) 
{$
	// удалить пару ключей
	Handle->SetParam(PP_CNT_DEL_SN, keyID, 0); 
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::DeleteKeys()
{$
/*
	// указать режим удаления
	DWORD mode = CRYPT_SILENT; HWND hwnd = ::GetActiveWindow();

	// указать активное окно
	Provider->Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	try { 
		// удалить контейнер
		Provider->Handle->DeleteContainer(nativeName, mode); 
	}
	finally { hwnd = NULL; 
	
		// сбросить активное окно
		Provider->Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	}
*/
	// получить идентификаторы ключей
	//array<array<BYTE>^>^ keyIDs = GetKeyIDs(); if (keyIDs == nullptr) return; 

	// для всех ключей
	for each (array<BYTE>^ keyID in GetKeyIDs())
	{
		// проверить наличие идентификатора
		//if (keyID == nullptr) continue; 

		/* TODO */
		// if (Arrays::Equals(keyID, gcnew array<BYTE> {
		// 	0x78, 0x93, 0x95, 0x6F, 0xF8, 0x9A, 0x6D, 0x44, 
		// 	0x55, 0x2C, 0x07, 0x4D, 0x49, 0xA7, 0x64, 0x1D, 
		// 	0x6C, 0x34, 0x43, 0xE8, 0x36, 0xA4, 0x28, 0x1E, 
		// 	0xAB, 0x78, 0x55, 0x7E, 0x50, 0x8F, 0x7D, 0xD0
		// }))	continue; 

		// удалить ключ
		DeleteKeyPair(keyID); 
	}
}

