#include "..\..\stdafx.h"
#include "GOST34310TransportKeyUnwrap.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310TransportKeyUnwrap.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм транспорта ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ISecretKey^ Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportKeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, TransportKeyData^ transportData, SecretKeyFactory^ keyFactory)
{$
	// проверить наличие параметров
	if (transportData == nullptr) throw gcnew ArgumentException(); 

	// извлечь зашифрованный ключ
	array<BYTE>^ encryptedKey = transportData->EncryptedKey; 

	// проверить размер данных
	if (encryptedKey->Length < 12) throw gcnew InvalidDataException(); 

	// проверить корректность заголовка
	if (encryptedKey[0] != SIMPLEBLOB || encryptedKey[1] != CUR_BLOB_VERSION) 
	{
		// при ошибке выбросить исключение
		throw gcnew InvalidDataException();
	}
	// удалить заголовок
	encryptedKey = Arrays::CopyOf(encryptedKey, 12, encryptedKey->Length - 12); 

	// сформировать новые данные
	transportData = gcnew TransportKeyData(transportData->Algorithm, encryptedKey); 

	// расшифровать ключ
	return CAPI::CSP::TransportKeyUnwrap::Unwrap(privateKey, transportData, keyFactory); 
}
