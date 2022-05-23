#include "..\stdafx.h"
#include "GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ 
Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::CreateBlockMode(CipherMode^ mode)
{$
	// для режима ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// для режима CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// для режима CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// для режима CTR
	else if (dynamic_cast<CipherMode::CTR^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}

void Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey)
{$
	// установить таблицу подстановок
	hKey->SetString(KP_CIPHEROID, sboxOID, 0);

	// в зависимости от режима смены ключа
	if (meshing == ASN1::GOST::OID::keyMeshing_none)
	{
		// установить режим смены ключа
		hKey->SetLong(KP_MIXMODE, CRYPT_SIMPLEMIX_MODE, 0);  
	}
	// в зависимости от режима смены ключа
	else if (meshing == ASN1::GOST::OID::keyMeshing_cryptopro)
	{
		// установить режим смены ключа
		hKey->SetLong(KP_MIXMODE, CRYPT_PROMIX_MODE, 0);  
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// Режим блочного алгоритма шифрования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::Cipher::GOST28147::BlockMode::SetParameters(
	CAPI::CSP::KeyHandle^ hKey, PaddingMode padding)
{$
	// вызвать базовую функцию
	CAPI::CSP::BlockMode::SetParameters(hKey, padding);

	// для режима CBC
	if (dynamic_cast<CipherMode::CBC^>(Mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::CBC^ parameters = (CipherMode::CBC^)Mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_CBCRFC4357, 0);  

		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// для режима CTR
	else if (dynamic_cast<CipherMode::CTR^>(Mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::CTR^ parameters = (CipherMode::CTR^)Mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_CNT, 0);  

		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}

