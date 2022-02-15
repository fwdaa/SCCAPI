#include "..\stdafx.h"
#include "GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ 
Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::CreateBlockMode(CipherMode^ mode)
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
	// для режима OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
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

void Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey)
{$
	// установить таблицу подстановок и режим смены ключа
	hKey->SetString(KP_CIPHEROID, sboxOID, 0); 

	// установить режим смены ключа
	hKey->SetLong(KP_MESHING, meshing ? 1 : 0, 0);
}


///////////////////////////////////////////////////////////////////////////
// Режим шифрования ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::KZ::CSP::Tumar::Cipher::GOST28147::BlockMode::SetParameters(
	CAPI::CSP::KeyHandle^ hKey, PaddingMode padding)
{$
	// вызвать базовую функцию
	CAPI::CSP::BlockMode::SetParameters(hKey, padding); 

	// для режима CTR
	if (dynamic_cast<CipherMode::CTR^>(Mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::CTR^ parameters = (CipherMode::CTR^)Mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_CNT, 0);  

		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}
