#include "..\stdafx.h"
#include "RSANKeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSANKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace RSA 
{
///////////////////////////////////////////////////////////////////////////
// Установка параметров ключа
///////////////////////////////////////////////////////////////////////////
private ref class SetParametersAction
{
	// конструктор
	public: SetParametersAction(int bits)
	
		// сохранить переданные параметры
		{ this->bits = bits; } private: int bits;

	// установить параметры ключа
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// указать значение параметра
		DWORD value = bits; DWORD cbValue = sizeof(value); 

		// установить размер ключа в битах
		hKey->SetParam(NCRYPT_LENGTH_PROPERTY, IntPtr(&value), cbValue, 0); 
	}
}; 
}}}}}

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::RSA::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// извлечь требуемое число битов
	int bits = ((IKeySizeParameters^)Parameters)->KeyBits;

	// создать функцию установки парамтеров
	SetParametersAction^ paramAction = gcnew SetParametersAction(bits); 

    // указать функцию установки параметров
    Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
        paramAction, &SetParametersAction::Invoke
    ); 
	// сгенерировать ключи 
	return Generate(container, NCRYPT_RSA_ALGORITHM, keyType, exportable, action, 0); 
}

