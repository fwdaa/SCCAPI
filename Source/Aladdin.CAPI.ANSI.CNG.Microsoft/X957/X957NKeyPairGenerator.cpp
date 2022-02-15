#include "..\stdafx.h"
#include "..\PrimitiveProvider.h"
#include "X957NKeyPairGenerator.h"
#include "X957BKeyPairGenerator.h"
#include "X957Encoding.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957NKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X957 
{
///////////////////////////////////////////////////////////////////////////
// Установка параметров ключа
///////////////////////////////////////////////////////////////////////////
private ref class SetParametersAction
{
	// параметры ключа
	private: IntPtr ptrBlob; private: DWORD cbBlob; 

	// конструктор
	public: SetParametersAction(IntPtr ptrBlob, DWORD cbBlob)
	{
		// сохранить переданные параметры
		this->ptrBlob = ptrBlob; this->cbBlob = cbBlob; 
	}
	// установить параметры ключа
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// установить параметры 
		hKey->SetParam(BCRYPT_DSA_PRIVATE_BLOB, IntPtr(ptrBlob), cbBlob, 0); 
	}
}; 
}}}}}}

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X957::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// проверить тип ключа
	if (keyType != AT_SIGNATURE) throw gcnew Win32Exception(NTE_BAD_TYPE); 

	// указать имя алгоритма
	PrimitiveProvider factory; String^ algName = NCRYPT_DSA_ALGORITHM; 

    // получить параметры ключа
    ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)Parameters; 

	// создать программный алгоритм генерации
	BKeyPairGenerator generator(%factory, nullptr, Rand, factory.Provider, parameters); 

	// сгенерировать программную пару ключей
	Using<KeyPair^> keyPair(generator.Generate(keyOID));

	// преобразовать тип ключей
	ANSI::X957::IPublicKey ^ publicKeyDSA  = (ANSI::X957::IPublicKey^ )keyPair.Get()->PublicKey; 
	ANSI::X957::IPrivateKey^ privateKeyDSA = (ANSI::X957::IPrivateKey^)keyPair.Get()->PrivateKey; 

	// определить требуемый размер буфера
	DWORD cbBlob = Encoding::GetKeyPairBlob(publicKeyDSA, privateKeyDSA, 0, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

	// получить структуру для импорта ключа
	cbBlob = Encoding::GetKeyPairBlob(publicKeyDSA, privateKeyDSA, pbBlob, cbBlob); 

	// создать функцию установки парамтеров
	SetParametersAction^ paramAction = gcnew SetParametersAction(IntPtr(pbBlob), cbBlob); 

	// указать функцию установки параметров
	Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
        paramAction, &SetParametersAction::Invoke
    ); 
	// сгенерировать пару ключей
	return Generate(container, NCRYPT_DSA_ALGORITHM, keyType, exportable, action, 0); 
}

