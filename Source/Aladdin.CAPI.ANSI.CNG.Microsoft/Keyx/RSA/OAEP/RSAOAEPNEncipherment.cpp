#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAOAEPNEncipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAOAEPNEncipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Ассиметричное шифрование данных RSA OAEP
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::OAEP::NEncipherment::NEncipherment(
	CAPI::CNG::NProvider^ provider, String^ hashOID, array<BYTE>^ label) 
			
	// сохранить переданные параметры
	: RSA::PKCS1::NEncipherment(provider) 
{
	// указать параметры алгоритма хэширования
	ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(hashOID), ASN1::Null::Instance
	); 
	// указать фабрику алгоритмов
	Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

	// создать алгоритм хэширования
	Using<CAPI::Hash^> hashAlgorithm(
		factory.Get()->CreateAlgorithm<CAPI::Hash^>(nullptr, hashParameters)
	); 
	// определить размер хэш-значения
	this->hashSize = hashAlgorithm.Get()->HashSize; 

	// сохранить переданные параметры
	this->hashOID = hashOID; this->label = label;
}

array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::OAEP::NEncipherment::Encrypt(
	CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data)
{$
	// определить требуемый размер буфера
	DWORD cbInfo = sizeof(BCRYPT_OAEP_PADDING_INFO) + label->Length; std::vector<BYTE> vecInfo(cbInfo); 

	// выделить буфер требуемого размера
	BCRYPT_OAEP_PADDING_INFO* pInfo = (BCRYPT_OAEP_PADDING_INFO*)&vecInfo[0]; 

	// установить имя алгоритма хэширования 
	pInfo->pszAlgId = PrimitiveProvider::GetHashName(hashOID); 

	// установить указатель на метку
	pInfo->pbLabel = (PBYTE)(pInfo + 1); pInfo->cbLabel = label->Length; 

	// скопировать метку
	Marshal::Copy(label, 0, IntPtr(pInfo->pbLabel), pInfo->cbLabel); 

	// зашифровать данные
	return hPublicKey->Encrypt(IntPtr(pInfo), data, BCRYPT_PAD_OAEP); 
}

