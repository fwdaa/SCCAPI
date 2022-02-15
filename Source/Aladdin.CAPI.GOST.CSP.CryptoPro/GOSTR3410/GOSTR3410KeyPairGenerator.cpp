#include "..\stdafx.h"
#include "..\Provider.h"
#include "GOSTR3410KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::GOSTR3410::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags)
{$
	// проверить совпадение идентификатора ключа
	if (keyOID != this->keyOID) throw gcnew NotSupportedException(); 

	// преобразовать тип провайдера
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

	// извлечь параметры алгоритма
	GOST::GOSTR3410::INamedParameters^ parameters = (GOST::GOSTR3410::INamedParameters^)Parameters; 

	// при наличии контейнера
	if (container != nullptr)
	{
		// определить идентификатор параметра
		DWORD curveID = (keyType == AT_KEYEXCHANGE) ? PP_DHOID : PP_SIGNATUREOID;
	
		// указать параметры эллиптических кривых
		container->Handle->SetString(curveID, parameters->ParamOID, 0); 

        // при наличии параметров хэширования
        if (Provider->Type == PROV_GOST_2001_DH)
        {
            // установить параметры хэширования
		    container->Handle->SetString(PP_HASHOID, parameters->HashOID, 0); 
        }
		// указать идентификатор алгоритма
		ALG_ID algID = provider->ConvertKeyOID(keyOID, keyType);  

		// создать пару ключей
		return Generate(container, keyType, keyFlags); 
	}
	else {
		// проверить идентификатор ключа
		if (keyType != AT_KEYEXCHANGE) throw gcnew Win32Exception(NTE_BAD_TYPE);

		// указать идентификатор алгоритма
		ALG_ID algID = provider->ConvertKeyOID(keyOID, keyType) + 1;  

		// создать пустую пару ключей
		Using<CAPI::CSP::KeyHandle^> hKeyPair(Provider->Handle->GenerateKey(
            algID, CRYPT_PREGEN | CRYPT_EXPORTABLE
		));
		// указать параметры эллиптических кривых
		hKeyPair.Get()->SetString(KP_DHOID, parameters->ParamOID, 0); 

        // при наличии параметров хэширования
        if (Provider->Type == PROV_GOST_2001_DH)
        {
            // установить параметры хэширования
	        hKeyPair.Get()->SetString(KP_HASHOID, parameters->HashOID, 0); 
        }
		// сгенерировать эффемерную пару ключей
		hKeyPair.Get()->SetParam(KP_X, IntPtr::Zero, 0); return hKeyPair.Detach();
	}
}

