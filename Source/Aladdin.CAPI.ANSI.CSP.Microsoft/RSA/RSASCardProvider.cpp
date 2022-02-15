#include "..\stdafx.h"
#include "RSASCardProvider.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSASCardProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Base Smart Card
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::SCardProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; 

	// для алгоритмов подписи
	if (type == VerifyHash::typeid)
	{
		// родной алгоритм провайдера возвращает ACCESS DENIED при проверке подписи
		if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew CAPI::ANSI::Sign::RSA::PKCS1::VerifyHash();
		}
	}
	// для алгоритмов транспортирвки ключа 
	else if (type == TransportKeyWrap::typeid)
    {
		// родной алгоритм провайдера не позволяет экспортировать ключи
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// получить алгоритм ассиметричного шифрования
			return CreateAlgorithm(factory, scope, parameters, Encipherment::typeid); 
		}
    }
	// для алгоритмов транспортирвки ключа 
	else if (type == TransportKeyUnwrap::typeid)
    {
		// родной алгоритм провайдера не позволяет экспортировать ключи
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// получить алгоритм ассиметричного шифрования
			return CreateAlgorithm(factory, scope, parameters, Decipherment::typeid); 
		}
    }
	// вызвать базовую функцию
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, parameters, type); 
}

