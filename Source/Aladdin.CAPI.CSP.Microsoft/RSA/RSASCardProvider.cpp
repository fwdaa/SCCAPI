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
Aladdin::CAPI::CSP::Microsoft::RSA::SCardProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	// для алгоритмов подписи
	if (type == CAPI::VerifyHash::typeid)
	{
		// родной алгоритм провайдера возвращает ACCESS DENIED при проверке подписи
		if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// создать алгоритм подписи хэш-значения
			return gcnew CAPI::ANSI::Sign::RSA::PKCS1::VerifyHash();
		}
	}
	// для алгоритмов транспортирвки ключа 
	else if (type == CAPI::TransportKeyWrap::typeid)
    {
		// родной алгоритм провайдера не позволяет экспортировать ключи
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// получить алгоритм ассиметричного шифрования
			return CreateAlgorithm(factory, scope, oid, parameters, CAPI::Encipherment::typeid); 
		}
    }
	// для алгоритмов транспортирвки ключа 
	else if (type == CAPI::TransportKeyUnwrap::typeid)
    {
		// родной алгоритм провайдера не позволяет экспортировать ключи
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// получить алгоритм ассиметричного шифрования
			return CreateAlgorithm(factory, scope, oid, parameters, CAPI::Decipherment::typeid); 
		}
    }
	// вызвать базовую функцию
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}

