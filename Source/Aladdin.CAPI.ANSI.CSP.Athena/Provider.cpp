#include "stdafx.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер Athena
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Athena::Provider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	// для алгоритмов подписи
	if (type == SignData::typeid)
	{
		// старые хэш-алгоритмы не поддерживаются в подписи
		if (oid == ASN1::ANSI::OID::ssig_rsa_md2) return nullptr;
		if (oid == ASN1::ANSI::OID::ssig_rsa_md4) return nullptr;
	}
	// для алгоритмов подписи
	else if (type == VerifyData::typeid)
	{
		// старые хэш-алгоритмы не поддерживаются в подписи
		if (oid == ASN1::ANSI::OID::ssig_rsa_md2) return nullptr;
		if (oid == ASN1::ANSI::OID::ssig_rsa_md4) return nullptr;
	}
	// вызвать базовую функцию
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}
