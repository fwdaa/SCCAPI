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
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value; 

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
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, parameters, type); 
}
