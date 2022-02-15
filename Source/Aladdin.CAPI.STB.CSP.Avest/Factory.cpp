#include "stdafx.h"
#include "Factory.h"
#include "GOST28147.h"
#include "STB11762.h"

///////////////////////////////////////////////////////////////////////
// Вернуть фабрику ключей
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyFactory^ Aladdin::CAPI::STB::Avest::CSP::Factory::GetKeyFactory(
	ASN1::ISO::AlgorithmIdentifier^ parameters)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Factory::GetKeyFactory); 

	// определить идентификатор алгоритма
	String^ oid = parameters->Algorithm->Value;  

	if (oid == ASN1::STB::Avest::OID::bds_bdh) 
	{
		// раскодировать параметры ключей
		return gcnew STB::Avest::STB11762::KeyFactory(oid, parameters->Parameters); 
	}
	if (oid == ASN1::STB::Avest::OID::bdspro_bdh) 
	{
		// раскодировать параметры ключей
		return gcnew STB::Avest::STB11762::KeyFactory(oid, parameters->Parameters); 
	}
	return nullptr; 
}
///////////////////////////////////////////////////////////////////////
// Cоздать алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyPairGenerator^ Aladdin::CAPI::STB::Avest::CSP::Factory::CreateGenerator(
	IKeyFactory^ keyFactory, IRand^ rand)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Factory::CreateGenerator); 
	
	// вызвать базовую функцию
	return Avest::Factory::Instance->CreateGenerator(keyFactory, rand); 
}
///////////////////////////////////////////////////////////////////////
// Cоздать алгоритм для параметров
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ Aladdin::CAPI::STB::Avest::CSP::Factory::CreateAlgorithm(
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Factory::CreateAlgorithm); 

	// вызвать базовую функцию
	IAlgorithm^ algorithm = CAPI::Factory::CreateAlgorithm(parameters, type, context); 

	// вернуть алгоритм
	return (algorithm != nullptr) ? algorithm : Avest::Factory::Instance->CreateAlgorithm(parameters, type, context); 
}
