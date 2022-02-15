#include "stdafx.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� Athena
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Athena::Provider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; 

	// ��� ���������� �������
	if (type == SignData::typeid)
	{
		// ������ ���-��������� �� �������������� � �������
		if (oid == ASN1::ANSI::OID::ssig_rsa_md2) return nullptr;
		if (oid == ASN1::ANSI::OID::ssig_rsa_md4) return nullptr;
	}
	// ��� ���������� �������
	else if (type == VerifyData::typeid)
	{
		// ������ ���-��������� �� �������������� � �������
		if (oid == ASN1::ANSI::OID::ssig_rsa_md2) return nullptr;
		if (oid == ASN1::ANSI::OID::ssig_rsa_md4) return nullptr;
	}
	// ������� ������� �������
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, parameters, type); 
}
