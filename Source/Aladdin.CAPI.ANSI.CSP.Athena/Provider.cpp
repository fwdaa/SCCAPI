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
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
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
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}
