#include "..\stdafx.h"
#include "RSASCardProvider.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSASCardProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� Base Smart Card
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::CSP::Microsoft::RSA::SCardProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	// ��� ���������� �������
	if (type == CAPI::VerifyHash::typeid)
	{
		// ������ �������� ���������� ���������� ACCESS DENIED ��� �������� �������
		if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// ������� �������� ������� ���-��������
			return gcnew CAPI::ANSI::Sign::RSA::PKCS1::VerifyHash();
		}
	}
	// ��� ���������� �������������� ����� 
	else if (type == CAPI::TransportKeyWrap::typeid)
    {
		// ������ �������� ���������� �� ��������� �������������� �����
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// �������� �������� �������������� ����������
			return CreateAlgorithm(factory, scope, oid, parameters, CAPI::Encipherment::typeid); 
		}
    }
	// ��� ���������� �������������� ����� 
	else if (type == CAPI::TransportKeyUnwrap::typeid)
    {
		// ������ �������� ���������� �� ��������� �������������� �����
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// �������� �������� �������������� ����������
			return CreateAlgorithm(factory, scope, oid, parameters, CAPI::Decipherment::typeid); 
		}
    }
	// ������� ������� �������
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}

