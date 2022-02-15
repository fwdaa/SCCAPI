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
Aladdin::CAPI::ANSI::CSP::Microsoft::RSA::SCardProvider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, 
	ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type)
{$
	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; 

	// ��� ���������� �������
	if (type == VerifyHash::typeid)
	{
		// ������ �������� ���������� ���������� ACCESS DENIED ��� �������� �������
		if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// ������� �������� ������� ���-��������
			return gcnew CAPI::ANSI::Sign::RSA::PKCS1::VerifyHash();
		}
	}
	// ��� ���������� �������������� ����� 
	else if (type == TransportKeyWrap::typeid)
    {
		// ������ �������� ���������� �� ��������� �������������� �����
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// �������� �������� �������������� ����������
			return CreateAlgorithm(factory, scope, parameters, Encipherment::typeid); 
		}
    }
	// ��� ���������� �������������� ����� 
	else if (type == TransportKeyUnwrap::typeid)
    {
		// ������ �������� ���������� �� ��������� �������������� �����
        if (oid == ASN1::ISO::PKCS::PKCS1::OID::rsa) 
		{
			// �������� �������� �������������� ����������
			return CreateAlgorithm(factory, scope, parameters, Decipherment::typeid); 
		}
    }
	// ������� ������� �������
	return AESEnhancedProvider::CreateAlgorithm(factory, scope, parameters, type); 
}

