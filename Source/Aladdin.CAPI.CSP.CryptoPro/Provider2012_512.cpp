#include "stdafx.h"
#include "Provider2012_512.h"
#include "GOSTR3410\GOSTR3410KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider2012_512.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� ��������� 2012
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::CSP::CryptoPro::Provider2012_512::CreateGenerator(
	CAPI::Factory^ factory, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// ��������� ��� ����������
	if (keyOID == ASN1::GOST::OID::gostR3410_2001)
	{
		// ��� ����������� �����������
		if (scope == nullptr || dynamic_cast<Software::Container^>(scope) != nullptr)
		{
			// ������������� ��� ����������
			GOST::GOSTR3410::IECParameters^ gostParameters = 
				(GOST::GOSTR3410::IECParameters^)parameters; 

			// ������� ������� ����������
			Using<Factory^> softwareFactory(gcnew CAPI::GOST::Factory()); 

		    // ������� �������� ��������� ������
		    return gcnew CAPI::GOST::GOSTR3410::ECKeyPairGenerator(
				softwareFactory.Get(), scope, rand, gostParameters
			);
		}
	}
	// ��������� ��� ����������
	if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
	{
		// ��� ����������� �����������
		if (scope == nullptr || dynamic_cast<Software::Container^>(scope) != nullptr)
		{
			// ������������� ��� ����������
			GOST::GOSTR3410::IECParameters^ gostParameters = 
				(GOST::GOSTR3410::IECParameters^)parameters; 

			// ������� ������� ����������
			Using<Factory^> softwareFactory(gcnew CAPI::GOST::Factory()); 

		    // ������� �������� ��������� ������
		    return gcnew CAPI::GOST::GOSTR3410::ECKeyPairGenerator(
				softwareFactory.Get(), scope, rand, gostParameters
			);
		}
	}
	// ��������� ��� ����������
	if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
	{
		// ������������� ��� ����������
		GOST::GOSTR3410::IECParameters^ gostParameters = 
			(GOST::GOSTR3410::IECParameters^)parameters; 

	    // ������� �������� ��������� ������
	    return gcnew GOSTR3410::KeyPairGenerator(
			this, scope, rand, keyOID, gostParameters
		);
	}
	return nullptr; 
}

