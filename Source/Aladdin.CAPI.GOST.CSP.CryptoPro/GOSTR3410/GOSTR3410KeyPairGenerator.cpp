#include "..\stdafx.h"
#include "..\Provider.h"
#include "GOSTR3410KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::GOSTR3410::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags)
{$
	// ��������� ���������� �������������� �����
	if (keyOID != this->keyOID) throw gcnew NotSupportedException(); 

	// ������������� ��� ����������
	CryptoPro::Provider^ provider = (CryptoPro::Provider^)Provider; 

	// ������� ��������� ���������
	GOST::GOSTR3410::INamedParameters^ parameters = (GOST::GOSTR3410::INamedParameters^)Parameters; 

	// ��� ������� ����������
	if (container != nullptr)
	{
		// ���������� ������������� ���������
		DWORD curveID = (keyType == AT_KEYEXCHANGE) ? PP_DHOID : PP_SIGNATUREOID;
	
		// ������� ��������� ������������� ������
		container->Handle->SetString(curveID, parameters->ParamOID, 0); 

        // ��� ������� ���������� �����������
        if (Provider->Type == PROV_GOST_2001_DH)
        {
            // ���������� ��������� �����������
		    container->Handle->SetString(PP_HASHOID, parameters->HashOID, 0); 
        }
		// ������� ������������� ���������
		ALG_ID algID = provider->ConvertKeyOID(keyOID, keyType);  

		// ������� ���� ������
		return Generate(container, keyType, keyFlags); 
	}
	else {
		// ��������� ������������� �����
		if (keyType != AT_KEYEXCHANGE) throw gcnew Win32Exception(NTE_BAD_TYPE);

		// ������� ������������� ���������
		ALG_ID algID = provider->ConvertKeyOID(keyOID, keyType) + 1;  

		// ������� ������ ���� ������
		Using<CAPI::CSP::KeyHandle^> hKeyPair(Provider->Handle->GenerateKey(
            algID, CRYPT_PREGEN | CRYPT_EXPORTABLE
		));
		// ������� ��������� ������������� ������
		hKeyPair.Get()->SetString(KP_DHOID, parameters->ParamOID, 0); 

        // ��� ������� ���������� �����������
        if (Provider->Type == PROV_GOST_2001_DH)
        {
            // ���������� ��������� �����������
	        hKeyPair.Get()->SetString(KP_HASHOID, parameters->HashOID, 0); 
        }
		// ������������� ���������� ���� ������
		hKeyPair.Get()->SetParam(KP_X, IntPtr::Zero, 0); return hKeyPair.Detach();
	}
}

