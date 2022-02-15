#include "stdafx.h"
#include "Provider.h"
#include "BelT.h"
#include "GOST28147.h"
#include "STB11761.h"
#include "STB11762.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// ��������������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle Aladdin::CAPI::STB::Avest::CSP::Provider::ConstructKey(
	Aladdin::CAPI::CSP::ContextHandle hContext, ALG_ID algID, IKey^ key)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::ConstructKey); 

	// ��������� ��� �����
	if (dynamic_cast<CAPI::CSP::SessionKey^>(key) != nullptr || key->Value == nullptr)
	{
        // ������� ������� �������
        return CAPI::CSP::Provider::ConstructKey(hContext, algID, key); 
    }
    else {
	    // ��������� ������ �����
	    if (key->Value->Length != 32) throw gcnew CryptographicException(NTE_BAD_LEN); 

	    // ������ ������������� ���������
	    BLOBHEADER blobHeader = { SIMPLEBLOB, CUR_BLOB_VERSION, 0, algID } ; 

	    // ������ ��������� ������� ����� ����������
	    AVEST_SIMPLE_BLOB blob = { blobHeader, 0 }; DWORD cbBlob = sizeof(blob); 
	
	    // ����������� ���������� �����
	    Marshal::Copy(key->Value, 0, IntPtr(&blob.key), key->Value->Length); 

	    // ������������� ���� � ��������
	    return hContext.ImportKey(CAPI::CSP::KeyHandle::Zero, IntPtr(&blob), cbBlob, CRYPT_EXPORTABLE); 
    }
}

Dictionary<String^, Aladdin::CAPI::KeyUsage>^ 
Aladdin::CAPI::STB::Avest::CSP::Provider::SupportedKeys()		
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::SupportedKeys); 

    // ������� ������ ������ ������
    Dictionary<String^, KeyUsage>^ keys = gcnew Dictionary<String^, KeyUsage>(); 

    // �������� �������������� ����
    keys->Add(KeyOID, KeyUsage::dataSignature | KeyUsage::keyEncipherment); return keys; 
} 

Aladdin::CAPI::IPrivateKey^ 
Aladdin::CAPI::STB::Avest::CSP::Provider::GetPrivateKey(
	IKeyFactory^ keyFactory, CAPI::CSP::Container^ container, 
	CAPI::CSP::KeyHandle hKeyPair, DWORD keyType)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::Provider::GetPrivateKey);

	// ��������� ������������� ����������
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bds_bdh) 
    {
		// ��� �������� ����������
		if (container != nullptr)
		{
			// ������� ���������� ������ ����
			return gcnew STB11762::PrivateKey(container, keyFactory, hKeyPair, keyType); 
		}
		// ������� ��������� ������ ����
		return gcnew STB11762::PrivateKey(this, keyFactory, hKeyPair, keyType); 
    }
	// ������� ������� �������
	return CAPI::CSP::Provider::GetPrivateKey(keyFactory, container, hKeyPair, keyType); 
}

///////////////////////////////////////////////////////////////////////////
// ��������������� ����� Full
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyPairGenerator^ Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateGenerator(
	IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateGenerator); 

	// ��������� ������������� ����������
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bds_bdh) 
	{
		// ������� �������� ��������� ������
		return gcnew STB11762::KeyPairGenerator(this, keyFactory);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateAlgorithm(
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) 
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderFull::CreateAlgorithm); 

	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; 

	// ��� ���������� �����������
	if (type == IHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::belt_hash) return gcnew BelT::Hash(this, Handle.Context);
		if (oid == ASN1::STB::Avest::OID::bhf      ) 
		{
			// ������� ��������� ��������
			array<BYTE>^ start = gcnew array<BYTE>(32); for (int i = 0; i < 32; i++) start[i] = 0xAA; 

			// ������� �������� �����������
			return gcnew STB11761::Hash(this, Handle.Context, start);
		}
	}
	// ��� ���������� ���������� ������������
	else if (type == IMac::typeid)
	{
		// ������� �������� ���������� ������������
		if (oid == ASN1::STB::Avest::OID::gost) 
		{
			// ������������� ���������
			ASN1::ObjectIdentifier^ sboxOID = gcnew ASN1::ObjectIdentifier(parameters->Parameters); 
			
			// ������� �������� ���������� ������������
			return gcnew GOST28147::Imito(this, Handle.Context, sboxOID->Value); 
		}
	}
	// ��� ���������� ������������� ����������
	else if (type == ICipher::typeid)
	{
		// ������� �������� ������������� ����������
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb)
		{ 
			// ������������� ���������
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// ������� �������� ������������� ����������
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::None, algParameters->IV->Value
			);
		}
		// ������� �������� ������������� ����������
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb_pad)
		{ 
			// ������������� ���������
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// ������� �������� ������������� ����������
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::PKCS7, algParameters->IV->Value
			);
		}
	}
	// ��� ���������� ������� ������
	else if (type == ISignData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds_bhf)
		{
			// ������� �������� ������� ������
			return gcnew STB11762::SignDataSTB11761(this);
		}
	}
	// ��� ���������� ������� ������
	else if (type == IVerifyData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds_bhf)
		{
			// ������� �������� ������� ������
			return gcnew STB11762::VerifyDataSTB11761(this);
		}
	}
	// ��� ���������� ������������ ������ �����
	else if (type == IASN1KeyWrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// ������� �������� ������������ ������ �����
			return gcnew STB11762::ASN1KeyWrap(this);
		}
	}
	// ��� ���������� ������������ ������ �����
	else if (type == IASN1KeyUnwrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// ������� �������� ������������ ������ �����
			return gcnew STB11762::ASN1KeyUnwrap(this);
		}
	}
	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// ��������������� ����� Pro
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IKeyPairGenerator^ Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateGenerator(
	IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateGenerator); 

	// ��������� ������������� ����������
	if (keyFactory->Oid == ASN1::STB::Avest::OID::bdspro_bdh) 
	{
		// ������� �������� ��������� ������
		return gcnew STB11762::KeyPairGenerator(this, keyFactory);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateAlgorithm(
	ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) 
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::ProviderPro::CreateAlgorithm); 

	// ���������� ������������� ���������
	String^ oid = parameters->Algorithm->Value; 

	// ��� ���������� �����������
	if (type == IHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::belt_hash) return gcnew BelT::Hash(this, Handle.Context);
		if (oid == ASN1::STB::Avest::OID::bhf      ) 
		{
			// ������� ��������� ��������
			array<BYTE>^ start = gcnew array<BYTE>(32); for (int i = 0; i < 32; i++) start[i] = 0xAA; 

			// ������� �������� �����������
			return gcnew STB11761::Hash(this, Handle.Context, start);
		}
	}
	// ��� ���������� ���������� ������������
	else if (type == IMac::typeid)
	{
		// ������� �������� ���������� ������������
		if (oid == ASN1::STB::Avest::OID::gost) 
		{
			// ������������� ���������
			ASN1::ObjectIdentifier^ sboxOID = gcnew ASN1::ObjectIdentifier(parameters->Parameters); 
			
			// ������� �������� ���������� ������������
			return gcnew GOST28147::Imito(this, Handle.Context, sboxOID->Value); 
		}
	}
	// ��� ���������� ������������� ����������
	else if (type == ICipher::typeid)
	{
		// ������� �������� ������������� ����������
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb)
		{ 
			// ������������� ���������
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// ������� �������� ������������� ����������
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::None, algParameters->IV->Value
			);
		}
		// ������� �������� ������������� ����������
		if (oid == ASN1::STB::Avest::OID::gost_modes_cfb_pad)
		{ 
			// ������������� ���������
			ASN1::STB::Avest::CipherParameters^ algParameters = 
				gcnew ASN1::STB::Avest::CipherParameters(parameters->Parameters); 

			// ������� �������� ������������� ����������
			return gcnew GOST28147::BlockCipher(this, Handle.Context, 
				algParameters->ParamSet->Value, CipherMode::CFB, 
				PaddingMode::PKCS7, algParameters->IV->Value
			);
		}
	}
	// ��� ���������� ������� ���-��������
	else if (type == ISignHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds) 
		{
			// ������� �������� ������� ���-��������
			return gcnew STB11762::SignHash(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro) 
		{
			// ������� �������� ������� ���-��������
			return gcnew STB11762::SignHash(this);
		}
	}
	// ��� ���������� ������� ���-��������
	else if (type == IVerifyHash::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bds) 
		{
			// ������� �������� ������� ���-��������
			return gcnew STB11762::VerifyHash(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro) 
		{
			// ������� �������� ������� ���-��������
			return gcnew STB11762::VerifyHash(this);
		}
	}
	// ��� ���������� ������� ������
	else if (type == ISignData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdspro_bhf) 
		{
			// ������� �������� ������� ������
			return gcnew STB11762::SignDataSTB11761(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro_belt) 
		{
			// ������� �������� ������� ������
			return gcnew STB11762::SignDataBelT(this);
		}
	}
	// ��� ���������� ������� ������
	else if (type == IVerifyData::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdspro_bhf) 
		{
			// ������� �������� ������� ������
			return gcnew STB11762::VerifyDataSTB11761(this);
		}
		if (oid == ASN1::STB::Avest::OID::bdspro_belt) 
		{
			// ������� �������� ������� ������
			return gcnew STB11762::VerifyDataBelT(this);
		}
	}
	// ��� ���������� ������������ ������ �����
	else if (type == IASN1KeyWrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// ������� �������� ������������ ������ �����
			return gcnew STB11762::ASN1KeyWrap(this);
		}
	}
	// ��� ���������� ������������ ������ �����
	else if (type == IASN1KeyUnwrap::typeid)
	{
		if (oid == ASN1::STB::Avest::OID::bdh) 
		{
			// ������� �������� ������������ ������ �����
			return gcnew STB11762::ASN1KeyUnwrap(this);
		}
	}
	return nullptr; 
}
