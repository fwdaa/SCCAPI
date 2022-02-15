#include "stdafx.h"
#include "STB11762.h"
#include "STB11761.h"
#include "GOST28147.h"
#include "BelT.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762); 	

	// �������� ������� ������ ����������
	IKeyFactory^ provKeyFactory = ((Provider^)provider)->KeyFactory; 

	// ������������ ��������� ������ ����������
	ASN1::IEncodable^ provKeyParameters = provKeyFactory->Parameters->Encodable; 

	// ������������ ��������� ������
	ASN1::IEncodable^ keyParameters = keyFactory->Parameters->Encodable; 

	// �������� ���������� ���������
	if (!provKeyParameters->Equals(keyParameters)) throw gcnew NotSupportedException(); 

	// ������� ���� ������
	return provider->GenerateKey(container, keyType, keyFlags); 
}

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� ��� 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignHash::CreateHash(
	CAPI::CSP::ContextHandle hContext, ASN1::ISO::AlgorithmIdentifier^ hashAgorithm)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::SignHash::CreateHash); 

	// ��������� ������������� ���������
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::bhf) 
	{
		// ������� �������� �����������
		return hContext.CreateHash(CALG_BHF, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// ��������� ������������� ���������
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::belt_hash) 
	{
		// ������� �������� �����������
		return hContext.CreateHash(CALG_BELT_HASH, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle hContext, ASN1::ISO::AlgorithmIdentifier^ hashAgorithm)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyHash::CreateHash); 

	// ��������� ������������� ���������
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::bhf) 
	{
		// ������� �������� �����������
		return hContext.CreateHash(CALG_BHF, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// ��������� ������������� ���������
	if (hashAgorithm->Algorithm->Value == ASN1::STB::Avest::OID::belt_hash) 
	{
		// ������� �������� �����������
		return hContext.CreateHash(CALG_BELT_HASH, CAPI::CSP::KeyHandle::Zero, 0); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}
///////////////////////////////////////////////////////////////////////
// ������� ������ ��� 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignDataSTB11761::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SignDataSTB11761::CreateHash); 

	// �������� ��������� ��������
	array<BYTE>^ start = ((Avest::STB11762::IParameters^)keyFactory->Parameters)->Sign->H; 

	// ������� �������� �����������
	return STB11761::Hash(Provider, hContext, start).Construct(); 
}

Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyDataSTB11761::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::VerifyDataSTB11761::CreateHash); 

	// �������� ��������� ��������
	array<BYTE>^ start = ((Avest::STB11762::IParameters^)keyFactory->Parameters)->Sign->H; 

	// ������� �������� �����������
	return STB11761::Hash(Provider, hContext, start).Construct(); 
}
///////////////////////////////////////////////////////////////////////
// ������� ������ ��� 1176.2
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::SignDataBelT::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SignDataBelT::CreateHash); 

	// ������� �������� �����������
	return BelT::Hash(Provider, hContext).Construct(); 
}
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11762::VerifyDataBelT::CreateHash(
	CAPI::CSP::ContextHandle hContext, IKeyFactory^ keyFactory)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::VerifyDataBelT::CreateHash); 

	// ������� �������� �����������
	return BelT::Hash(Provider, hContext).Construct(); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ������ ��� 1176.2
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::ASN1TransportData^ Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyWrap::Wrap(
	IPublicKey^ publicKey, IRand^ rand, IKey^ CEK)
{
	ATRACE_SCOPE(Aladdin::STB::Avest::CSP::STB11762::ASN1KeyWrap::Unwrap); 

	// ������� ������������� ������� �����������
	String^ sboxOID = ASN1::STB::Avest::OID::parameters_sboxes_default; 

	// �������� ��������� ���������
	STB::Avest::STB11762::IParameters^ parameters =
		(STB::Avest::STB11762::IParameters^)publicKey->KeyFactory->Parameters; 

	// ������������� �������� ���� ������
	CAPI::CSP::SessionObject<CAPI::CSP::KeyHandle> sessionPubKey(
		provider->ImportPublicKey(CALG_BDH, publicKey)
	); 
	// ������� �������� ���������� �����
	GOST28147::BlockEngine^ blockEngine = 
        gcnew GOST28147::BlockEngine(provider, provider->Handle.Context); 

	// ������� ���� ���������� ������ �� ��� ��������
	CAPI::CSP::SessionKey sessionCEK(provider->ConstructKey(
        provider->Handle.Context, CALG_G28147, Key::FromBinary(CEK->Value)
    )); 
	// ���������� ������ ����� � ������
	int cb = (parameters->KeyX->L + 7) / 8; DWORD cbBlob = sizeof(AVEST_SIMPLE_BLOB) + cb; 

	// �������� ������ ��� ��������� ��������
	PAVEST_SIMPLE_BLOB pBlob = (PAVEST_SIMPLE_BLOB)_alloca(cbBlob); 

	// �������������� ���� ���������� ������
	cbBlob = sessionCEK.Handle.Export(sessionPubKey.Handle, SIMPLEBLOB, 0, IntPtr(pBlob), cbBlob); 

	// ������� ��������� �������������� �����
	array<BYTE>^ encrypted = gcnew array<BYTE>(32); Marshal::Copy(IntPtr(pBlob->key), encrypted, 0, 32); 
	array<BYTE>^ mac       = gcnew array<BYTE>( 4); Marshal::Copy(IntPtr(pBlob->mac), mac,       0,  4); 
	array<BYTE>^ nonce	   = gcnew array<BYTE>(cb); Marshal::Copy(IntPtr(pBlob +  1), nonce,     0, cb); 

	// ������������ ��������� ���������������
	ASN1::STB::Avest::ExchangeParameters^ transportParameters = 
		gcnew ASN1::STB::Avest::ExchangeParameters(
			gcnew ASN1::OctetString(nonce), gcnew ASN1::ObjectIdentifier(sboxOID)
	); 
	// ������������ ������������� ���� 
	ASN1::STB::Avest::EncryptedKey^ encodedEncryptedKey = 
		gcnew ASN1::STB::Avest::EncryptedKey(
			gcnew ASN1::OctetString(encrypted), gcnew ASN1::BitString(mac)
	); 
	// ������� ���������� �� ���������
	ASN1::ISO::AlgorithmIdentifier^ algInfo = gcnew ASN1::ISO::AlgorithmIdentifier(
        gcnew ASN1::ObjectIdentifier(ASN1::STB::Avest::OID::bdh_gost_ecb), 
        transportParameters
	);
	// ������� ������������� ����
	return gcnew ASN1TransportData(algInfo, encodedEncryptedKey->Encoded); 
}

Aladdin::CAPI::IKey^ Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyUnwrap::Unwrap(
	IPrivateKey^ privateKey, ASN1TransportData^ transportData)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11762::ASN1KeyUnwrap::Unwrap); 

	// �������� ��������� ���������
	STB::Avest::STB11762::IParameters^ parameters =
		(STB::Avest::STB11762::IParameters^)privateKey->KeyFactory->Parameters; 

	// ������� ��������� ���������������
	ASN1::STB::Avest::ExchangeParameters^ transportParameters = 
		gcnew ASN1::STB::Avest::ExchangeParameters(transportData->Algorithm->Parameters); 

	// ������� ������������� ���� � ������������
	ASN1::STB::Avest::EncryptedKey^ encodedEncryptedKey = 
		gcnew ASN1::STB::Avest::EncryptedKey(
            ASN1::Encodable::Decode(transportData->EncryptedKey)); 

	// ������� �����
	array<BYTE>^ nonce = transportParameters->Nonce->Value;

	// ��������� ����������� ���������
	BLOBHEADER header = { SIMPLEBLOB,  CUR_BLOB_VERSION, 0, CALG_G28147 }; 

	// ���������� ������ ��������� ��� �������
	DWORD cbBlob = sizeof(AVEST_SIMPLE_BLOB) + nonce->Length; 

	// �������� ������ ��� ��������� �������
	PAVEST_SIMPLE_BLOB pBlob = (PAVEST_SIMPLE_BLOB)_alloca(cbBlob); 

	// ����������� ����������� ���������
	pBlob->header = header; pBlob->algID = CALG_BDH; pBlob->bitsNonce = parameters->KeyX->L;

	// �������� ������������� ����
	Marshal::Copy(encodedEncryptedKey->Encrypted->Value, 0, IntPtr(pBlob->key), 32); 

	// �������� ����������� �����
	Marshal::Copy(encodedEncryptedKey->MacKey->Value, 0, IntPtr(pBlob->mac), 4);

	// �������� ������ ����� � �����
	pBlob->encrypt = 0x01; pBlob->bitsNonce = parameters->KeyX->L;

	// �������� �����
	Marshal::Copy(nonce, 0, IntPtr(pBlob + 1), nonce->Length); 

	// ������� ��������� ��� ������� �����
	CAPI::CSP::Container^ container = (CAPI::CSP::Container^)privateKey->Container; 
	
	// ������������� ��� ����������
	CAPI::CSP::Provider^ provider = container->Store->Provider; 

	// �������� ��������� ������� �����
	CAPI::CSP::SessionObject<CAPI::CSP::KeyHandle> sessionPrivateKey(
		container->Handle.GetUserKey(AT_KEYEXCHANGE)
	);
	// ������������� ����
	CAPI::CSP::KeyHandle hKey = container->ImportKey(
		sessionPrivateKey.Handle, IntPtr(pBlob), cbBlob, CRYPT_EXPORTABLE
	); 
	// ������� ��������������� ����
	return gcnew CAPI::CSP::SessionKey(hKey); 
}
