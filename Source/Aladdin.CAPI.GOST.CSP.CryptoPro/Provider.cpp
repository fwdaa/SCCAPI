#include "stdafx.h"
#include "Provider.h"
#include "SecretKeyType.h"
#include "GOSTR3410\GOSTR3410PrivateKey.h"
#include "Hash\GOSTR3411_1994.h"
#include "Hash\GOSTR3411_2012.h"
#include "MAC\HMAC_GOSTR3411_1994.h"
#include "MAC\HMAC_GOSTR3411_2012.h"
#include "MAC\MAC_GOST28147.h"
#include "Cipher\GOST28147.h"
#include "Wrap\RFC4357_NONE.h"
#include "Wrap\RFC4357_CPRO.h"
#include "Wrap\RFC4357_TC26.h"
#include "Sign\GOSTR3410\GOSTR3410SignHash.h"
#include "Sign\GOSTR3410\GOSTR3410VerifyHash.h"
#include "Sign\GOSTR3410\GOSTR3410SignData2001.h"
#include "Sign\GOSTR3410\GOSTR3410VerifyData2001.h"
#include "Keyx\GOSTR3410\GOSTR3410KeyAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::BlockCipher^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateGOST28147(String^ paramOID)
{$
	// �������� ����������� ��������� ���������
	ASN1::GOST::GOST28147ParamSet^ namedParameters = 
		ASN1::GOST::GOST28147ParamSet::Parameters(paramOID);

	// ������� �������� ���������� 
	return gcnew Cipher::GOST28147(
		this, Handle, paramOID, namedParameters->KeyMeshing->Algorithm->Value
	); 
}

array<Aladdin::CAPI::SecurityInfo^>^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::EnumerateAllObjects(Scope scope)
{$
	// ������� ������ ������������
	List<String^>^ names = gcnew List<String^>(); 

    // �������� ���������� �����-����
    PCSC::Provider^ cardProvider = PCSC::Windows::Provider::Instance; 

	// ����������� �����������
	array<PCSC::Reader^>^ readers = cardProvider->EnumerateReaders(PCSC::ReaderScope::System); 

	// ��� ������ �����-�����
	for (int i = 0; i < readers->Length; i++) 
	try {
		// ��� ������� �����-����� �������� ��� �����������
		if (readers[i]->GetState() == PCSC::ReaderState::Card) names->Add(readers[i]->Name); 
	}
    // ������� ������ �������� ��������
	catch (Exception^) {} List<SecurityInfo^>^ infos = gcnew List<SecurityInfo^>(); 

    // ��� ������������ ��������� ��������
    if (scope == Scope::Any || scope == Scope::System)
    {
		// ����������� ��� ����������
		array<String^>^ fullNames = Handle->EnumerateContainers(CRYPT_FQCN | CRYPT_MACHINE_KEYSET); 

		// ��� ���� ������������
		for (int i = 0; i < names->Count; i++)
		{
			// ��� ���� �����������
			for each (String^ fullName in fullNames)
			{
				// ��������� ��� �����������
				if (!fullName->StartsWith(String::Format("\\\\.\\{0}\\", names[i]))) continue; 

				// ������� ��� ���������
				String^ storeName = String::Format("Card\\{0}", names[i]); 

				// ������� ��� ����������
				String^ name = fullName->Substring(4 + names[i]->Length + 1); 

				// �������� ���������� � ����������
				infos->Add(gcnew SecurityInfo(Scope::System, storeName, name)); 
			}
		}
		// ��� ���� �����������
		for each (String^ fullName in fullNames)
		{
			// ��������� �������������� �������
			if (!fullName->StartsWith("\\\\.\\REGISTRY\\")) continue; 
			
			// ������� ��� ����������
			String^ name = fullName->Substring(13); 

			// �������� ���������� � ����������
			infos->Add(gcnew SecurityInfo(Scope::System, "HKLM", name)); 
		}
	}
    // ��� ������������ ���������������� ��������
    if (scope == Scope::Any || scope == Scope::User)
    {
		// ����������� ��� ����������
		array<String^>^ fullNames = Handle->EnumerateContainers(CRYPT_FQCN); 

		// ��� ���� �����������
		for each (String^ fullName in fullNames)
		{
			// ��������� �������������� �������
			if (!fullName->StartsWith("\\\\.\\REGISTRY\\")) continue; 

			// ������� ��� ����������
			String^ name = fullName->Substring(13); 

			// �������� ���������� � ����������
			infos->Add(gcnew SecurityInfo(Scope::User, "HKCU", name)); 
        }
	}
    // ������� ������ �������� ��������
    return infos->ToArray(); 
}

Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// �������� ��� �����
	if (keySize == 32) return gcnew SecretKeyType(CALG_G28147       ); 
	if (keySize == 64) return gcnew SecretKeyType(CALG_SYMMETRIC_512); 

	// ���������������� ��������
	throw gcnew NotSupportedException(); 
}

String^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ConvertKeyOID(ALG_ID keyOID) 
{$
    if (keyOID == CALG_GR3410EL   ) return ASN1::GOST::OID::gostR3410_2001; 
    if (keyOID == CALG_DH_EL_SF   ) return ASN1::GOST::OID::gostR3410_2001;
    if (keyOID == CALG_DH_EL_EPHEM) return ASN1::GOST::OID::gostR3410_2001;

    if (version >= 0x0400)
    {
        if (keyOID == CALG_GR3410_12_256         ) return ASN1::GOST::OID::gostR3410_2012_256; 
        if (keyOID == CALG_DH_GR3410_12_256_SF   ) return ASN1::GOST::OID::gostR3410_2012_256;
        if (keyOID == CALG_DH_GR3410_12_256_EPHEM) return ASN1::GOST::OID::gostR3410_2012_256;
        if (keyOID == CALG_GR3410_12_512         ) return ASN1::GOST::OID::gostR3410_2012_512; 
        if (keyOID == CALG_DH_GR3410_12_512_SF   ) return ASN1::GOST::OID::gostR3410_2012_512;
        if (keyOID == CALG_DH_GR3410_12_512_EPHEM) return ASN1::GOST::OID::gostR3410_2012_512;
    }
	// ���������������� ����
	throw gcnew NotSupportedException(); 
}

ALG_ID Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ConvertKeyOID(String^ keyOID, DWORD keyType)
{$
    if (keyOID == ASN1::GOST::OID::gostR3410_2001)
    {
        return (keyType == AT_KEYEXCHANGE) ? CALG_DH_EL_SF : CALG_GR3410EL; 
    }
    if (version >= 0x0400)
    {
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
        {
            return (keyType == AT_KEYEXCHANGE) ? CALG_DH_GR3410_12_256_SF : CALG_GR3410_12_256; 
        }
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
        {
            return (keyType == AT_KEYEXCHANGE) ? CALG_DH_GR3410_12_512_SF : CALG_GR3410_12_512; 
        }
    }
	// ���������������� ����
	throw gcnew NotSupportedException(); 
}

String^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetExportKeyOID(String^ keyOID, DWORD keyType)
{
    if (keyOID == ASN1::GOST::OID::gostR3410_2001)
    {
        return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2001_SSDH : keyOID; 
	}
    if (version >= 0x0400)
    {
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
        {
			/* TODO */
            return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2012_DH_256 : keyOID; 
        }
        if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
        {
			/* TODO */
            return (keyType == AT_KEYEXCHANGE) ? ASN1::GOST::OID::gostR3410_2012_DH_512 : keyOID; 
        }
    }
	// ���������������� ����
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::KeyWrap^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateExportKeyWrap(
    CAPI::CSP::ContextHandle^ hContext, ALG_ID exportID, String^ sboxOID, array<BYTE>^ ukm)
{$
    if (exportID == CALG_PRO_EXPORT)
    {
        // ������� �������� ���������� �����
		return gcnew Wrap::RFC4357_CPRO(this, hContext, sboxOID, ukm);
    }
    if (exportID == CALG_PRO12_EXPORT)
    {
        // ������� �������� ���������� �����
        return gcnew Wrap::RFC4357_TC26(this, hContext, sboxOID, ukm);
    } 
	// ���������������� ��������
	throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// �������� ��������� ���������
	CAPI::GOST::GOSTR3410::IECParameters^ gostParameters = 
		(CAPI::GOST::GOSTR3410::IECParameters^) publicKey->Parameters;

	// ������������� ��� �����
	CAPI::GOST::GOSTR3410::IECPrivateKey^ gostPrivateKey = 
		(CAPI::GOST::GOSTR3410::IECPrivateKey^) privateKey; 

	// ���������� ������������� ����� � ���������
	String^ keyOID = GetExportKeyOID(publicKey->KeyOID, keyType); 

	// ������� �������� �����
	ASN1::GOST::CryptoProPrivateKeyAttributes attributes = 
		ASN1::GOST::CryptoProPrivateKeyAttributes::Exportable;

	// ������� �������� �����
	if (keyType == AT_KEYEXCHANGE) 
	{ 
		// ���������������� �������� �����
		attributes = attributes | ASN1::GOST::CryptoProPrivateKeyAttributes::Exchange;
	}
	// ������������ �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo = publicKey->Encoded; 

	// ������� ��������� ���������� ��������� �����
	ASN1::ISO::AlgorithmIdentifier^ algorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
			gcnew ASN1::ObjectIdentifier(keyOID), 
			publicKeyInfo->Algorithm->Parameters
	); 
	// ������� ��������� ���������� ������� �����
	ASN1::GOST::CryptoProPrivateKeyParameters^ parameters =
		gcnew ASN1::GOST::CryptoProPrivateKeyParameters(
			gcnew ASN1::BitFlags(attributes), algorithm
	);
	// ������������� ���� ���������� �����
	Using<CAPI::CSP::KeyHandle^> hKEK(
		Handle->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	); 
	// ������� ������ �����
	CAPI::CSP::SecretKey KEK(this, Keys::GOST::Instance, hKEK.Get()); 

	// �������� ������������� ������� �����������
	String^ sboxOID = hKEK.Get()->GetString(KP_CIPHEROID, 0);

	// ������� ������� UKM
	array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN);   

	// ������� �������� ���������� �����
	Using<KeyWrap^> keyWrap(CreateExportKeyWrap(
		Handle, GetExportID(publicKey->KeyOID), sboxOID, ukm
	)); 
	// �������� �������� ������� �����
	array<BYTE>^ valueCEK = Math::Convert::FromBigInteger(
		gostPrivateKey->D, Endian, (gostParameters->Order->BitLength + 7) / 8
	); 
	// ������� ��� �����
	SecretKeyFactory^ typeCEK = (valueCEK->Length == 32) ? 
		Keys::GOST::Instance : SecretKeyFactory::Generic; 

	// ������� ������ �����
	Using<ISecretKey^> CEK(typeCEK->Create(valueCEK)); 

	// ����������� �������� ������� �����
	array<BYTE>^ wrapped = keyWrap.Get()->Wrap(nullptr, %KEK, CEK.Get()); 

	// �������� ����� ��� �������������� �����
	array<BYTE>^ encKey = gcnew array<BYTE>(wrapped->Length - EXPORT_IMIT_SIZE); 

	// ������� �������� �������������� �����
	Array::Copy(wrapped, 0, encKey, 0, encKey->Length); 

	// �������� ����� ��� ������������
	array<BYTE>^ macKey = gcnew array<BYTE>(EXPORT_IMIT_SIZE); 

	// ������� �������� ������������
	Array::Copy(wrapped, encKey->Length, macKey, 0, EXPORT_IMIT_SIZE); 
		
	// ������� ��������� �������������� �����
	ASN1::GOST::EncryptedKey^ encryptedKey = gcnew ASN1::GOST::EncryptedKey(
		gcnew ASN1::OctetString(encKey), nullptr, gcnew ASN1::OctetString(macKey)
	); 
	// ������� ��������� ��������
	ASN1::GOST::CryptoProKeyTransferContent^ keyTransferContent = 
		gcnew ASN1::GOST::CryptoProKeyTransferContent(
			gcnew ASN1::OctetString(ukm), encryptedKey, parameters
	); 
	// ������� �������� �������������� �����
	Using<KeyDerive^> keyDerive(((Wrap::RFC4357^)keyWrap.Get())->GetKDFAlgorithm(Handle)); 

	// ������� �������� ���������� ������������
	Using<Mac^> macAlgorithm(gcnew MAC::GOST28147(
		this, Handle, sboxOID, ASN1::GOST::OID::keyMeshing_none, ukm
	)); 
	// ������� ������������������� ����
	Using<ISecretKey^> sessionKey(keyDerive.Get()->DeriveKey(
		%KEK, ukm, macAlgorithm.Get()->KeyFactory, 32
	)); 
	// ��������� ������������ �� ���������
	array<BYTE>^ mac = macAlgorithm.Get()->MacData(sessionKey.Get(), 
		keyTransferContent->Encoded, 0, keyTransferContent->Encoded->Length
	); 
	// ������� ��������� � �������������
	ASN1::GOST::CryptoProKeyTransfer^ keyTransfer = 
		gcnew ASN1::GOST::CryptoProKeyTransfer(
			keyTransferContent, gcnew ASN1::OctetString(mac)
	); 
	// ������ ������������� ���������
	BLOBHEADER blobHeader = { PRIVATEKEYBLOB, BLOB_VERSION, 0, 
		ConvertKeyOID(publicKey->KeyOID, keyType) 
	}; 
	// ������ ��������� ����� 
	CRYPT_PUBKEYPARAM keyHeader = { GR3410_2_MAGIC, (UINT)encKey->Length }; 

	// ���������� ��������� ������ ������
	DWORD cbBlob = sizeof(CRYPT_PUBKEY_INFO_HEADER) + keyTransfer->Encoded->Length; 

	// �������� ����� ����������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob; 

	// ������ ���������
	pBlob->BlobHeader = blobHeader; pBlob->KeyParam = keyHeader; 

	// ���������� �������� ���������
	DWORD offset = sizeof(CRYPT_PUBKEY_INFO_HEADER); 

	// ����������� ��������� � �������������
	Array::Copy(keyTransfer->Encoded, 0, blob, offset, keyTransfer->Encoded->Length); 

	// ������� ������������� ���������
	hKEK.Get()->SetLong(KP_ALGID, GetExportID(publicKey->KeyOID), 0); 

	// ������������� ���� ������
	return ImportKey(container, hKEK.Get(), IntPtr(pBlob), cbBlob, keyFlags); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
    // �������� ������������� �����
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, AT_KEYEXCHANGE); 

	// ������������ �������� ����
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ info = publicKey->Encoded; 

    // ������� �������������� ���������
    array<BYTE>^ encodedParams = info->Algorithm->Parameters->Encoded; 

    // ������������� ��� �����
    GOST::GOSTR3410::IECPublicKey^ ecPublicKey = (GOST::GOSTR3410::IECPublicKey^)publicKey; 

    // ������������� ��� ����������
	GOST::GOSTR3410::IECParameters^ ecParameters = (GOST::GOSTR3410::IECParameters^)publicKey->Parameters; 
        
    // ������� ����� ��� ����������� �����
    array<BYTE>^ xy = gcnew array<BYTE>((ecParameters->Order->BitLength + 7) / 8 * 2); 

    // ������������ ���������� �����
    Math::Convert::FromBigInteger(ecPublicKey->Q->X, Endian, xy,              0, xy->Length / 2);
    Math::Convert::FromBigInteger(ecPublicKey->Q->Y, Endian, xy, xy->Length / 2, xy->Length / 2);

    // ���������� ������ ��������� ��� �������
    DWORD cbBlob = sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Length + xy->Length; 

    // �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
    CRYPT_PUBKEY_INFO_HEADER* pHeader = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob; 

    // �������� ���������� �����
    std::memset(pHeader, 0, cbBlob); pHeader->BlobHeader.aiKeyAlg = algID; 

    // ������ ������������� ���������
    pHeader->BlobHeader.bType = PUBLICKEYBLOB; pHeader->BlobHeader.bVersion = BLOB_VERSION; 

	// ������ ��������� ����� 
    pHeader->KeyParam.Magic = GR3410_2_MAGIC; pHeader->KeyParam.BitLen = xy->Length * 8; 

	// ����������� ���������
	Array::Copy(encodedParams, 0, blob, sizeof(CRYPT_PUBKEY_INFO_HEADER), encodedParams->Length); 

	// ����������� �������� ����� � �����
	Array::Copy(xy, 0, blob, sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Length, xy->Length);  

	// ������������� �������� ����
	return hContext->ImportKey(nullptr, IntPtr(pHeader), cbBlob, 0); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// ���������� ������ ������
	DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr::Zero, 0);

	// �������� ������ ��� ��������� ��������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	CRYPT_PUBKEY_INFO_HEADER* pBlob = (CRYPT_PUBKEY_INFO_HEADER*)(PBYTE)ptrBlob;  

	// �������������� �������� ����
	cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, 0, IntPtr(pBlob), cbBlob);

    // ���������� ������������� �����
    String^ keyOID = ConvertKeyOID(pBlob->BlobHeader.aiKeyAlg); 

    // ���������� ������ ��������� ����� � ������
    DWORD publicSize = (pBlob->KeyParam.BitLen + 7) / 8; 

	// ������������� ���������
	ASN1::IEncodable^ encodedParams = ASN1::Encodable::Decode(
		blob,    sizeof(CRYPT_PUBKEY_INFO_HEADER), 
		cbBlob - sizeof(CRYPT_PUBKEY_INFO_HEADER)
	); 
	// ������������ ��������� � ���������������
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
    );  
	// �������� ������ ��� ��������� �����
	array<BYTE>^ xy = gcnew array<BYTE>(publicSize); 

	// ���������� �������� ��������� �����
	DWORD offsetKey = sizeof(CRYPT_PUBKEY_INFO_HEADER) + encodedParams->Encoded->Length; 

	// ������� �������� ��������� �����
    Array::Copy(blob, offsetKey, xy, 0, publicSize); 

	// ������������ �������� ��������� ����� 
	array<BYTE>^ encoded = ASN1::OctetString(xy).Encoded; 

	// ������������ ����
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(encoded, encoded->Length * 8); 

	// ������� �������������� ���� � �����������
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// ��������� ��� ����������
	if (dynamic_cast<GOST::GOSTR3410::IECPublicKey^>(publicKey) != nullptr)
	{
		// ������������� ��� ����������
		GOST::GOSTR3410::IECPublicKey^ ecPublicKey = (GOST::GOSTR3410::IECPublicKey^)publicKey; 

		// ������� ������������� �����
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// ������� ������ ����
		return gcnew GOSTR3410::PrivateKey(this, scope, ecPublicKey, hKeyPair, keyID, keyType);
	}
	// ������� ������� �������
	else return CAPI::CSP::Provider::GetPrivateKey(scope, publicKey, hKeyPair, keyType);
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::Provider::CreateAlgorithm(
	CAPI::Factory^ factory, SecurityStore^ scope, 
	String^ oid, ASN1::IEncodable^ parameters, System::Type^ type) 
{$
	for (int i = 0; i < 1; i++)
	{
		// ��� ���������� �����������
		if (type == CAPI::Hash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94) 
			{
				// ��� ��������������� ��������������
				if (parameters->Tag == ASN1::Tag::ObjectIdentifier) 					
				{
					// ������������� ������������� ����������
					oid = ASN1::ObjectIdentifier(parameters).Value;
				}
				// ���������� ������������� �� ���������
				else oid = ASN1::GOST::OID::hashes_cryptopro; 
 
				// ������� �������� �����������
				return gcnew Hash::GOSTR3411_1994(this, Handle, oid);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_256) 
			{
				// ������� �������� �����������
				return gcnew Hash::GOSTR3411_2012(this, Handle, 256);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_512) 
			{
				// ������� �������� �����������
				return gcnew Hash::GOSTR3411_2012(this, Handle, 512);
			}
		}
		// ��� ���������� ���������� ������������
		else if (type == Mac::typeid)
		{
			if (oid == ASN1::GOST::OID::gost28147_89_MAC) 
			{
				// ������������� ��������� ���������
				ASN1::GOST::GOST28147CipherParameters^ algParameters = 
					gcnew ASN1::GOST::GOST28147CipherParameters(parameters); 

				// ���������� ������������� ������� �����������
				String^ sboxOID = algParameters->ParamSet->Value; 

				// �������� ����������� ��������� ���������
				ASN1::GOST::GOST28147ParamSet^ namedParameters = 
					ASN1::GOST::GOST28147ParamSet::Parameters(sboxOID);
 
				// ������� �������� ���������� ������������
				return gcnew MAC::GOST28147(this, Handle, sboxOID, 
					namedParameters->KeyMeshing->Algorithm->Value, algParameters->IV->Value
				);
			}
			if (oid == ASN1::GOST::OID::gostR3411_94_HMAC) 
			{
				// ��� ��������������� ��������������
				if (parameters->Tag == ASN1::Tag::ObjectIdentifier) 					
				{
					// ������������� ������������� ����������
					oid = ASN1::ObjectIdentifier(parameters).Value;
				}
				// ���������� ������������� �� ���������
				else oid = ASN1::GOST::OID::hashes_cryptopro; 
 
				// ������� �������� �����������
				return gcnew MAC::HMAC_GOSTR3411_1994(this, Handle, oid);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_HMAC_256) 
			{
				// ������� �������� �����������
				return gcnew MAC::HMAC_GOSTR3411_2012(this, Handle, 256);
			}
			if (oid == ASN1::GOST::OID::gostR3411_2012_HMAC_512) 
			{
				// ������� �������� �����������
				return gcnew MAC::HMAC_GOSTR3411_2012(this, Handle, 512);
			}
		}
		// ��� ���������� ������������� ����������
		else if (type == CAPI::Cipher::typeid)
		{
			if (oid == ASN1::GOST::OID::gost28147_89)
			{ 
				// ���������� �������� �� ���������
				CipherMode^ mode = gcnew CipherMode::ECB();	PaddingMode padding = PaddingMode::None;

				// ������������� ��������� ���������
				ASN1::GOST::GOST28147CipherParameters^ algParameters = 
					gcnew ASN1::GOST::GOST28147CipherParameters(parameters); 

				// ���������� ������������� ����������
				ASN1::ObjectIdentifier^ paramSet = algParameters->ParamSet; 

				// ������� �������� ����������
				Using<IBlockCipher^> blockCipher(CreateBlockCipher(scope, "GOST28147", paramSet)); 

				// ������� �������������
				array<BYTE>^ iv = algParameters->IV->Value; 
		 
				// �������� ����������� ��������� ���������
				ASN1::GOST::GOST28147ParamSet^ namedParameters = 
					ASN1::GOST::GOST28147ParamSet::Parameters(paramSet->Value);

				// � ����������� �� ������ 
				switch (namedParameters->Mode->Value->IntValue)
				{
				// ���������� ����� ���������
				case 0: mode = gcnew CAPI::CipherMode::CTR(iv, 8); padding = PaddingMode::None;  break;  
				case 1: mode = gcnew CAPI::CipherMode::CFB(iv, 8); padding = PaddingMode::None;  break;
				case 2: mode = gcnew CAPI::CipherMode::CBC(iv, 8); padding = PaddingMode::PKCS5; break;
				}
				// ������� ����� ����������
				return gcnew Cipher::GOST28147::BlockMode((CAPI::CSP::BlockCipher^)blockCipher.Get(), mode, padding);
			}
		}
		// ��� ���������� ������������ �����
		else if (type == KeyDerive::typeid)
		{
			if (oid == ASN1::GOST::OID::keyMeshing_cryptopro) 
			{
				// ������������� ��������� ���������
				ASN1::ObjectIdentifier^ paramSet = gcnew ASN1::ObjectIdentifier(parameters); 

				// ������� �������� ����������
				Using<CAPI::CSP::BlockCipher^> blockCipher(gcnew Cipher::GOST28147(
					this, Handle, paramSet->Value, ASN1::GOST::OID::keyMeshing_none
				)); 
				// ������� ����� ���������
				CipherMode^ mode = gcnew CipherMode::ECB(); 
                
				// ������� �������� ���������� �����
				Using<CAPI::Cipher^> cipher(blockCipher.Get()->CreateBlockMode(mode)); 

				// ������� �������� ������������ �����
				return gcnew GOST::Derive::KeyMeshing(cipher.Get()); 
			}
		}
		// ��� ���������� ���������� �����
		else if (type == KeyWrap::typeid)
		{
			if (oid == ASN1::GOST::OID::keyWrap_none) 
			{
				// ������������� ��������� ���������
				ASN1::GOST::KeyWrapParameters^ algParameters = 
					gcnew ASN1::GOST::KeyWrapParameters(parameters); 

				// ���������� ������������� ������� �����������
				String^ sboxOID = algParameters->ParamSet->Value; 

				// ���������� UKM
				array<BYTE>^ ukm = (algParameters->Ukm != nullptr) ? algParameters->Ukm->Value : nullptr; 

				// ������� �������� ���������� �����
				return gcnew Wrap::RFC4357_NONE(this, Handle, sboxOID, ukm);
			}
			if (oid == ASN1::GOST::OID::keyWrap_cryptopro) 
			{
				// ������������� ��������� ���������
				ASN1::GOST::KeyWrapParameters^ algParameters = 
					gcnew ASN1::GOST::KeyWrapParameters(parameters); 

				// ���������� ������������� ������� �����������
				String^ sboxOID = algParameters->ParamSet->Value; 

				// ���������� UKM
				array<BYTE>^ ukm = (algParameters->Ukm != nullptr) ? algParameters->Ukm->Value : nullptr; 

				// ������� �������� ���������� �����
				return gcnew Wrap::RFC4357_CPRO(this, Handle, sboxOID, ukm);
			}
		}
		// ��� ���������� ������� ���-��������
		else if (type == SignHash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411_2012_256);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411_2012_512);
			}
		}
		// ��� ���������� ������� ���-��������
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411_2012_256);
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512) 
			{
				// ������� �������� ������� ���-��������
				return gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411_2012_512);
			}
		}
		// ��� ���������� ������� ������
		else if (type == SignData::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94_R3410_2001) 
			{
				// ������� �������� ������� ���-��������
				Using<SignHash^> signHash(gcnew Sign::GOSTR3410::SignHash(this, CALG_GR3411));

				// ������� �������� ������� ������
				return gcnew Sign::GOSTR3410::SignData2001(this, signHash.Get()); 
			}
		}
		// ��� ���������� ������� ������
		else if (type == VerifyData::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3411_94_R3410_2001) 
			{
				// ������� �������� ������� ���-��������
				Using<VerifyHash^> verifyHash(gcnew Sign::GOSTR3410::VerifyHash(this, CALG_GR3411));

				// ������� �������� ������� ������
				return gcnew Sign::GOSTR3410::VerifyData2001(this, verifyHash.Get()); 
			}
		}
		// ��� ���������� ������������ ������ �����
		else if (type == IKeyAgreement::typeid)
		{
			if (oid == ASN1::GOST::OID::gostR3410_2001)
			{
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_256)
			{
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
			if (oid == ASN1::GOST::OID::gostR3410_2012_512)
			{
				// ������� �������� ������������ ������ �����
				return gcnew Keyx::GOSTR3410::KeyAgreement(this, 8); 
			}
		}
	}
    // ������� ������� �������
	return CAPI::GOST::Factory::RedirectAlgorithm(factory, scope, oid, parameters, type);
}

