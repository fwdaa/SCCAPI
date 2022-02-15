#include "..\stdafx.h"
#include "X962Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962Encoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ���������� ��� ���������
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetKeyName(
	ANSI::X962::IParameters^ parameters, DWORD keyType)
{$
	// ��������� ��� ����������
	if (dynamic_cast<INamedParameters^>(parameters) == nullptr) throw gcnew NotSupportedException(); 

	// ������� ������������� ����������
	String^ paramOID = ((INamedParameters^)parameters)->Oid; 

	if (paramOID == ASN1::ANSI::OID::x962_curves_prime256v1)
	{
		// ������� ��� ���������
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp384r1)
	{
		// ������� ��� ���������
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P384_ALGORITHM : BCRYPT_ECDH_P384_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp521r1)
	{
		// ������� ��� ���������
		return (keyType == AT_SIGNATURE) ? BCRYPT_ECDSA_P521_ALGORITHM : BCRYPT_ECDH_P521_ALGORITHM; 
	}
	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// ������������� ������ ��������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPublicKeyInfo(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = hPublicKey->Export(nullptr, BCRYPT_ECCPUBLIC_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// ��������� �������������� ����
	BCRYPT_ECCKEY_BLOB* pBlob = (BCRYPT_ECCKEY_BLOB*)(PBYTE)ptrBlob; 

	// �������������� �������� ����
	cbBlob = hPublicKey->Export(nullptr, BCRYPT_ECCPUBLIC_BLOB, 0, IntPtr(pBlob), cbBlob); 

	// � ����������� �� ���� �����
	String^ paramOID = nullptr; switch (pBlob->dwMagic)
	{
	// ������� ������������� ����������
	case BCRYPT_ECDSA_PUBLIC_P256_MAGIC: paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDH_PUBLIC_P256_MAGIC : paramOID = ASN1::ANSI::OID::x962_curves_prime256v1;    break; 
	case BCRYPT_ECDSA_PUBLIC_P384_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDH_PUBLIC_P384_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp384r1; break; 
	case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 
	case BCRYPT_ECDH_PUBLIC_P521_MAGIC : paramOID = ASN1::ANSI::OID::certicom_curves_secp521r1; break; 

	// ��� ������ ��������� ����������
	default: throw gcnew NotSupportedException(); 
	}
	// �������� ������ ��� ����������
	array<BYTE>^ arrX = gcnew array<BYTE>(pBlob->cbKey); 
	array<BYTE>^ arrY = gcnew array<BYTE>(pBlob->cbKey); 

	// ���������� �������� ����������
	DWORD offset = sizeof(BCRYPT_ECCKEY_BLOB); 

	// ��������� ���������
	Array::Copy(blob, offset, arrX, 0, arrX->Length); offset += arrX->Length; 
	Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

	// ������������� ���������
	Math::BigInteger^ X = Math::Convert::ToBigInteger(arrX, Endian); 
	Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, Endian); 

	// ������� ������� ����������� ������
	ANSI::X962::KeyFactory^ keyFactory = gcnew ANSI::X962::KeyFactory(
		ASN1::ANSI::OID::x962_ec_public_key
	); 
	// ������������� ��������� ���������
	ANSI::X962::IParameters^ ecParameters = (ANSI::X962::IParameters^)
		keyFactory->DecodeParameters(gcnew ASN1::ObjectIdentifier(paramOID)); 

	// ������� �������� ����
	IPublicKey^ publicKey = gcnew ANSI::X962::PublicKey(
		keyFactory, ecParameters, gcnew EC::Point(X, Y)
	); 
	// ������������ �������� ����
	return keyFactory->EncodePublicKey(publicKey); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� � ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetKeyPairBlob(String^ algName, 
	ANSI::X962::IPublicKey^ publicKey, ANSI::X962::IPrivateKey^ privateKey, 
	BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)privateKey->Parameters; 

	// ������� ������������ ����
	EC::FieldFp^ field = (EC::FieldFp^)parameters->Curve->Field; 

	// ���������� ������ ��������� 
	DWORD cbKey = (field->P->BitLength + 7) / 8; 

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cbKey; 

	// ��������� ������������� ������
	if (pBlob == nullptr) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->cbKey = cbKey; 

	// ������� ��� �����
	     if (algName == BCRYPT_ECDSA_P256_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC; 
	else if (algName == BCRYPT_ECDH_P256_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P384_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC; 
	else if (algName == BCRYPT_ECDH_P384_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P384_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P521_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC; 
	else if (algName == BCRYPT_ECDH_P521_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PRIVATE_P521_MAGIC; 

	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); 
	
	// ������� ���������� �����
	Math::BigInteger^ X = (Math::BigInteger^)publicKey->Q->X; 
	Math::BigInteger^ Y = (Math::BigInteger^)publicKey->Q->Y; 

	// ������������ ���������� ������� �����
	array<BYTE>^ arrX = Math::Convert::FromBigInteger(X,             Endian, cbKey); 
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(Y,             Endian, cbKey); 
    array<BYTE>^ arrD = Math::Convert::FromBigInteger(privateKey->D, Endian, cbKey);  

	// ������� �� �������� ����������
	PBYTE pbParams = (PBYTE)(pBlob + 1); DWORD offset = 0; 

	// �������� ��������� ��������
	Marshal::Copy(arrX, 0, IntPtr(pbParams + offset), arrX->Length); offset += arrX->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pbParams + offset), arrY->Length); offset += arrY->Length;  
	Marshal::Copy(arrD, 0, IntPtr(pbParams + offset), arrD->Length); offset += arrD->Length;  

	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPrivateKeyBlob(String^ algName, 
	ANSI::X962::IPrivateKey^ privateKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// ��������� ������� ������
	if (pBlob == nullptr) return GetKeyPairBlob(algName, nullptr, privateKey, pBlob, cbBlob); 

	// �������� ��������� �����
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)privateKey->Parameters; 

    // �������� ������� ����� �� �����
    EC::Point^ Q = parameters->Curve->Multiply(parameters->Generator, privateKey->D); 

	// ������� �������� ����
	ANSI::X962::IPublicKey^ publicKey = gcnew ANSI::X962::PublicKey(
		privateKey->KeyFactory, parameters, Q
	); 
	// �������� ��������� ��� ������� ������� �����
	return GetKeyPairBlob(algName, publicKey, privateKey, pBlob, cbBlob); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::GetPublicKeyBlob(String^ algName, 
	ANSI::X962::IPublicKey^ publicKey, BCRYPT_ECCKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X962::IParameters^ parameters = (ANSI::X962::IParameters^)publicKey->Parameters; 

	// ������� ������������ ����
	EC::FieldFp^ field = (EC::FieldFp^)parameters->Curve->Field; 

	// ���������� ������ ��������� 
	DWORD cbKey = (field->P->BitLength + 7) / 8; 

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cbKey; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->cbKey = cbKey; 

	// ������� ��� �����
	     if (algName == BCRYPT_ECDSA_P256_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC; 
	else if (algName == BCRYPT_ECDH_P256_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P384_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC; 
	else if (algName == BCRYPT_ECDH_P384_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC; 
	else if (algName == BCRYPT_ECDSA_P521_ALGORITHM) pBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC; 
	else if (algName == BCRYPT_ECDH_P521_ALGORITHM ) pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC; 

	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException(); 
	
	// ������� ���������� �����
	Math::BigInteger^ X = (Math::BigInteger^)publicKey->Q->X; 
	Math::BigInteger^ Y = (Math::BigInteger^)publicKey->Q->Y; 

	// ������������ ���������� ������� �����
	array<BYTE>^ arrX = Math::Convert::FromBigInteger(X, Endian, cbKey); 
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(Y, Endian, cbKey); 

	// ������� �� �������� ����������
	PBYTE pbParams = (PBYTE)(pBlob + 1); DWORD offset = 0; 

	// �������� ��������� ��������
	Marshal::Copy(arrX, 0, IntPtr(pbParams + offset), arrX->Length); offset += arrX->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pbParams + offset), arrY->Length); offset += arrY->Length;  

	return cb; 
}

///////////////////////////////////////////////////////////////////////
// ����������� ������� ECDSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::EncodeSignature(
	ANSI::X962::IParameters^ parameters, ASN1::ANSI::X962::ECDSASigValue^ signature)
{$
    // ���������� �������� ���������
    int bytesR = (parameters->Order->BitLength + 7) / 8; 

	// ������������ ��������� R � S
	array<BYTE>^ R = Math::Convert::FromBigInteger(signature->R->Value, Endian, bytesR); 
	array<BYTE>^ S = Math::Convert::FromBigInteger(signature->S->Value, Endian, bytesR); 

	// ���������� ��������� R � S
	return Arrays::Concat(R, S); 
}

Aladdin::ASN1::ANSI::X962::ECDSASigValue^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::Encoding::DecodeSignature(
	ANSI::X962::IParameters^ parameters, array<BYTE>^ encoded)
{$
    // ���������� �������� ���������
    int bytesR = (parameters->Order->BitLength + 7) / 8; int bytesS = encoded->Length - bytesR; 

	// ��������� ������ �������
	if (bytesS <= 0) throw gcnew InvalidDataException(); 

	// ������������� ��������� R � S
	Math::BigInteger^ R = Math::Convert::ToBigInteger(encoded,      0, bytesR, Endian); 
	Math::BigInteger^ S = Math::Convert::ToBigInteger(encoded, bytesR, bytesS, Endian); 

	// ������������ �������
	return gcnew ASN1::ANSI::X962::ECDSASigValue(
		gcnew ASN1::Integer(R), gcnew ASN1::Integer(S), nullptr, nullptr
	); 
}


