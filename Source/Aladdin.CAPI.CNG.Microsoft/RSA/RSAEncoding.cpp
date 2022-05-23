#include "..\stdafx.h"
#include "RSAEncoding.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAEncoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������������� ������ ��������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CNG::Microsoft::RSA::Encoding::GetPublicKeyInfo(
    CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbInfo = 0; AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hPublicKey->Value, 0, X509_ASN_ENCODING, szOID_RSA_RSA, 0, 0, 0, &cbInfo
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> vecInfo(cbInfo); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&vecInfo[0]; 

	// �������� �������� �����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hPublicKey->Value, 0, X509_ASN_ENCODING, szOID_RSA_RSA, 0, 0, pInfo, &cbInfo
	)); 
	// ���������� ������ ��� ����������� �����
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptEncodeObject(
		X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, 0, &cb
	)); 
	// �������� ������ ��� ����������� �����
	array<BYTE>^ encoded = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrEncoded = &encoded[0]; 

	// ������������ ����
	AE_CHECK_WINAPI(::CryptEncodeObject(
		X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, ptrEncoded, &cb
	));
	// ������������� �������� ����
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(ASN1::Encodable::Decode(encoded, 0, cb)); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::RSA::Encoding::GetPrivateKeyBlob(
	ANSI::RSA::IPrivateKey^ privateKey, BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// ������������ ���������� ������� �����
	array<BYTE>^ arrPubExp  = Math::Convert::FromBigInteger(privateKey->PublicExponent , Endian); 
	array<BYTE>^ arrModulus = Math::Convert::FromBigInteger(privateKey->Modulus		   , Endian);  
	array<BYTE>^ arrPrime1  = Math::Convert::FromBigInteger(privateKey->PrimeP		   , Endian);  
	array<BYTE>^ arrPrime2  = Math::Convert::FromBigInteger(privateKey->PrimeQ		   , Endian);  
	array<BYTE>^ arrExp1	= Math::Convert::FromBigInteger(privateKey->PrimeExponentP , Endian);  
	array<BYTE>^ arrExp2	= Math::Convert::FromBigInteger(privateKey->PrimeExponentQ , Endian);  
	array<BYTE>^ arrCoeff   = Math::Convert::FromBigInteger(privateKey->CrtCoefficient , Endian);  
	array<BYTE>^ arrPrivExp = Math::Convert::FromBigInteger(privateKey->PrivateExponent, Endian);  

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_RSAKEY_BLOB) + arrPubExp->Length + 
		2 * arrModulus->Length + 3 * arrPrime1->Length + 2 * arrPrime2->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->BitLength = privateKey->Modulus->BitLength; 

	// ���������� ������� �����������
	pBlob->cbPublicExp = arrPubExp ->Length; pBlob->cbModulus = arrModulus->Length; 
	pBlob->cbPrime1	   = arrPrime1 ->Length; pBlob->cbPrime2  = arrPrime2 ->Length;  

	// �������� ��������� ��������
	Marshal::Copy(arrPrivExp, 0, IntPtr(pb - arrPrivExp->Length), arrPrivExp->Length); pb -= arrModulus->Length;  
	Marshal::Copy(arrCoeff,   0, IntPtr(pb - arrCoeff  ->Length), arrCoeff  ->Length); pb -= arrPrime1 ->Length;  
	Marshal::Copy(arrExp2,    0, IntPtr(pb - arrExp2   ->Length), arrExp2   ->Length); pb -= arrPrime2 ->Length;  
	Marshal::Copy(arrExp1,    0, IntPtr(pb - arrExp1   ->Length), arrExp1   ->Length); pb -= arrPrime1 ->Length;
	Marshal::Copy(arrPrime2,  0, IntPtr(pb - arrPrime2 ->Length), arrPrime2 ->Length); pb -= arrPrime2 ->Length;  
	Marshal::Copy(arrPrime1,  0, IntPtr(pb - arrPrime1 ->Length), arrPrime1 ->Length); pb -= arrPrime1 ->Length;  
	Marshal::Copy(arrModulus, 0, IntPtr(pb - arrModulus->Length), arrModulus->Length); pb -= arrModulus->Length;  
	Marshal::Copy(arrPubExp,  0, IntPtr(pb - arrPubExp ->Length), arrPubExp ->Length); pb -= arrPubExp ->Length;
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::RSA::Encoding::GetPublicKeyBlob(
	ANSI::RSA::IPublicKey^ publicKey, BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob)
{$
	// ������������ ���������� ������� �����
	array<BYTE>^ arrPubExp  = Math::Convert::FromBigInteger(publicKey->PublicExponent, Endian); 
	array<BYTE>^ arrModulus = Math::Convert::FromBigInteger(publicKey->Modulus	     , Endian);  

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_RSAKEY_BLOB) + arrPubExp->Length + arrModulus->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->BitLength = publicKey->Modulus->BitLength; 

	// ���������� ������� �����������
	pBlob->cbPublicExp = arrPubExp ->Length; pBlob->cbModulus = arrModulus->Length; 

	// �������� ��������� ��������
	Marshal::Copy(arrModulus, 0, IntPtr(pb - arrModulus->Length), arrModulus->Length); pb -= arrModulus->Length;  
	Marshal::Copy(arrPubExp,  0, IntPtr(pb - arrPubExp ->Length), arrPubExp ->Length); pb -= arrPubExp ->Length;
	return cb; 
}

