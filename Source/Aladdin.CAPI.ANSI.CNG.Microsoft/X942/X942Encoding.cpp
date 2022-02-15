#include "..\stdafx.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942Encoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������������� ������ ��������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPublicKeyInfo(
	CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = hPublicKey->Export(nullptr, LEGACY_DH_PUBLIC_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// �������������� �������� ����
	cbBlob = hPublicKey->Export(nullptr, LEGACY_DH_PUBLIC_BLOB, 0, IntPtr(pBlob), cbBlob); 

	// ������� ������ ����������� �����
	Math::Endian endian = Math::Endian::LittleEndian; 

	// ������������� ��� ���������
	DHPUBKEY_VER3* pInfo = (DHPUBKEY_VER3*)(pBlob + 1); 

	// ���������� �������� ����������
	DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3); 

	// �������� ������ ��� ����������
	array<BYTE>^ arrP = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
	array<BYTE>^ arrQ = gcnew array<BYTE>((pInfo->bitlenQ + 7) / 8); 
	array<BYTE>^ arrG = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
	array<BYTE>^ arrY = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 

	// ��������� ���������
	Array::Copy(blob, offset, arrP, 0, arrP->Length); offset += arrP->Length; 
	Array::Copy(blob, offset, arrQ, 0, arrQ->Length); offset += arrQ->Length; 
	Array::Copy(blob, offset, arrG, 0, arrG->Length); offset += arrG->Length; 
	Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

	// ������������� ���������
	Math::BigInteger^ P = Math::Convert::ToBigInteger(arrP, endian); 
	Math::BigInteger^ Q = Math::Convert::ToBigInteger(arrQ, endian); 
	Math::BigInteger^ G = Math::Convert::ToBigInteger(arrG, endian); 
	Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, endian); 

	// ������������ ���������
	ASN1::IEncodable^ encodedParams = gcnew ASN1::ANSI::X942::DomainParameters(
		gcnew ASN1::Integer(P), gcnew ASN1::Integer(G), gcnew ASN1::Integer(Q), nullptr, nullptr
	); 
	// ������������ ��������� ���������
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(gcnew ASN1::ObjectIdentifier(
            ASN1::ANSI::OID::x942_dh_public_key), encodedParams); 

	// ������������ �������� �����
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(ASN1::Integer(Y).Encoded); 

	// ������� �������������� ���� � ���������
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetParametersBlob(
	ANSI::X942::IParameters^ parameters, BCRYPT_DH_PARAMETER_HEADER* pBlob, DWORD cbBlob)
{$
	// ������������ ��������� 
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
    array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  

	// ���������� ������ ��������� ����������
	DWORD cb = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 2 * arrP->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// �������� ���������� ������
	PBYTE pb = (PBYTE)pBlob + cb; memset(pBlob, 0, cb); 
	
	// ������� ��������� ����������
	pBlob->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; 

	// ������� ������� ����������
	pBlob->cbLength = cb; pBlob->cbKeyLength = arrP->Length; 

	// ����������� ��������� 
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length; 
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� � ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetKeyPairBlob(
	ANSI::X942::IPublicKey^ publicKey, ANSI::X942::IPrivateKey^ privateKey, 
	BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)privateKey->Parameters; 

	// ������������ ���������� �����
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_DH_KEY_BLOB) + 4 * arrP->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������������ ���������� �����
    array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian); 
    array<BYTE>^ arrX = Math::Convert::FromBigInteger(privateKey->X, Endian);  

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->cbKey = arrP->Length; 

	// �������� ��������� ��������
	Marshal::Copy(arrX, 0, IntPtr(pb - arrX->Length), arrX->Length); pb -= arrP->Length;  
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPrivateKeyBlob(
	ANSI::X942::IPrivateKey^ privateKey, BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// ��������� ������� ������
	if (pBlob == nullptr) return GetKeyPairBlob(nullptr, privateKey, pBlob, cbBlob); 

	// �������� ��������� �����
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)privateKey->Parameters; 

	// ��������� �������� ����
	Math::BigInteger^ Y = parameters->G->ModPow(privateKey->X, parameters->P);

	// ������� �������� ����
	ANSI::X942::IPublicKey^ publicKey = gcnew ANSI::X942::PublicKey(
		privateKey->KeyFactory, parameters, Y
	); 
	// �������� ��������� ��� ������� ������� �����
	return GetKeyPairBlob(publicKey, privateKey, pBlob, cbBlob); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::ANSI::CNG::Microsoft::X942::Encoding::GetPublicKeyBlob(
	ANSI::X942::IPublicKey^ publicKey, BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)publicKey->Parameters; 

	// ������������ ���������� ������� �����
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
	array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  
	array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian);  

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_DH_KEY_BLOB) + 3 * arrP->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cb; pBlob->cbKey = arrP->Length; 

	// �������� ��������� ��������
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

