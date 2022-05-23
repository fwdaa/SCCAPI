#include "..\stdafx.h"
#include "X957Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957Encoding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������������� ������ ��������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::CNG::Microsoft::X957::Encoding::GetPublicKeyInfo(CAPI::CNG::NKeyHandle^ hPublicKey)
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = hPublicKey->Export(nullptr, LEGACY_DSA_PUBLIC_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; DSSPUBKEY_VER3* pInfo = (DSSPUBKEY_VER3*)(pBlob + 1);

	// �������������� �������� ����
	cbBlob = hPublicKey->Export(nullptr, LEGACY_DSA_PUBLIC_BLOB, 0, IntPtr(pBlob), cbBlob); 

	// ������� ������ ����������� �����
	Math::Endian endian = Math::Endian::LittleEndian; 

	// ���������� �������� ����������
	DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY_VER3); 

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
	ASN1::IEncodable^ encodedParams = gcnew ASN1::ANSI::X957::DssParms(
		gcnew ASN1::Integer(P), gcnew ASN1::Integer(Q), gcnew ASN1::Integer(G)
	); 
	// ������������ ��������� ���������
	ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = 
		gcnew ASN1::ISO::AlgorithmIdentifier(gcnew ASN1::ObjectIdentifier(
            ASN1::ANSI::OID::x957_dsa), encodedParams); 

	// ������������ �������� �����
	ASN1::BitString^ encodedKey = gcnew ASN1::BitString(ASN1::Integer(Y).Encoded); 

	// ������� �������������� ���� � ���������
	return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::X957::Encoding::GetParametersBlob(
	ANSI::X957::IParameters^ parameters, BCRYPT_DSA_PARAMETER_HEADER* pBlob, DWORD cbBlob)
{$
	// ������������ ��������� 
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
	array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian); 
	array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters->Q, Endian); 

	// ��������� ������������ ����������
	if (arrQ->Length > 20) throw gcnew ArgumentException();

	// ���������� ������ ��������� ����������
	DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER) + 2 * arrP->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// �������� ���������� ������
	PBYTE pb = (PBYTE)pBlob + cb; memset(pBlob, 0, cb); 
	
	// ������� ��������� ����������
	pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC; 

	// ������� ������� ����������
	pBlob->cbLength = cb; pBlob->cbKeyLength = arrP->Length; 

	// ������� ���������� ���������� �����������
	memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

	// ����������� �������� Q
	Marshal::Copy(arrQ, 0, IntPtr(PBYTE(pBlob + 1) - arrQ->Length), arrQ->Length); 

	// ����������� ��������� 
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length; 
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� � ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::X957::Encoding::GetKeyPairBlob(
	ANSI::X957::IPublicKey^ publicKey, ANSI::X957::IPrivateKey^ privateKey, 
	BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)privateKey->Parameters; 

	// ������������ ���������� �����
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian);
	array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters->Q, Endian);
	array<BYTE>^ arrX = Math::Convert::FromBigInteger(privateKey->X, Endian);  

	// ��������� ������������ ����������
	if (arrQ->Length > 20 || arrX->Length > 20) throw gcnew ArgumentException();

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * arrP->Length + 20; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������������ ���������� �����
	array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian); 
    array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian);

	// ������� ��������� ���������
	memset(pBlob, 0, cb); pBlob->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cbBlob; pBlob->cbKey = arrP->Length; 

	// ������� ���������� ���������� �����������
	memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

	// ����������� �������� Q
	Marshal::Copy(arrQ, 0, IntPtr(PBYTE(pBlob + 1) - arrQ->Length), arrQ->Length); 

	// �������� ��������� ��������
	Marshal::Copy(arrX, 0, IntPtr(pb - arrX->Length), arrX->Length); pb -=           20;  
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::X957::Encoding::GetPrivateKeyBlob(
	ANSI::X957::IPrivateKey^ privateKey, BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// ��������� ������� ������
	if (pBlob == nullptr) return GetKeyPairBlob(nullptr, privateKey, pBlob, cbBlob); 

	// �������� ��������� �����
	ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)privateKey->Parameters; 

	// ��������� �������� ����
	Math::BigInteger^ Y = parameters->G->ModPow(privateKey->X, parameters->P);

	// ������� �������� ����
	ANSI::X957::IPublicKey^ publicKey = gcnew ANSI::X957::PublicKey(
		privateKey->KeyFactory, parameters, Y
	); 
	// �������� ��������� ��� ������� ������� �����
	return GetKeyPairBlob(publicKey, privateKey, pBlob, cbBlob); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��� ������� ��������� �����
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::Microsoft::X957::Encoding::GetPublicKeyBlob(
	ANSI::X957::IPublicKey^ publicKey, BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob)
{$
	// �������� ��������� �����
	ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)publicKey->Parameters; 

	// ������������ ���������� ������� �����
	array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters->P, Endian); 
    array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters->G, Endian);  
	array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters->Q, Endian); 
    array<BYTE>^ arrY = Math::Convert::FromBigInteger(publicKey ->Y, Endian);  

	// ��������� ������������ ����������
	if (arrQ->Length > 20) throw gcnew ArgumentException();

	// ���������� ������ ��������� �������
	DWORD cb = sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * arrP->Length; 

	// ��������� ������������� ������
	if (pBlob == 0) return cb; if (cb > cbBlob) throw gcnew OutOfMemoryException();

	// ������� ��������� ���������
	memset(pBlob, 0, cbBlob); pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC; 
	
	// ���������� ������ ������ � �����
	PBYTE pb = (PBYTE)pBlob + cbBlob; pBlob->cbKey = arrP->Length; 

	// ������� ���������� ���������� �����������
	memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

	// ����������� �������� Q
	Marshal::Copy(arrQ, 0, IntPtr(PBYTE(pBlob + 1) - arrQ->Length), arrQ->Length); 

	// �������� ��������� ��������
	Marshal::Copy(arrY, 0, IntPtr(pb - arrY->Length), arrY->Length); pb -= arrP->Length;  
	Marshal::Copy(arrG, 0, IntPtr(pb - arrG->Length), arrG->Length); pb -= arrP->Length;  
	Marshal::Copy(arrP, 0, IntPtr(pb - arrP->Length), arrP->Length); pb -= arrP->Length;  
	return cb; 
}

///////////////////////////////////////////////////////////////////////
// ����������� ������� DSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::X957::Encoding::EncodeSignature(
	ANSI::X957::IParameters^ parameters, ASN1::ANSI::X957::DssSigValue^ signature)
{$
	// ���������� �������� ���������
	int bytesR = (parameters->Q->BitLength + 7) / 8; 

	// ������������ ��������� R � S
	array<BYTE>^ R = Math::Convert::FromBigInteger(signature->R->Value, Endian, bytesR); 
	array<BYTE>^ S = Math::Convert::FromBigInteger(signature->S->Value, Endian, bytesR); 

	// ���������� ��������� R � S
	return Arrays::Concat(R, S); 
}

Aladdin::ASN1::ANSI::X957::DssSigValue^ 
Aladdin::CAPI::CNG::Microsoft::X957::Encoding::DecodeSignature(
	ANSI::X957::IParameters^ parameters, array<BYTE>^ encoded)
{$
	// ���������� �������� ���������
	int bytesR = (parameters->Q->BitLength + 7) / 8; int bytesS = encoded->Length - bytesR; 

	// ��������� ������ �������
	if (bytesS <= 0) throw gcnew InvalidDataException(); 

	// ������������� ��������� R � S
	Math::BigInteger^ R = Math::Convert::ToBigInteger(encoded,      0, bytesR, Endian); 
	Math::BigInteger^ S = Math::Convert::ToBigInteger(encoded, bytesR, bytesS, Endian); 

	// ������������ �������
	return gcnew ASN1::ANSI::X957::DssSigValue(gcnew ASN1::Integer(R), gcnew ASN1::Integer(S)); 
}
