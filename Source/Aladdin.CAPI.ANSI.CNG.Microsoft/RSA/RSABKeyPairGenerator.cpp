#include "..\stdafx.h"
#include "RSABKeyPairGenerator.h"
#include "RSAEncoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSABKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::RSA::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// ������� ��������� ����� �����
	int bits = ((IKeySizeParameters^)parameters)->KeyBits;

	// ������������� ���� ������
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(bits, 0)); 
    
	// ��������� �������� ���� ������
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// ���������� ��������� ������ ������
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// ��������� �������������� ����
	BCRYPT_RSAKEY_BLOB* pHeader = (BCRYPT_RSAKEY_BLOB*)(PBYTE)ptrBlob; 

	// �������������� ������ ����
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// �������� ������ ��������� ��������
	array<BYTE>^ arrPubExp  = gcnew array<BYTE>(pHeader->cbPublicExp); 
	array<BYTE>^ arrModulus = gcnew array<BYTE>(pHeader->cbModulus	); 
	array<BYTE>^ arrPrime1  = gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrPrime2  = gcnew array<BYTE>(pHeader->cbPrime2	); 
	array<BYTE>^ arrExp1	= gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrExp2	= gcnew array<BYTE>(pHeader->cbPrime2	); 
	array<BYTE>^ arrCoeff   = gcnew array<BYTE>(pHeader->cbPrime1	); 
	array<BYTE>^ arrPrivExp = gcnew array<BYTE>(pHeader->cbModulus	); 

	// ������� �������� ����������
	DWORD offset = sizeof(BCRYPT_RSAKEY_BLOB);

	// ������� ��������� ��������
	Array::Copy(blob, offset, arrPubExp,  0, pHeader->cbPublicExp); offset += pHeader->cbPublicExp;  
	Array::Copy(blob, offset, arrModulus, 0, pHeader->cbModulus	 ); offset += pHeader->cbModulus;  
	Array::Copy(blob, offset, arrPrime1,  0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrPrime2,  0, pHeader->cbPrime2	 ); offset += pHeader->cbPrime2;  
	Array::Copy(blob, offset, arrExp1,    0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrExp2,    0, pHeader->cbPrime2	 ); offset += pHeader->cbPrime2;  
	Array::Copy(blob, offset, arrCoeff,   0, pHeader->cbPrime1	 ); offset += pHeader->cbPrime1;  
	Array::Copy(blob, offset, arrPrivExp, 0, pHeader->cbModulus	 ); offset += pHeader->cbModulus; 

	// ������������� ��������� ��������
	Math::BigInteger^ pubExp  = Math::Convert::ToBigInteger(arrPubExp , Encoding::Endian); 
	Math::BigInteger^ modulus = Math::Convert::ToBigInteger(arrModulus, Encoding::Endian); 
	Math::BigInteger^ prime1  = Math::Convert::ToBigInteger(arrPrime1 , Encoding::Endian); 
	Math::BigInteger^ prime2  = Math::Convert::ToBigInteger(arrPrime2 , Encoding::Endian); 
	Math::BigInteger^ exp1	  = Math::Convert::ToBigInteger(arrExp1	  , Encoding::Endian); 
	Math::BigInteger^ exp2	  = Math::Convert::ToBigInteger(arrExp2	  , Encoding::Endian); 
	Math::BigInteger^ coeff   = Math::Convert::ToBigInteger(arrCoeff  , Encoding::Endian); 
	Math::BigInteger^ privExp = Math::Convert::ToBigInteger(arrPrivExp, Encoding::Endian); 

	// �������� ������� �����������
	KeyFactory^ keyFactory = Factory->GetKeyFactory(keyOID); 

	// ������� ������ ��������� �����
	IPublicKey^ publicKey = gcnew ANSI::RSA::PublicKey(keyFactory, modulus, pubExp); 

	// ������� ������ ������� �����
	Using<IPrivateKey^> privateKey(gcnew ANSI::RSA::PrivateKey(Factory, 
		nullptr, keyOID, modulus, pubExp, privExp, prime1, prime2, exp1, exp2, coeff
	)); 
    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

