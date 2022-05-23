#include "..\stdafx.h"
#include "X957BKeyPairGenerator.h"
#include "X957Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957BKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::CNG::Microsoft::X957::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// ���������� ��������� ������ ������
	DWORD cbParamBlob = Encoding::GetParametersBlob(parameters, 0, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ paramBlob = gcnew array<BYTE>(cbParamBlob); pin_ptr<BYTE> ptrParamBlob = &paramBlob[0]; 

	// ��������� �������������� ����
	BCRYPT_DSA_PARAMETER_HEADER* pParamBlob = (BCRYPT_DSA_PARAMETER_HEADER*)(PBYTE)ptrParamBlob; 

	// �������� ��������� ��� ������� ����������
	cbParamBlob = Encoding::GetParametersBlob(parameters, pParamBlob, cbParamBlob); 

	// ������������� ���� ������
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(pParamBlob->cbKeyLength * 8, 0));

	// ���������� ��������� 
	hKeyPair.Get()->SetParam(BCRYPT_DSA_PARAMETERS, IntPtr(pParamBlob), cbParamBlob, 0); 

	// ��������� �������� ���� ������
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// ���������� ��������� ������ ������
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BCRYPT_DSA_KEY_BLOB* pHeader = (BCRYPT_DSA_KEY_BLOB*)(PBYTE)ptrBlob; 

	// �������������� ������ ����
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// �������� ������ ��������� ��������
	array<BYTE>^ arrY = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrX = gcnew array<BYTE>(20); 

	// ���������� �������� ����������
	DWORD offset = sizeof(BCRYPT_DSA_KEY_BLOB) + 2 * pHeader->cbKey; 
	
	// ������� �������� � ������ ����
	Array::Copy(blob, offset, arrY,  0, arrY->Length); offset += arrY->Length; 
	Array::Copy(blob, offset, arrX,  0, arrX->Length); offset += arrX->Length; 

	// ������������� �������� � ������ ����
	Math::BigInteger^ y = Math::Convert::ToBigInteger(arrY, Encoding::Endian); 
	Math::BigInteger^ x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 

	// �������� ������� �����������
	KeyFactory^ keyFactory = Factory->GetKeyFactory(keyOID); 

	// ������� ������ ��������� �����
	IPublicKey^ publicKey = gcnew ANSI::X957::PublicKey(keyFactory, parameters, y); 

	// ������� ������ ������� �����
	Using<IPrivateKey^> privateKey(gcnew ANSI::X957::PrivateKey(Factory, nullptr, keyOID, parameters, x)); 

    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr); 
}

