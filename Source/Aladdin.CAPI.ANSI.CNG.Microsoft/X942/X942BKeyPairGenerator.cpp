#include "..\stdafx.h"
#include "X942BKeyPairGenerator.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942BKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPair^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X942::BKeyPairGenerator::Generate(String^ keyOID)
{$
	// ���������� ��������� ������ ������
	DWORD cbParamBlob = Encoding::GetParametersBlob(parameters, 0, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ paramBlob = gcnew array<BYTE>(cbParamBlob); pin_ptr<BYTE> ptrParamBlob = &paramBlob[0]; 

	// ��������� �������������� ����
	BCRYPT_DH_PARAMETER_HEADER* pParamBlob = (BCRYPT_DH_PARAMETER_HEADER*)(PBYTE)ptrParamBlob; 

	// �������� ��������� ��� ������� ����������
	cbParamBlob = Encoding::GetParametersBlob(parameters, pParamBlob, cbParamBlob); 

	// ������������� ���� ������
	Using<CAPI::CNG::BKeyHandle^> hKeyPair(Handle->CreateKeyPair(pParamBlob->cbKeyLength * 8, 0));

	// ���������� ��������� 
	hKeyPair.Get()->SetParam(BCRYPT_DH_PARAMETERS, IntPtr(pParamBlob), cbParamBlob, 0); 

	// ��������� �������� ���� ������
	Handle->FinalizeKeyPair(hKeyPair.Get(), 0);

	// ���������� ��������� ������ ������
	DWORD cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0, IntPtr::Zero, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BCRYPT_DH_KEY_BLOB* pHeader = (BCRYPT_DH_KEY_BLOB*)(PBYTE)ptrBlob; 

	// �������������� ������ ����
	cbBlob = hKeyPair.Get()->Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0, IntPtr(pHeader), cbBlob); 

	// �������� ������ ��������� ��������
	array<BYTE>^ arrY = gcnew array<BYTE>(pHeader->cbKey); 
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// ������� ��������� ������� ��� ����������
	DWORD offset = sizeof(BCRYPT_DH_KEY_BLOB) + 2 * pHeader->cbKey; 
	
	// ������� �������� � ������ ����
	Array::Copy(blob, offset, arrY,  0, pHeader->cbKey); offset += pHeader->cbKey; 
	Array::Copy(blob, offset, arrX,  0, pHeader->cbKey); offset += pHeader->cbKey; 

	// ������������� �������� � ������ ����
	Math::BigInteger^ y = Math::Convert::ToBigInteger(arrY, Encoding::Endian); 
	Math::BigInteger^ x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 

	// �������� ������� �����������
	KeyFactory^ keyFactory = Factory->GetKeyFactory(keyOID); 

	// ������� ������ ��������� �����
	IPublicKey^ publicKey = gcnew ANSI::X942::PublicKey (keyFactory, parameters, y); 

	// ������� ������ ������� �����
	Using<IPrivateKey^> privateKey(gcnew ANSI::X942::PrivateKey(Factory, nullptr, keyOID, parameters, x)); 

    // ������� ��������� ���� ������
    return gcnew KeyPair(publicKey, privateKey.Get(), nullptr);  
}

