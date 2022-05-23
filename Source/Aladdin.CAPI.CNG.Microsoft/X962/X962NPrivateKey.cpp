#include "..\stdafx.h"
#include "X962NPrivateKey.h"
#include "X962Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X962::NPrivateKey::GetPrivateValue()
{$
	// �������������� ����
	array<BYTE>^ blob = Export(nullptr, BCRYPT_ECCPRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BCRYPT_ECCKEY_BLOB* pHeader = (BCRYPT_ECCKEY_BLOB*)(PBYTE)ptrBlob; 

	// �������� ����� ���������� �������
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// ������� ��������� ������� ��� ����������
	DWORD offset = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * pHeader->cbKey; 
		
	// ������� ������ ����
	Array::Copy(blob, offset, arrX, 0, pHeader->cbKey);

	// ������������� ������ ����
	d = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}

