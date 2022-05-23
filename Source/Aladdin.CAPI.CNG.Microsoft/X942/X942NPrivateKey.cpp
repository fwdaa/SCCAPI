#include "..\stdafx.h"
#include "X942NPrivateKey.h"
#include "X942Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X942::NPrivateKey::GetPrivateValue()
{$
	// �������������� ����
	array<BYTE>^ blob = Export(nullptr, BCRYPT_DH_PRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BCRYPT_DH_KEY_BLOB* pHeader = (BCRYPT_DH_KEY_BLOB*)(PBYTE)ptrBlob; 

	// �������� ����� ���������� �������
	array<BYTE>^ arrX = gcnew array<BYTE>(pHeader->cbKey); 

	// ������� ��������� ������� ��� ����������
	DWORD offset = sizeof(BCRYPT_DH_KEY_BLOB) + 3 * pHeader->cbKey; 
		
	// ������� ������ ����
	Array::Copy(blob, offset, arrX,  0, pHeader->cbKey);

	// ������������� ������ ����
	x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}
