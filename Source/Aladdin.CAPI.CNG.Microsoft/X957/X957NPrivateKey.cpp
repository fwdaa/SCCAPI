#include "..\stdafx.h"
#include "X957NPrivateKey.h"
#include "X957Encoding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957NPrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Microsoft::X957::NPrivateKey::GetPrivateValue()
{$
	// �������������� ����
	array<BYTE>^ blob = Export(nullptr, BCRYPT_DSA_PRIVATE_BLOB, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	BCRYPT_DSA_KEY_BLOB* pHeader = (BCRYPT_DSA_KEY_BLOB*)(PBYTE)ptrBlob; 

	// ���������� �������� �����
	DWORD offsetKey = sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * pHeader->cbKey; 
		
	// ������� ������ ����
	array<BYTE>^ arrX = gcnew array<BYTE>(20); Array::Copy(blob, offsetKey, arrX, 0, 20);

	// ������������� ������ ����
	x = Math::Convert::ToBigInteger(arrX, Encoding::Endian); 
}
