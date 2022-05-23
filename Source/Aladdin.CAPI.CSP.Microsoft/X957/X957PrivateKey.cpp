#include "..\stdafx.h"
#include "X957PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� DSA
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Microsoft::X957::PrivateKey::GetPrivateValue()
{$
    // �������������� ������ ����
    array<BYTE>^ blob = Export(nullptr, CRYPT_BLOB_VER3); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

	// ��������� �������������� ����
	DSSPRIVKEY_VER3* pInfo = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// ���������� �������� ����������
	DWORD offsetParams = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPRIVKEY_VER3); 
	
    // ���������� ������� �����
    DWORD cbP = pInfo->bitlenP / 8; DWORD cbQ = pInfo->bitlenQ / 8; 
	DWORD cbX = pInfo->bitlenX / 8; DWORD cbJ = pInfo->bitlenJ / 8;
	
	// �������� ����� ���������� �������
	array<BYTE>^ arrX = gcnew array<BYTE>(cbX); 

	// ����������� �������� ������� �����
	Array::Copy(blob, offsetParams + 3 * cbP + cbQ + cbJ, arrX, 0, cbX); 

	// ������������� ��������
	x = Math::Convert::ToBigInteger(arrX, Endian); 
}

