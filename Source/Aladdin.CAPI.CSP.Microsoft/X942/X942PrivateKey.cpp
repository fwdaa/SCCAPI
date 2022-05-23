#include "..\stdafx.h"
#include "X942PrivateKey.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942PrivateKey.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������ ���� DH
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Microsoft::X942::PrivateKey::GetPrivateValue()
{$
    // �������������� ������ ����
    array<BYTE>^ blob = Export(nullptr, 0); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob;

	// �������� ���������� �� ���������� � ������
	DSSPUBKEY* pInfo = (DSSPUBKEY*)(pBlob + 1); 
	
	// ���������� �������� ����������
	DWORD offsetParams = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY); 
	
	// �������� ����� ���������� �������
	DWORD cbX = pInfo->bitlen / 8; array<BYTE>^ arrX = gcnew array<BYTE>(cbX);

	// ����������� �������� ������� �����
	Array::Copy(blob, offsetParams + 2 * cbX, arrX, 0, cbX); 

	// ������������� ��������
	x = Math::Convert::ToBigInteger(arrX, Endian); 
}

