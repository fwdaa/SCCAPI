#include "..\..\..\stdafx.h"
#include "..\..\..\PrimitiveProvider.h"
#include "RSAOAEPNDecipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAOAEPNDecipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� ���������� ������ RSA OAEP
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Microsoft::Keyx::RSA::OAEP::NDecipherment::Decrypt(
	SecurityObject^ scope, CAPI::CNG::NKeyHandle^ hPrivateKey, array<BYTE>^ data)
{$
	// ���������� ��������� ������ ������
	DWORD cbInfo = sizeof(BCRYPT_OAEP_PADDING_INFO) + label->Length; std::vector<BYTE> vecInfo(cbInfo); 

	// �������� ����� ���������� �������
	BCRYPT_OAEP_PADDING_INFO* pInfo = (BCRYPT_OAEP_PADDING_INFO*)&vecInfo[0]; 

	// ���������� ��� ��������� ����������� 
	pInfo->pszAlgId = PrimitiveProvider::GetHashName(hashOID); 

	// ���������� ��� ��������� ����������� � ��������� �� �����
	pInfo->pbLabel = (PBYTE)(pInfo + 1); pInfo->cbLabel = label->Length; 

	// ����������� �����
	Marshal::Copy(label, 0, IntPtr(pInfo->pbLabel), pInfo->cbLabel); 

	// ������������ ������
	return Decrypt(scope, hPrivateKey, IntPtr(pInfo), data, BCRYPT_PAD_OAEP); 
}
