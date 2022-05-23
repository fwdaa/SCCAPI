#include "..\..\stdafx.h"
#include "ECDSABVerifyHash.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ECDSABVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� ECDSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Sign::ECDSA::BVerifyHash::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_ECCKEY_BLOB* pbBlob = (BCRYPT_ECCKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = X962::Encoding::GetPublicKeyBlob(algName, (ANSI::X962::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, BCRYPT_ECCPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

