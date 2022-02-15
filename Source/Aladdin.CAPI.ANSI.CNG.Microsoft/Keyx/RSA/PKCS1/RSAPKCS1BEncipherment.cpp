#include "..\..\..\stdafx.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BEncipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BEncipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� ���������� ������ RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::Keyx::RSA::PKCS1::BEncipherment::ImportPublicKey(
	CAPI::CNG::BProviderHandle^ hProvider, IPublicKey^ publicKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = Microsoft::RSA::Encoding::GetPublicKeyBlob((ANSI::RSA::IPublicKey^)publicKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, BCRYPT_RSAPUBLIC_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

