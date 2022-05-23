#include "..\..\..\stdafx.h"
#include "..\..\..\RSA\RSAEncoding.h"
#include "RSAPKCS1BDecipherment.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAPKCS1BDecipherment.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� ���������� ������ RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::Keyx::RSA::PKCS1::BDecipherment::ImportPrivateKey(
	CAPI::CNG::BProviderHandle^ hProvider, IPrivateKey^ privateKey) 
{$
	// ���������� ��������� ������ ������
	DWORD cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_RSAKEY_BLOB* pbBlob = (BCRYPT_RSAKEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = Microsoft::RSA::Encoding::GetPrivateKeyBlob((ANSI::RSA::IPrivateKey^)privateKey, pbBlob, cbBlob); 

	// ������������� �������� ����
	return hProvider->ImportKeyPair(nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, IntPtr(pbBlob), cbBlob, 0); 
}

