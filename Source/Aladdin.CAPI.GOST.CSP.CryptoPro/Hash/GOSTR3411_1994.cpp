#include "..\stdafx.h"
#include "GOSTR3411_1994.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3411_1994.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ����������� ���� � 34.11-1994
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::GOST::CSP::CryptoPro::Hash::GOSTR3411_1994::Construct()
{$
	// ������� �������� �����������
	Using<CAPI::CSP::HashHandle^> hHash(CAPI::CSP::Hash::Construct()); 

	// ���������� ������������� ����������
	hHash.Get()->SetString(HP_OID, paramsOID, 0); return hHash.Detach();
}
