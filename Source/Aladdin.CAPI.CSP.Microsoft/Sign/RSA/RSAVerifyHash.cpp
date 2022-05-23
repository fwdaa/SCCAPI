#include "..\..\stdafx.h"
#include "RSAVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAVerifyHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::Microsoft::Sign::RSA::VerifyHash::CreateHash(
	CAPI::CSP::ContextHandle^ hContext, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm)
{$
	// ���������� ������������� ��������� �����������
	String^ hashOID = hashAlgorithm->Algorithm->Value; ALG_ID algID = 0; if (false) {}

	// ���������� ������������� ��������� �����������
	else if (hashOID == ASN1::ANSI::OID::rsa_md2	  ) algID = CALG_MD2;
	else if (hashOID == ASN1::ANSI::OID::rsa_md4	  ) algID = CALG_MD4;
	else if (hashOID == ASN1::ANSI::OID::rsa_md5	  ) algID = CALG_MD5;
	else if (hashOID == ASN1::ANSI::OID::ssig_sha1	  ) algID = CALG_SHA1;
	else if (hashOID == ASN1::ANSI::OID::nist_sha2_256) algID = CALG_SHA_256;
	else if (hashOID == ASN1::ANSI::OID::nist_sha2_384) algID = CALG_SHA_384;
	else if (hashOID == ASN1::ANSI::OID::nist_sha2_512) algID = CALG_SHA_512;

	// ��� ������ ��������� ����������
	else throw gcnew NotSupportedException();

	// ������� �������� �����������
	return hContext->CreateHash(algID, nullptr, 0); 
}
