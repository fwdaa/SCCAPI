#include "..\..\stdafx.h"
#include "..\..\Container.h"
#include "RSASignHash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSASignHash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������� ���-�������� RSA
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::Tumar::Sign::RSA::SignHash::Sign(
	IPrivateKey^ privateKey, IRand^ rand, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ������������� ��� �����
	CAPI::CSP::PrivateKey^ cspPrivateKey = (CAPI::CSP::PrivateKey^)privateKey; 

	// ��������� ������� ����������
	if (privateKey->Container == nullptr) throw gcnew InvalidKeyException();
	
	// �������� ��������� �����
	Container^ container = (Container^)privateKey->Container; 

	// �������������� �������� ����
	Container::SetActivePrivateKey active(container, cspPrivateKey); 

	// ������� ������� �������
	return Microsoft::Sign::RSA::SignHash::Sign(privateKey, rand, hashAlgorithm, hash); 
}
