#include "..\..\stdafx.h"
#include "GOST34310TransportKeyWrap.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310TransportKeyWrap.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::TransportKeyData^ 
Aladdin::CAPI::KZ::CSP::Tumar::Keyx::GOST34310::TransportKeyWrap::Wrap(
	ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
	IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK)
{$
	// ����������� ����
	TransportKeyData^ transportData = CAPI::CSP::TransportKeyWrap::Wrap(
		algorithmParameters, publicKey, rand, CEK
	); 
	// ������� ��������� ������
    array<BYTE>^ blobHeader = gcnew array<BYTE> { 
		0x01, 0x02, 0x00, 0x00, // SIMPLEBLOB
        0x20, 0x66, 0x04, 0x00, // CALG_GOST-OFB
        0x20, 0xA0, 0x00, 0x00, // CALG_ELGAM
	}; 
	// �������� ��������� ������
	array<BYTE>^ encryptedKey = Arrays::Concat(blobHeader, transportData->EncryptedKey); 

	// ������� ������ � ����������
	return gcnew TransportKeyData(transportData->Algorithm, encryptedKey); 
}

