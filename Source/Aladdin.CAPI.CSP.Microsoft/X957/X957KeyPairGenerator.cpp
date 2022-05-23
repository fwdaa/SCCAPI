#include "..\stdafx.h"
#include "X957KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::Microsoft::X957::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags)
{$
	// ������� ��������� ����������
	ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)Parameters; 

	// �������� ��������� ���������
	array<BYTE>^ P = Math::Convert::FromBigInteger(parameters->P, Endian); 
	array<BYTE>^ Q = Math::Convert::FromBigInteger(parameters->Q, Endian); 
	array<BYTE>^ G = Math::Convert::FromBigInteger(parameters->G, Endian); 

	// ������� ��������� � ����������� �������
	pin_ptr<BYTE> ptrP = &P[0]; CRYPT_INTEGER_BLOB blobP = { (UINT)P->Length, ptrP }; 
	pin_ptr<BYTE> ptrQ = &Q[0]; CRYPT_INTEGER_BLOB blobQ = { (UINT)Q->Length, ptrQ }; 
	pin_ptr<BYTE> ptrG = &G[0]; CRYPT_INTEGER_BLOB blobG = { (UINT)G->Length, ptrG }; 

	// ������� ��������� ���������
	DWORD flags = ((blobP.cbData * 8) << 16) | CRYPT_PREGEN | keyFlags; 

	// ������� ���� ������
	Using<CAPI::CSP::KeyHandle^> hKeyPair(Generate(container, AT_SIGNATURE, flags)); 

	// ���������� ��������� ���������
	hKeyPair.Get()->SetParam(KP_P, IntPtr(&blobP), 0); 
	hKeyPair.Get()->SetParam(KP_Q, IntPtr(&blobQ), 0); 
	hKeyPair.Get()->SetParam(KP_G, IntPtr(&blobG), 0); 

	// ������������� ��������� 
	hKeyPair.Get()->SetParam(KP_X, IntPtr::Zero, 0); return hKeyPair.Detach(); 
}

