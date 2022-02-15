#include "..\stdafx.h"
#include "X942KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// ƒополнительные определени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// јлгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::X942::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD)
{$
	// извлечь параметры алгоритмов
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)Parameters; 

	// получить параметры генерации
	array<BYTE>^ P = Math::Convert::FromBigInteger(parameters->P, Endian); 
	array<BYTE>^ Q = Math::Convert::FromBigInteger(parameters->Q, Endian); 
	array<BYTE>^ G = Math::Convert::FromBigInteger(parameters->G, Endian); 

	// указать параметры в специальном формате
	pin_ptr<BYTE> ptrP = &P[0]; CRYPT_INTEGER_BLOB blobP = { (UINT)P->Length, ptrP }; 
	pin_ptr<BYTE> ptrQ = &Q[0]; CRYPT_INTEGER_BLOB blobQ = { (UINT)Q->Length, ptrQ }; 
	pin_ptr<BYTE> ptrG = &G[0]; CRYPT_INTEGER_BLOB blobG = { (UINT)G->Length, ptrG }; 

	// указать идентификатор алгоритма
	ALG_ID algID = (container != nullptr) ? CALG_DH_SF : CALG_DH_EPHEM; 

	// указать параметры генерации
	DWORD flags = ((blobP.cbData * 8) << 16) | CRYPT_PREGEN | CRYPT_EXPORTABLE; 

	// создать пару ключей
	Using<CAPI::CSP::KeyHandle^> hKeyPair(Generate(container, algID, flags)); 

	// установить параметры генерации
	hKeyPair.Get()->SetParam(KP_P, IntPtr(&blobP), 0); 
	hKeyPair.Get()->SetParam(KP_Q, IntPtr(&blobQ), 0); 
	hKeyPair.Get()->SetParam(KP_G, IntPtr(&blobG), 0); 

	// сгенерировать параметры 
	hKeyPair.Get()->SetParam(KP_X, IntPtr::Zero, 0); return hKeyPair.Detach();
}

