#include "..\stdafx.h"
#include "DSSProvider.h"
#include "..\SecretKeyType.h"
#include "..\X942\X942PrivateKey.h"
#include "..\X942\X942KeyPairGenerator.h"
#include "..\X957\X957PrivateKey.h"
#include "..\X957\X957KeyPairGenerator.h"
#include "..\Sign\DSA\DSASignHash.h"
#include "..\Sign\DSA\DSAVerifyHash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DSSProvider.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер DSS
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::SecretKeyType^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::GetSecretKeyType(
	SecretKeyFactory^ keyFactory, DWORD keySize)
{$
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::DES^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_DES); 
	}
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::RC4^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_RC4);
	}
	// в зависимости от типа алгоритма
	if (dynamic_cast<Keys::RC2^>(keyFactory) != nullptr) 
	{
		// указать идентификатор алгоритма
		return gcnew SecretKeyType(CALG_RC2);
	}
	// указать идентификатор алгоритма по умолчанию
	return gcnew SecretKeyType(CALG_RC2); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::ImportKeyPair(
	CAPI::CSP::Container^ container, DWORD keyType, DWORD keyFlags, 
	IPublicKey^ publicKey, IPrivateKey^ privateKey)
{$
	// в зависимости от значения типа ключа
	if (keyType == AT_SIGNATURE)
	{
		// получить параметры алгоритма
		ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)publicKey->Parameters; 

		// преобразовать тип ключей
		ANSI::X957::IPublicKey ^ dsaPublicKey  = (ANSI::X957::IPublicKey ^)publicKey; 
		ANSI::X957::IPrivateKey^ dsaPrivateKey = (ANSI::X957::IPrivateKey^)privateKey; 

		// извлечь параметры
		Math::BigInteger^ P = parameters->P; Math::BigInteger^ Q = parameters->Q;

		// закодировать отдельные параметры
		array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters   ->P, Endian);
		array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters   ->Q, Endian);
		array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters   ->G, Endian);
		array<BYTE>^ arrY = Math::Convert::FromBigInteger(dsaPublicKey ->Y, Endian);
		array<BYTE>^ arrX = Math::Convert::FromBigInteger(dsaPrivateKey->X, Endian);

		// указать фиксированный заголовок
		PUBLICKEYSTRUC header = { PRIVATEKEYBLOB, 3, 0, CALG_DSS_SIGN }; DSSSEED seed = { 0xFFFFFFFF, {0} }; 

		// указать заголовок DSS
		DSSPRIVKEY_VER3 headerDSS = { 0x34535344, (UINT)P->BitLength, (UINT)Q->BitLength, 0, (UINT)Q->BitLength, seed }; 

		// указать смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPRIVKEY_VER3); 

		// определить размер буфера
		DWORD cbBlob = offset + 3 * ((headerDSS.bitlenP + 7) / 8) + 2 * ((headerDSS.bitlenQ + 7) / 8); 

		// выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// выполнить преобразование типа
		PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 
		
		// скопировать фиксированный заголовок и заголовок DSS
		*pBlob = header; *(DSSPRIVKEY_VER3*)(pBlob + 1) = headerDSS; 

		// скопировать параметры P, Q, G, Y, X
		Array::Copy(arrP, 0, blob, offset, arrP->Length); offset += (headerDSS.bitlenP + 7) / 8; 
		Array::Copy(arrQ, 0, blob, offset, arrQ->Length); offset += (headerDSS.bitlenQ + 7) / 8; 
		Array::Copy(arrG, 0, blob, offset, arrG->Length); offset += (headerDSS.bitlenP + 7) / 8; 
		Array::Copy(arrY, 0, blob, offset, arrY->Length); offset += (headerDSS.bitlenP + 7) / 8;
		Array::Copy(arrX, 0, blob, offset, arrX->Length); offset += (headerDSS.bitlenQ + 7) / 8;

		// импортировать пару ключей
		return ImportKey(container, nullptr, IntPtr(ptrBlob), blob->Length, keyFlags); 
	}
	// в зависимости от значения типа ключа
	else if (keyType == AT_KEYEXCHANGE) { keyFlags |= CRYPT_EXPORTABLE; 

		// получить параметры алгоритма
		ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)publicKey->Parameters; 

		// преобразовать тип ключей
		ANSI::X942::IPublicKey ^ dhPublicKey  = (ANSI::X942::IPublicKey ^)publicKey; 
		ANSI::X942::IPrivateKey^ dhPrivateKey = (ANSI::X942::IPrivateKey^)privateKey; 

		// извлечь параметры
		Math::BigInteger^ P = parameters->P; Math::BigInteger^ Q = parameters->Q;

		// закодировать отдельные параметры
		array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters  ->P, Endian);
		array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters  ->Q, Endian);
		array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters  ->G, Endian);
		array<BYTE>^ arrY = Math::Convert::FromBigInteger(dhPublicKey ->Y, Endian);
		array<BYTE>^ arrX = Math::Convert::FromBigInteger(dhPrivateKey->X, Endian);

        // выполнить нормализацию
        if (arrP[arrP->Length - 1] == 0) Array::Resize(arrP, arrP->Length - 1); 
        if (arrQ[arrQ->Length - 1] == 0) Array::Resize(arrQ, arrQ->Length - 1); 
        if (arrG[arrG->Length - 1] == 0) Array::Resize(arrG, arrG->Length - 1); 
        if (arrY[arrY->Length - 1] == 0) Array::Resize(arrY, arrY->Length - 1); 
        if (arrX[arrX->Length - 1] == 0) Array::Resize(arrX, arrX->Length - 1); 

		// указать фиксированный заголовок
		PUBLICKEYSTRUC header = { PRIVATEKEYBLOB, 3, 0, CALG_DH_SF }; DSSSEED seed = { 0xFFFFFFFF, {0} };

		// указать заголовок DH
		DHPRIVKEY_VER3 headerDH = { 0x34484400, (UINT)P->BitLength, (UINT)Q->BitLength, 0, (UINT)Q->BitLength, seed }; 

		// указать смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DHPRIVKEY_VER3); 

		// определить размер буфера
		DWORD cbBlob = offset + 3 * ((headerDH.bitlenP + 7) / 8) + 2 * ((headerDH.bitlenQ + 7) / 8); 

		// выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// выполнить преобразование типа
		PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 
		
		// скопировать фиксированный заголовок и заголовок DH
		*pBlob = header; *(DHPRIVKEY_VER3*)(pBlob + 1) = headerDH; 

		// скопировать параметры P, Q, G, Y
		Array::Copy(arrP, 0, blob, offset, arrP->Length); offset += (headerDH.bitlenP + 7) / 8; 
		Array::Copy(arrQ, 0, blob, offset, arrQ->Length); offset += (headerDH.bitlenQ + 7) / 8; 
		Array::Copy(arrG, 0, blob, offset, arrG->Length); offset += (headerDH.bitlenP + 7) / 8; 
		Array::Copy(arrY, 0, blob, offset, arrY->Length); offset += (headerDH.bitlenP + 7) / 8; 
		Array::Copy(arrX, 0, blob, offset, arrX->Length); offset += (headerDH.bitlenQ + 7) / 8; 

		// импортировать пару ключей
		return ImportKey(container, nullptr, IntPtr(ptrBlob), blob->Length, keyFlags); 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::ImportPublicKey(
	CAPI::CSP::ContextHandle^ hContext, IPublicKey^ publicKey, DWORD keyType)
{$
	// преобразовать идентификатор ключа
	ALG_ID algID = ConvertKeyOID(publicKey->KeyOID, keyType); 

	// в зависимости от значения типа ключа
	if (algID == CALG_DSS_SIGN)
	{
		// получить параметры алгоритма
		ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)publicKey->Parameters; 

		// преобразовать тип ключа
		ANSI::X957::IPublicKey ^ dsaPublicKey  = (ANSI::X957::IPublicKey ^)publicKey; 

		// извлечь параметры
		Math::BigInteger^ P = parameters->P; Math::BigInteger^ Q = parameters->Q;

		// закодировать отдельные параметры
		array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters   ->P, Endian);
		array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters   ->Q, Endian);
		array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters   ->G, Endian);
		array<BYTE>^ arrY = Math::Convert::FromBigInteger(dsaPublicKey ->Y, Endian);

		// указать фиксированный заголовок
		PUBLICKEYSTRUC header = { PUBLICKEYBLOB, 3, 0, CALG_DSS_SIGN }; DSSSEED seed = { 0xFFFFFFFF, {0} }; 

		// указать заголовок DSS
		DSSPUBKEY_VER3 headerDSS = { 0x33535344, (UINT)P->BitLength, (UINT)Q->BitLength, 0, seed }; 

		// указать смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY_VER3); 

		// определить размер буфера
		DWORD cbBlob = offset + 3 * ((headerDSS.bitlenP + 7) / 8) + ((headerDSS.bitlenQ + 7) / 8); 

		// выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
		
		// выполнить преобразование типа
		PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

		// скопировать фиксированный заголовок и заголовок DSS
		*pBlob = header; *(DSSPUBKEY_VER3*)(pBlob + 1) = headerDSS; 

		// скопировать параметры P, Q, G, Y, X
		Array::Copy(arrP, 0, blob, offset, arrP->Length); offset += (headerDSS.bitlenP + 7) / 8; 
		Array::Copy(arrQ, 0, blob, offset, arrQ->Length); offset += (headerDSS.bitlenQ + 7) / 8; 
		Array::Copy(arrG, 0, blob, offset, arrG->Length); offset += (headerDSS.bitlenP + 7) / 8; 
		Array::Copy(arrY, 0, blob, offset, arrY->Length); offset += (headerDSS.bitlenP + 7) / 8;

		// импортировать открытый ключ
		return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
	}
	// в зависимости от значения типа ключа
	else if (algID == CALG_DH_SF) 
	{ 
		// получить параметры алгоритма
		ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)publicKey->Parameters; 

		// преобразовать тип ключа
		ANSI::X942::IPublicKey^ dhPublicKey = (ANSI::X942::IPublicKey ^)publicKey; 

		// извлечь параметры
		Math::BigInteger^ P = parameters->P; Math::BigInteger^ Q = parameters->Q;

		// закодировать отдельные параметры
		array<BYTE>^ arrP = Math::Convert::FromBigInteger(parameters  ->P, Endian);
		array<BYTE>^ arrQ = Math::Convert::FromBigInteger(parameters  ->Q, Endian);
		array<BYTE>^ arrG = Math::Convert::FromBigInteger(parameters  ->G, Endian);
		array<BYTE>^ arrY = Math::Convert::FromBigInteger(dhPublicKey ->Y, Endian);

        // выполнить нормализацию
        if (arrP[arrP->Length - 1] == 0) Array::Resize(arrP, arrP->Length - 1); 
        if (arrQ[arrQ->Length - 1] == 0) Array::Resize(arrQ, arrQ->Length - 1); 
        if (arrG[arrG->Length - 1] == 0) Array::Resize(arrG, arrG->Length - 1); 
        if (arrY[arrY->Length - 1] == 0) Array::Resize(arrY, arrY->Length - 1); 

		// указать фиксированный заголовок
		PUBLICKEYSTRUC header = { PUBLICKEYBLOB, 3, 0, CALG_DH_SF }; DSSSEED seed = { 0xFFFFFFFF, {0} };

		// указать заголовок DH
		DHPUBKEY_VER3 headerDH = { 0x33484400, (UINT)P->BitLength, (UINT)Q->BitLength, 0, seed }; 

		// указать смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3); 

		// определить размер буфера
		DWORD cbBlob = offset + 3 * ((headerDH.bitlenP + 7) / 8) + ((headerDH.bitlenQ + 7) / 8); 

		// выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0];

		// выполнить преобразование типа
		PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

		// скопировать фиксированный заголовок и заголовок DH
		*pBlob = header; *(DHPUBKEY_VER3*)(pBlob + 1) = headerDH; 

		// скопировать параметры P, Q, G, Y
		Array::Copy(arrP, 0, blob, offset, arrP->Length); offset += (headerDH.bitlenP + 7) / 8; 
		Array::Copy(arrQ, 0, blob, offset, arrQ->Length); offset += (headerDH.bitlenQ + 7) / 8; 
		Array::Copy(arrG, 0, blob, offset, arrG->Length); offset += (headerDH.bitlenP + 7) / 8; 
		Array::Copy(arrY, 0, blob, offset, arrY->Length); offset += (headerDH.bitlenP + 7) / 8; 

		// импортировать открытый ключ
		return hContext->ImportKey(nullptr, IntPtr(ptrBlob), blob->Length, 0); 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
}

Aladdin::ASN1::ISO::PKIX::SubjectPublicKeyInfo^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::ExportPublicKey(
	CAPI::CSP::KeyHandle^ hPublicKey)
{$
	// определить размер буфера
	DWORD cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, CRYPT_BLOB_VER3, IntPtr::Zero, 0);

	// выделить память для структуры экспорта
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)(PBYTE)ptrBlob; 

	// экспортировать открытый ключ
	cbBlob = hPublicKey->Export(nullptr, PUBLICKEYBLOB, CRYPT_BLOB_VER3, IntPtr(pBlob), cbBlob);

	// указать идентификатор ключа
	String^ keyOID = ConvertKeyOID(pBlob->aiKeyAlg); 

	// в зависимости от типа параметров
	if (pBlob->aiKeyAlg == CALG_DSS_SIGN) 
	{
		// преобразовать тип указателя
		DSSPUBKEY_VER3* pInfo = (DSSPUBKEY_VER3*)(pBlob + 1); 

		// определить смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY_VER3); 

		// выделить память для параметров
		array<BYTE>^ arrP = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
		array<BYTE>^ arrQ = gcnew array<BYTE>((pInfo->bitlenQ + 7) / 8); 
		array<BYTE>^ arrG = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
		array<BYTE>^ arrY = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 

		// прочитать параметры
		Array::Copy(blob, offset, arrP, 0, arrP->Length); offset += arrP->Length; 
		Array::Copy(blob, offset, arrQ, 0, arrQ->Length); offset += arrQ->Length; 
		Array::Copy(blob, offset, arrG, 0, arrG->Length); offset += arrG->Length; 
		Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

		// раскодировать параметры
		Math::BigInteger^ P = Math::Convert::ToBigInteger(arrP, Endian); 
		Math::BigInteger^ Q = Math::Convert::ToBigInteger(arrQ, Endian);
		Math::BigInteger^ G = Math::Convert::ToBigInteger(arrG, Endian);
		Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, Endian);

		// закодировать параметры
		ASN1::IEncodable^ encodedParams = gcnew ASN1::ANSI::X957::DssParms(
			gcnew ASN1::Integer(P), gcnew ASN1::Integer(Q), gcnew ASN1::Integer(G)
		); 
		// закодировать параметры алгоритма
		ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
        ); 
		// закодировать значение ключа
		ASN1::BitString^ encodedKey = gcnew ASN1::BitString(ASN1::Integer(Y).Encoded); 

		// вернуть закодированный ключ и параметры
		return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
	}
	// в зависимости от типа параметров
	if (pBlob->aiKeyAlg == CALG_DH_SF || pBlob->aiKeyAlg == CALG_DH_EPHEM) 
	{
		// преобразовать тип указателя
		DHPUBKEY_VER3* pInfo = (DHPUBKEY_VER3*)(pBlob + 1); 

		// определить смещение параметров
		DWORD offset = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3); 

		// выделить память для параметров
		array<BYTE>^ arrP = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
		array<BYTE>^ arrQ = gcnew array<BYTE>((pInfo->bitlenQ + 7) / 8); 
		array<BYTE>^ arrG = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 
		array<BYTE>^ arrY = gcnew array<BYTE>((pInfo->bitlenP + 7) / 8); 

		// прочитать параметры
		Array::Copy(blob, offset, arrP, 0, arrP->Length); offset += arrP->Length; 
		Array::Copy(blob, offset, arrQ, 0, arrQ->Length); offset += arrQ->Length; 
		Array::Copy(blob, offset, arrG, 0, arrG->Length); offset += arrG->Length; 
		Array::Copy(blob, offset, arrY, 0, arrY->Length); offset += arrY->Length; 

		// раскодировать параметры
		Math::BigInteger^ P = Math::Convert::ToBigInteger(arrP, Endian); 
		Math::BigInteger^ Q = Math::Convert::ToBigInteger(arrQ, Endian);
		Math::BigInteger^ G = Math::Convert::ToBigInteger(arrG, Endian);
		Math::BigInteger^ Y = Math::Convert::ToBigInteger(arrY, Endian);

		// закодировать параметры
		ASN1::IEncodable^ encodedParams = gcnew ASN1::ANSI::X942::DomainParameters(
			gcnew ASN1::Integer(P), gcnew ASN1::Integer(G), gcnew ASN1::Integer(Q), nullptr, nullptr
		); 
		// закодировать параметры алгоритма
		ASN1::ISO::AlgorithmIdentifier^ encodedAlgorithm = gcnew ASN1::ISO::AlgorithmIdentifier(
            gcnew ASN1::ObjectIdentifier(keyOID), encodedParams
        ); 
		// закодировать значение ключа
		ASN1::BitString^ encodedKey = gcnew ASN1::BitString(ASN1::Integer(Y).Encoded); 

		// вернуть закодированный ключ и параметры
		return gcnew ASN1::ISO::PKIX::SubjectPublicKeyInfo(encodedAlgorithm, encodedKey); 
	}
    // при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}
		
Aladdin::CAPI::CSP::PrivateKey^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::GetPrivateKey(
	SecurityObject^ scope, IPublicKey^ publicKey, 
	CAPI::CSP::KeyHandle^ hKeyPair, DWORD keyType)
{$
	// проверить тип параметров
	if (dynamic_cast<CAPI::ANSI::X957::IPublicKey^>(publicKey) != nullptr) 
    {
        // преобразовать тип параметров
        CAPI::ANSI::X957::IPublicKey^ dsaPublicKey = (CAPI::ANSI::X957::IPublicKey^)publicKey; 

		// указать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// создать личный ключ
		return gcnew X957::PrivateKey(this, scope, dsaPublicKey, hKeyPair, keyID); 
    }
	// проверить тип параметров
	if (dynamic_cast<CAPI::ANSI::X942::IPublicKey^>(publicKey) != nullptr) 
	{
        // преобразовать тип параметров
        CAPI::ANSI::X942::IPublicKey^ dhPublicKey = (CAPI::ANSI::X942::IPublicKey^)publicKey; 

		// указать идентификатор ключа
		array<BYTE>^ keyID = gcnew array<BYTE> { (BYTE)keyType }; 

		// создать личный ключ
		return gcnew X942::PrivateKey(this, scope, dhPublicKey, hKeyPair, keyID); 
	}
	// вызвать базовую функцию
	return CAPI::CSP::Provider::GetPrivateKey(scope, publicKey, hKeyPair, keyType); 
}

Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::CreateGenerator(
	Factory^ factory, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// проверить тип параметров
	if (keyOID == ASN1::ANSI::OID::x957_dsa) 
	{
        // преобразовать тип параметров
        CAPI::ANSI::X957::IParameters^ dsaParameters = (CAPI::ANSI::X957::IParameters^)parameters; 

		// создать алгоритм генерации ключей
		return gcnew X957::KeyPairGenerator(this, scope, rand, dsaParameters);
	}
	// проверить тип параметров
	if (keyOID == ASN1::ANSI::OID::x942_dh_public_key) 
	{
        // преобразовать тип параметров
        CAPI::ANSI::X942::IParameters^ dhParameters = (CAPI::ANSI::X942::IParameters^)parameters; 

		// создать алгоритм генерации ключей
		return gcnew X942::KeyPairGenerator(this, scope, rand, dhParameters);
	}
	return nullptr; 
}

Aladdin::CAPI::IAlgorithm^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::DSS::Provider::CreateAlgorithm(
	Factory^ factory, SecurityStore^ scope, String^ oid, 
	ASN1::IEncodable^ parameters, System::Type^ type)
{$
	for (int i = 0; i < 1; i++)
	{
		// для алгоритмов подписи
		if (type == SignHash::typeid)
		{
			if (oid == ASN1::ANSI::OID::x957_dsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::DSA::SignHash(this); 
			}
		}
		// для алгоритмов подписи
		else if (type == VerifyHash::typeid)
		{
			if (oid == ASN1::ANSI::OID::x957_dsa) 
			{
				// создать алгоритм подписи хэш-значения
				return gcnew Sign::DSA::VerifyHash(this); 
			}
		}
		// для алгоритмов согласования общего ключа
		else if (type == IKeyAgreement::typeid)
		{
			if (oid == ASN1::ISO::PKCS::PKCS9::OID::smime_ssdh || 
				oid == ASN1::ISO::PKCS::PKCS9::OID::smime_esdh)
			{
    			// раскодировать параметры
				ASN1::ISO::AlgorithmIdentifier^ wrapParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(parameters); 

				// указать параметры алгоритма хэширования
				ASN1::ISO::AlgorithmIdentifier^ hashParameters = 
					gcnew ASN1::ISO::AlgorithmIdentifier(
						gcnew ASN1::ObjectIdentifier(ASN1::ANSI::OID::ssig_sha1), 
						ASN1::Null::Instance
				); 
				// получить алгоритм хэширования
				Using<CAPI::Hash^> hashAlgorithm(
					factory->CreateAlgorithm<CAPI::Hash^>(scope, hashParameters)
				); 
				// проверить поддержку алгоритма
				if (hashAlgorithm.Get() == nullptr) break; 

				// получить алгоритм согласования общего ключа
				return gcnew ANSI::Keyx::DH::KeyAgreement(
					hashAlgorithm.Get(), wrapParameters->Algorithm->Value
				);  
			}
		}
	}
	// вызвать базовую функцию
	return Microsoft::Provider::CreateAlgorithm(factory, scope, oid, parameters, type); 
}

