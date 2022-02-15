#include "stdafx.h"
#include "Sign.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Sign.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::SignHash::Sign(IPrivateKey^ privateKey, 
	IRand^ rand, ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash)
{$
	// ��������� ������� ����������
	if (privateKey->Container == nullptr) throw gcnew InvalidOperationException();

	// �������� ��������� �����
	Container^ container = (Container^)(privateKey->Container);  

	// ������� �������� �����������
	Using<HashHandle^> hHash(CreateHash(container->Handle, hashAlgorithm));

	// ���������� ��� �����
	DWORD keyType = ((PrivateKey^)privateKey)->KeyType; 

	// ���������� ���-�������� 
	hHash.Get()->SetParam(HP_HASHVAL, hash, 0); 

	// ��������� ���-��������
	return container->SignHash(keyType, hHash.Get(), flags);
}

void Aladdin::CAPI::CSP::VerifyHash::Verify(IPublicKey^ publicKey, 
	ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature)
{$
	// ������������� �������� ���� �������
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, publicKey, AT_SIGNATURE
	)); 
	// ������� �������� �����������
	Using<HashHandle^> hHash(CreateHash(provider->Handle, hashAlgorithm));

	// ���������� ���-�������� 
	hHash.Get()->SetParam(HP_HASHVAL, hash, 0); 

	// ��������� ������� ������
	hPublicKey.Get()->VerifySignature(hHash.Get(), signature, flags); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������� ������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::SignData::Init(IPrivateKey^ privateKey, IRand^ rand)
{$
	hHash.Close(); 

	// ��������� ������� ����������
	if (privateKey->Container == nullptr) throw gcnew InvalidOperationException();

	// ������� ������� �������
	CAPI::SignData::Init(privateKey, rand); 

	// �������� ��������� �����
	Container^ container = (Container^)(privateKey->Container); 

	// ������� �������� �����������
	hHash.Attach(CreateHash(container->Handle, privateKey->Parameters));
}
				
void Aladdin::CAPI::CSP::SignData::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0);  
}

array<BYTE>^ Aladdin::CAPI::CSP::SignData::Finish(IRand^ rand)
{$
	// �������� ��������� �����
	Container^ container = (Container^)(PrivateKey->Container);  

	// ���������� ��� �����
	DWORD keyType = ((CSP::PrivateKey^)PrivateKey)->KeyType; 

	// ��������� ���-��������
	array<BYTE>^ signature = container->SignHash(keyType, hHash.Get(), flags);

	// ������� �������
	hHash.Close(); CAPI::SignData::Finish(rand); return signature; 
}

///////////////////////////////////////////////////////////////////////////
// �������� �������� ������� ������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::VerifyData::Init(IPublicKey^ publicKey, array<BYTE>^ signature)
{$
    // ������� ������� �������
	CAPI::VerifyData::Init(publicKey, signature); hHash.Close(); 

	// ������� �������� �����������
	hHash.Attach(CreateHash(provider->Handle, publicKey->Parameters));
}
				
void Aladdin::CAPI::CSP::VerifyData::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0);  
}

void Aladdin::CAPI::CSP::VerifyData::Finish()
{$
	// ������������� �������� ���� �������
	Using<KeyHandle^> hPublicKey(provider->ImportPublicKey(
		provider->Handle, PublicKey, AT_SIGNATURE
	)); 
	// ��������� ������� ������
	try { hPublicKey.Get()->VerifySignature(hHash.Get(), Signature, flags); }

	// ���������� ���������� �������
	finally { hHash.Close(); }
}
