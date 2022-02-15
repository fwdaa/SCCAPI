#include "stdafx.h" 
#include "Keyx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Keyx.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� �������� ����������
///////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::BEncipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// ������� ������ ��������� �����
	Using<BKeyHandle^> hPublicKey(ImportPublicKey(hProvider.Get(), publicKey));
 
	// ����������� ������
	return Encrypt(hPublicKey.Get(), data);  
}

array<BYTE>^ Aladdin::CAPI::CNG::BDecipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// ������������� ������ ����
	Using<BKeyHandle^> hPrivateKey(ImportPrivateKey(hProvider.Get(), privateKey));

	// ������������ ������
	return Decrypt(hPrivateKey.Get(), data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NEncipherment::Encrypt( 
	IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data)
{$
	// ������� ������ ��������� �����
	Using<NKeyHandle^> hPublicKey(provider->ImportPublicKey(AT_KEYEXCHANGE, publicKey));
 
	// ����������� ������
	return Encrypt(hPublicKey.Get(), data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NDecipherment::Decrypt(
	IPrivateKey^ privateKey, array<BYTE>^ data)
{$
	// �������� ��������� ������� �����
	NKeyHandle^ hPrivateKey = ((NPrivateKey^)privateKey)->Handle;

	// ������������ ������
	return Decrypt(privateKey->Scope, hPrivateKey, data); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NDecipherment::Decrypt(SecurityObject^ scope, 
	NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ��� ����� ����������
	if (dynamic_cast<Container^>(scope) != nullptr) 
	{
		// ������������� ��� ����������
		Container^ container = (Container^)scope; 

		// ������������ ������
		return container->Decrypt(hPrivateKey, padding, data, flags); 
	}
	// ������������ ������
	else return hPrivateKey->Decrypt(padding, data, flags);
}

