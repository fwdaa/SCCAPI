#include "stdafx.h"
#include "Key.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Key.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NPrivateKey::NPrivateKey(NProvider^ provider, 
	SecurityObject^ scope, IPublicKey^ publicKey, NKeyHandle^ hPrivateKey) 
		: CAPI::PrivateKey(provider, scope, publicKey->KeyOID)
 { 
	// ��������� ���������� ���������
	this->hPrivateKey = CNG::Handle::AddRef(hPrivateKey); 
	
	// ��������� ��������� �����
	this->parameters = publicKey->Parameters; 
} 

array<BYTE>^ Aladdin::CAPI::CNG::NPrivateKey::Export(
    NKeyHandle^ hExportKey, String^ blobType, DWORD flags)
{$
	// ��� ����� ����������
	if (dynamic_cast<CAPI::CNG::Container^>(Container) != nullptr)
	{
		// �������� ��������� �����
		CAPI::CNG::Container^ container = (CAPI::CNG::Container^)Container; 

		// �������������� ����
		return container->ExportKey(hPrivateKey, hExportKey, blobType, flags); 
	}
	else {
		// ���������� ��������� ������ ������
		DWORD cbBlob = hPrivateKey->Export(hExportKey, blobType, flags, IntPtr::Zero, 0); 

		// �������� ����� ���������� �������
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// �������������� ����
		cbBlob = hPrivateKey->Export(hExportKey, blobType, flags, IntPtr(ptrBlob), cbBlob); 

		// �������� ������ ������
		Array::Resize(blob, cbBlob); return blob; 
	}
} 
