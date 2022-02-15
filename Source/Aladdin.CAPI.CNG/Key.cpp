#include "stdafx.h"
#include "Key.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Key.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Личный ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NPrivateKey::NPrivateKey(NProvider^ provider, 
	SecurityObject^ scope, IPublicKey^ publicKey, NKeyHandle^ hPrivateKey) 
		: CAPI::PrivateKey(provider, scope, publicKey->KeyOID)
 { 
	// сохранить переданные параметры
	this->hPrivateKey = CNG::Handle::AddRef(hPrivateKey); 
	
	// сохранить параметры ключа
	this->parameters = publicKey->Parameters; 
} 

array<BYTE>^ Aladdin::CAPI::CNG::NPrivateKey::Export(
    NKeyHandle^ hExportKey, String^ blobType, DWORD flags)
{$
	// для ключа контейнера
	if (dynamic_cast<CAPI::CNG::Container^>(Container) != nullptr)
	{
		// получить контейнер ключа
		CAPI::CNG::Container^ container = (CAPI::CNG::Container^)Container; 

		// экспортировать ключ
		return container->ExportKey(hPrivateKey, hExportKey, blobType, flags); 
	}
	else {
		// определить требуемый размер буфера
		DWORD cbBlob = hPrivateKey->Export(hExportKey, blobType, flags, IntPtr::Zero, 0); 

		// выделить буфер требуемого размера
		array<BYTE>^ blob = gcnew array<BYTE>(cbBlob + 1); pin_ptr<BYTE> ptrBlob = &blob[0]; 

		// экспортировать ключ
		cbBlob = hPrivateKey->Export(hExportKey, blobType, flags, IntPtr(ptrBlob), cbBlob); 

		// изменить размер буфера
		Array::Resize(blob, cbBlob); return blob; 
	}
} 
