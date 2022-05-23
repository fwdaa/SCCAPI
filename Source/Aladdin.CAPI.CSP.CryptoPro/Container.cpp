#include "stdafx.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::Container::GenerateKeyPair(
	IntPtr hwnd, ALG_ID keyType, DWORD flags)
{$
    // при наличии графического режима вызвать базовую функцию
    if ((Mode & CRYPT_SILENT) == 0) return CAPI::CSP::Container::GenerateKeyPair(hwnd, keyType, flags); 

	// определить идентификатор параметра
	DWORD curveID = (keyType == AT_KEYEXCHANGE) ? PP_DHOID : PP_SIGNATUREOID; 
	
	// получить параметры эллиптических кривых
	String^ curveOID = Handle->GetString(curveID, 0); 

    // при наличии параметров хэширования
    String^ hashOID = nullptr; if (Provider->Type == PROV_GOST_2001_DH)
    {
        // получить параметры хэширования
        hashOID  = Handle->GetString(PP_HASHOID, 0); 
    }
	// открыть контейнер с графическим интерфейсом
	Synchronize(); DetachHandle(); AttachHandle(Mode & ~CRYPT_SILENT);
	try { 
		// указать параметры эллиптических кривых
		Handle->SetString(curveID, curveOID, 0); 

		// указать параметры хэширования
		if (hashOID != nullptr) Handle->SetString(PP_HASHOID, hashOID, 0); 

		// сгенерировать клюvч
		CAPI::CSP::Handle::Release(CAPI::CSP::Container::GenerateKeyPair(hwnd, keyType, flags)); 
	}
	// закрыть описатель
	finally { DetachHandle(); }
	
	// открыть контейнер и получить описатель ключа
	AttachHandle(Mode | CRYPT_SILENT); return Handle->GetUserKey(keyType);
} 

