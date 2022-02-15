#include "stdafx.h"
#include "Hash.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Hash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Hash::Init() 
{$ 
	// инициализировать алгоритм
	hHash.Close(); hHash.Attach(hProvider.Get()->CreateHash(nullptr, 0)); 
}

void Aladdin::CAPI::CNG::Hash::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CNG::Hash::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// получить хэш-значение
	array<BYTE>^ hash = hHash.Get()->FinishHash(0);  
			
	// скопировать хэш-значение
	Array::Copy(hash, 0, buffer, bufferOff, hash->Length); 

    // освободить выделенные ресурсы
    hHash.Close(); return hash->Length;
}
