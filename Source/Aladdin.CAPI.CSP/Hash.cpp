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
void Aladdin::CAPI::CSP::Hash::Init() 
{$ 
    // создать алгоритм хэширования
    hHash.Close(); hHash.Attach(Construct());
}

void Aladdin::CAPI::CSP::Hash::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CSP::Hash::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// получить хэш-значение
	array<BYTE>^ hash = hHash.Get()->GetParam(HP_HASHVAL, 0);  
			
	// скопировать хэш-значение
	Array::Copy(hash, 0, buffer, bufferOff, hash->Length); 
	
	// освободить выделенные ресурсы
	hHash.Close(); return hash->Length;
}
