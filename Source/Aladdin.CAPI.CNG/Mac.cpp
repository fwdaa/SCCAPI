#include "stdafx.h"
#include "Mac.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Mac.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Mac::Init(ISecretKey^ key) 
{$ 
	// проверить тип ключа
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// инициализировать алгоритм
	hHash.Close(); hHash.Attach(hProvider.Get()->CreateHash(key->Value, 0)); 
}

void Aladdin::CAPI::CNG::Mac::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CNG::Mac::Finish(array<BYTE>^ buffer, int bufferOff)
{$
	// получить имитовставку
	array<BYTE>^ mac = hHash.Get()->FinishHash(0); 
			
	// скопировать имитовставку
	Array::Copy(mac, 0, buffer, bufferOff, mac->Length); 

    // освободить выделенные ресурсы
    hHash.Close(); return mac->Length; 
}
