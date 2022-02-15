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
void Aladdin::CAPI::CSP::Mac::Init(ISecretKey^ key) 
{$ 
    // освободить выделенные ресурсы
    hHash.Close(); hKey.Close(); 

	// при наличии родного ключа
	if (dynamic_cast<SecretKey^>(key) != nullptr)
	{
		// извлечь описатель ключа
		hKey.Attach(Handle::AddRef(((SecretKey^)key)->Handle)); 
	}
    // при наличии значения ключа
    else if (key->Value != nullptr)
    {
		// получить тип ключа
		SecretKeyType^ keyType = provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // создать ключ для алгоритма
        hKey.Attach(keyType->ConstructKey(hContext, key->Value, flags));  
    }
    // при ошибке выбросить исключение
    else throw gcnew InvalidKeyException();  
    try { 
		// установить параметры ключа
		SetParameters(hKey.Get()); 
		
		// создать алгоритм хэширования
		hHash.Attach(Construct(hContext, hKey.Get())); 
	}
	// при ошибке удалить ключ
	catch(Exception^) { hKey.Close(); throw; }
}

void Aladdin::CAPI::CSP::Mac::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// захэшировать данные
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CSP::Mac::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// получить имитовставку
	array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0); 
			
	// скопировать имитовставку
	Array::Copy(mac, 0, buffer, bufferOff, mac->Length); 
	
	// вернуть размер имитовставки
	hHash.Close(); hKey.Close(); return mac->Length;
}
