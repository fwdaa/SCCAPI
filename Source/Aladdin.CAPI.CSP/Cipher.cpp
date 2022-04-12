#include "stdafx.h"
#include "Mac.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Cipher.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Encryption::Init() 
{$ 
	hKey.Close();
			
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
		SecretKeyType^ keyType = cipher->Provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // создать ключ для алгоритма
        hKey.Attach(keyType->ConstructKey(cipher->Context, key->Value, 0));  
    }
    // при ошибке выбросить исключение
    else throw gcnew InvalidKeyException();  

    // установить параметры алгоритма
    try { cipher->SetParameters(hKey.Get(), Padding); }

    // обработать возможное исключение
    catch(Exception^) { hKey.Close(); throw; }
}

int Aladdin::CAPI::CSP::Encryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// проверить необходимость действий
	int blockSize = BlockSize; if (dataLen == 0) return 0; 

	// проверить кратность размеру блока
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();

	// зашифровать полные блоки кроме последнего
	hKey.Get()->Encrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); return dataLen; 
}

int Aladdin::CAPI::CSP::Encryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	int total = 0; 

	// при наличии данных
	if (dataLen > 0) { int blockSize = BlockSize; 

		// определить размер полных блоков кроме последнего
		int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

		// преобразовать полные блоки
		total = (cbBlocks > 0) ? Update(data, dataOff, cbBlocks, buf, bufOff) : 0; 

		// перейти на неполный блок
		dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += total; 
	}
	// указать способ обработки последнего блока
	DWORD final = (padding != PaddingMode::None); 

	// при наличии данных
	if (dataLen > 0 || final) 
	{
		// зашифровать последний неполный блок
		total += hKey.Get()->Encrypt(data, dataOff, dataLen, final, 0, buf, bufOff); 
	}
	// освободить выделенные ресурсы
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Decryption::Init() 
{$ 
	hKey.Close(); 

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
		SecretKeyType^ keyType = cipher->Provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // создать ключ для алгоритма
        hKey.Attach(keyType->ConstructKey(cipher->Context, key->Value, 0));  
    }
    // при ошибке выбросить исключение
    else throw gcnew InvalidKeyException();  

    // установить параметры алгоритма
    try { cipher->SetParameters(hKey.Get(), Padding); }

    // обработать возможное исключение
    catch(Exception^) { hKey.Close(); throw; }
}

int Aladdin::CAPI::CSP::Decryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// проверить наличие данных
	if (dataLen == 0) return 0; int blockSize = BlockSize; 
	
	// проверить кратность размеру блока
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();
	
	// при отсутствии дополнения последнего блока
	if (padding != PaddingMode::PKCS5)
	{
		// расшифровать данные
		return hKey.Get()->Decrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); 
	}
	// определить размер полных блоков кроме последнего
	int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

	// при наличии последнего блока
	if (lastBlock != nullptr) { array<BYTE>^ buffer = gcnew array<BYTE>(cbBlocks); 
	
		// скопировать данные для расшифрования
		Array::Copy(data, dataOff, buffer, 0, cbBlocks);
		
		// расшифровать последний блок
		hKey.Get()->Decrypt(lastBlock, 0, blockSize, FALSE, 0, buf, bufOff); bufOff += blockSize;  
			
		// сохранить последний блок
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

		// расшифровать полные блоки кроме последнего
		hKey.Get()->Decrypt(buffer, 0, cbBlocks, FALSE, 0, buf, bufOff); return dataLen;
	}
	else {
		// выделить память для последнего блока
		lastBlock = gcnew array<BYTE>(blockSize); 

		// расшифровать полные блоки кроме последнего
		hKey.Get()->Decrypt(data, dataOff, cbBlocks, FALSE, 0, buf, bufOff);

		// сохранить последний блок
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks;
	}
}

int Aladdin::CAPI::CSP::Decryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$ 
	int total = 0; 

	// при отсутствии дополнения последнего блока
	if (padding != PaddingMode::PKCS5)
	{
		// расшифровать данные
		if (dataLen > 0) total = hKey.Get()->Decrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); 
	}
	else {
		// проверить корректность данных
		if ((dataLen == 0 && lastBlock == nullptr) || (dataLen % BlockSize) != 0) 
		{
			// при ошибке выбросить исключение
			throw gcnew InvalidDataException();
		}
		// указать способ обработки последнего блока
		DWORD final = (padding != PaddingMode::None); 

		// расшифровать данные
		total = Update(data, dataOff, dataLen, buf, bufOff); bufOff += total; 

		// расшифровать последний блок
		total += hKey.Get()->Decrypt(lastBlock, 0, BlockSize, final, 0, buf, bufOff); 
	}
	// освободить выделенные ресурсы
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::Cipher::CreateEncryption(ISecretKey^ key)
{
	// вернуть алгоритм зашифрования данных
	return gcnew Encryption(this, PaddingMode::None, key); 
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::Cipher::CreateDecryption(ISecretKey^ key)
{
	// вернуть алгоритм расшифрования данных
	return gcnew Decryption(this, PaddingMode::None, key); 
}

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ Aladdin::CAPI::CSP::BlockCipher::CreateBlockMode(CipherMode^ mode)
{$
	// для режима ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// для режима CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// для режима CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// для режима OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
	{
		// создать режим алгоритма
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// Режим блочного алгоритма шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateEncryption(ISecretKey^ key, PaddingMode padding)
{$
	// указать режим дополнения
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// сохранить способ дополнения
	PaddingMode oldPadding = this->padding; this->padding = padding; 

	// указать режим дополнения
	BlockPadding^ paddingMode = GetPadding(); 

	// для неподдерживаемых режимов напрямую
	if (padding != PaddingMode::None && 
	    padding != PaddingMode::Zero &&
	    padding != PaddingMode::PKCS5)
	{
		// указать отсутствие дополнения в базовом преобразовании
		this->padding = PaddingMode::None; 
	}
	try {
		// получить режим зашифрования 
		Using<Transform^> encryption(CreateEncryption(key)); 
				
		// указать требуемое дополнение
		return paddingMode->CreateEncryption(encryption.Get(), Mode); 
	}
	// восстановить способ дополнения
	finally { this->padding = oldPadding; }
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateDecryption(ISecretKey^ key, PaddingMode padding)
{$
	// указать режим дополнения
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// сохранить способ дополнения
	PaddingMode oldPadding = this->padding; this->padding = padding; 

	// указать режим дополнения
	BlockPadding^ paddingMode = GetPadding(); 

	// для неподдерживаемых режимов напрямую
	if (padding != PaddingMode::None && 
	    padding != PaddingMode::Zero &&
	    padding != PaddingMode::PKCS5)
	{
		// указать отсутствие дополнения в базовом преобразовании
		this->padding = PaddingMode::None; 
	}
	try {
		// получить режим расшифрования 
		Using<Transform^> decryption(CreateDecryption(key)); 
				
		// указать требуемое дополнение
		return paddingMode->CreateDecryption(decryption.Get(), Mode); 
	}
	// восстановить способ дополнения
	finally { this->padding = oldPadding; }
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateEncryption(ISecretKey^ key)
{$
	// получить преобразовние зашифрования
	return gcnew Encryption(this, padding, key); 
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateDecryption(ISecretKey^ key)
{$
	// получить преобразовние расшифрования
	return gcnew Decryption(this, padding, key); 
}

Aladdin::CAPI::BlockPadding^ Aladdin::CAPI::CSP::BlockMode::GetPadding() 
{$
    // вернуть отсутствие дополнения
    if (padding == PaddingMode::None) return gcnew Pad::None();

    // вернуть дополнение нулями
    if (padding == PaddingMode::Zero) return gcnew Pad::Zero();

    // вернуть дополнение PKCS
    if (padding == PaddingMode::PKCS5) return gcnew Pad::PKCS5(); 

    // вернуть дополнение ISO
    if (padding == PaddingMode::ISO9797) return gcnew Pad::ISO9797(); 

    // для режима дополнения CTS
    if (padding == PaddingMode::CTS) return gcnew Pad::CTS(); 

    // при ошибке выбросить исключение
    throw gcnew NotSupportedException();
}

void Aladdin::CAPI::CSP::BlockMode::SetParameters(KeyHandle^ hKey, PaddingMode padding)
{$
	// установить параметры алгоритма
	blockCipher->SetParameters(hKey); switch (padding) 
	{
	case PaddingMode::Zero: 
	
		// закодировать режим дополнения
		hKey->SetLong(KP_PADDING, ZERO_PADDING,  0); break; 
	
	case PaddingMode::PKCS5: 

		// закодировать режим дополнения
		hKey->SetLong(KP_PADDING, PKCS5_PADDING,  0); break; 
	}
	// для режима ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_ECB, 0);  
	}
	// для режима CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_CBC, 0);  

		// при необходимости
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// установить величину сдвига
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// для режима CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::CFB^ parameters = (CipherMode::CFB^)mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_CFB, 0);  

		// при необходимости
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// установить величину сдвига
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// для режима OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
	{
		// получить параметры алгоритма
		CipherMode::OFB^ parameters = (CipherMode::OFB^)mode; 

		// установить режим шифрования
		hKey->SetLong(KP_MODE, CRYPT_MODE_OFB, 0);  

		// при необходимости
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// установить величину сдвига
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// установить синхропосылку
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}

