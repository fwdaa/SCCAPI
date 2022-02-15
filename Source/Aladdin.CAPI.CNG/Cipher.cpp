#include "stdafx.h" 
#include "Cipher.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Cipher.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Создать ключ для алгоритма шифрования
///////////////////////////////////////////////////////////////////////////////
static Aladdin::CAPI::CNG::BKeyHandle^ ConstructKey(
	Aladdin::CAPI::CNG::BProviderHandle^ hProvider, array<BYTE>^ key)
{$
	using namespace Aladdin::CAPI::CNG; 

	// указать фиксированный заголовок
	BCRYPT_KEY_DATA_BLOB_HEADER blobHeader = { 
		BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, (UINT)key->Length
	}; 
	// получить смещение ключа
	DWORD offsetKey = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER); DWORD cbBlob = offsetKey + key->Length;

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// выполнить преобразование типа
	BCRYPT_KEY_DATA_BLOB_HEADER* pHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)(PBYTE)ptrBlob; 

	// скопировать ключ
	*pHeader = blobHeader; Array::Copy(key, 0, blob, offsetKey, key->Length); 

	// импортировать ключ
	return hProvider->ImportKey(nullptr, BCRYPT_KEY_DATA_BLOB, IntPtr(pHeader), cbBlob, 0); 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Encryption::Init() 
{$ 
	hKey.Close();

    // установить параметры алгоритма
    array<BYTE>^ iv = cipher->SetParameters(hProvider.Get()); 

    // скопировать синхропосылку
    if (iv != nullptr) this->iv = (array<BYTE>^) iv->Clone(); 

	// создать ключ для алгоритма
	hKey.Attach(::ConstructKey(hProvider.Get(), key)); 
}

int Aladdin::CAPI::CNG::Encryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// проверить необходимость действий
	int blockSize = BlockSize; if (dataLen == 0) return 0; 

	// проверить кратность размеру блока
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();

	// зашифровать полные блоки кроме последнего
	hKey.Get()->Encrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); return dataLen; 
}

int Aladdin::CAPI::CNG::Encryption::Finish(
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
	DWORD padding = (Padding != PaddingMode::None) ? BCRYPT_BLOCK_PADDING : 0; 

	// зашифровать последний неполный блок
	total += hKey.Get()->Encrypt(iv, data, dataOff, dataLen, padding, buf, bufOff); 

	// освободить выделенные ресурсы
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Decryption::Init() 
{$ 
	hKey.Close();

    // установить параметры алгоритма
    array<BYTE>^ iv = cipher->SetParameters(hProvider.Get()); 

    // скопировать синхропосылку
    if (iv != nullptr) this->iv = (array<BYTE>^) iv->Clone(); 

	// создать ключ для алгоритма
	hKey.Attach(::ConstructKey(hProvider.Get(), key)); 
}

int Aladdin::CAPI::CNG::Decryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// проверить наличие данных
	if (dataLen == 0) return 0; int blockSize = BlockSize; 
	
	// проверить кратность размеру блока
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();
	
	// при отсутствии дополнения последнего блока
	if (Padding == PaddingMode::None) 
	{
		// расшифровать данные
		return hKey.Get()->Decrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); 
	}
	// определить размер полных блоков кроме последнего
	int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

	// при наличии последнего блока
	if (lastBlock != nullptr) 
	{
		// скопировать данные для зашифрования
		array<BYTE>^ buffer = gcnew array<BYTE>(cbBlocks); Array::Copy(data, dataOff, buffer, 0, cbBlocks);
		
		// расшифровать последний блок
		hKey.Get()->Decrypt(iv, lastBlock, 0, blockSize, 0, buf, bufOff); 
			
		// сохранить последний блок
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); bufOff += blockSize;  

		// расшифровать полные блоки кроме последнего
		hKey.Get()->Decrypt(iv, buffer, 0, cbBlocks, 0, buf, bufOff); return dataLen;
	}
	else {
		// выделить память для последнего блока
		lastBlock = gcnew array<BYTE>(blockSize); 

		// расшифровать полные блоки кроме последнего
		hKey.Get()->Decrypt(iv, data, dataOff, cbBlocks, 0, buf, bufOff);

		// сохранить последний блок
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks;
	}
}

int Aladdin::CAPI::CNG::Decryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$ 
	int total = 0; 

	// при отсутствии дополнения последнего блока
	if (Padding == PaddingMode::None) 
	{
		// расшифровать данные
		total = hKey.Get()->Decrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); 
	}
	else {
		// проверить корректность данных
		if ((dataLen == 0 && lastBlock == nullptr) || (dataLen % BlockSize) != 0) 
		{
			// при ошибке выбросить исключение
			throw gcnew InvalidDataException();
		}
		// расшифровать данные
		total = Update(data, dataOff, dataLen, buf, bufOff); bufOff += total; 

		// расшифровать последний блок
		total += hKey.Get()->Decrypt(
			iv, lastBlock, 0, BlockSize, BCRYPT_BLOCK_PADDING, buf, bufOff
		); 
	}
	// освободить выделенные ресурсы
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::Cipher::CreateEncryption(ISecretKey^ key)
{$
	// проверить тип ключа
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// вернуть алгоритм зашифрования данных
	return gcnew Encryption(this, PaddingMode::None, key->Value); 
}
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::Cipher::CreateDecryption(ISecretKey^ key)
{$
	// проверить тип ключа
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// вернуть алгоритм расшифрования данных
	return gcnew Decryption(this, PaddingMode::None, key->Value); 
}

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ Aladdin::CAPI::CNG::BlockCipher::CreateBlockMode(CipherMode^ mode)
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
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::BlockMode::CreateEncryption(
	ISecretKey^ key, PaddingMode padding)
{$
	// указать режим дополнения
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// сохранить способ дополнения
	PaddingMode oldPadding = this->padding; this->padding = padding; 
			
	// указать режим дополнения
	BlockPadding^ paddingMode = GetPadding(); 
	
	// для неподдерживаемых режимов напрямую
	if (padding != PaddingMode::None && padding != PaddingMode::PKCS5)
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

Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::BlockMode::CreateDecryption(
	ISecretKey^ key, PaddingMode padding)
{$
	// указать режим дополнения
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// сохранить способ дополнения
	PaddingMode oldPadding = this->padding; this->padding = padding; 
			
	// указать режим дополнения
	BlockPadding^ paddingMode = GetPadding(); 

	// для неподдерживаемых режимов напрямую
	if (padding != PaddingMode::None && padding != PaddingMode::PKCS5)
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

Aladdin::CAPI::BlockPadding^ Aladdin::CAPI::CNG::BlockMode::GetPadding() 
{$
    // вернуть отсутствие дополнения
    if (padding == PaddingMode::None) return gcnew Pad::None();

    // вернуть дополнение нулями
    if (padding == PaddingMode::Zero) return gcnew Pad::Zero();

    // вернуть дополнение PKCS
    if (padding == PaddingMode::PKCS5) return gcnew Pad::PKCS5(); 

    // вернуть дополнение ISO
    if (padding == PaddingMode::ISO) return gcnew Pad::ISO(); 

    // для режима дополнения CTS
    if (padding == PaddingMode::CTS) return gcnew Pad::CTS(); 

    // при ошибке выбросить исключение
    throw gcnew NotSupportedException();
}

array<BYTE>^ Aladdin::CAPI::CNG::BlockMode::SetParameters(BProviderHandle^ hProvider)
{$
	// установить параметры алгоритма
	blockCipher->SetParameters(hProvider); 

	// для режима ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// указать режим шифрования 
		String^ modeCNG = BCRYPT_CHAIN_MODE_ECB; 

		// установить режим шифрования
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 
		
		return nullptr; 
	}
	// для режима CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// преобразовать тип параметров
		CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

		// указать режим шифрования 
		String^ modeCNG = BCRYPT_CHAIN_MODE_CBC; 

		// установить режим шифрования
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 

		// при необходимости 
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// установить размер блока
			hProvider->SetLong(BCRYPT_BLOCK_LENGTH, parameters->BlockSize, 0); 
		}
		// вернуть синхропосылку
		return parameters->IV; 
	}
	// для режима CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// преобразовать тип параметров
		CipherMode::CFB^ parameters = (CipherMode::CFB^)mode; 

		// указать режим шифрования 
		String^ modeCNG = BCRYPT_CHAIN_MODE_CFB; 

		// установить режим шифрования
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 

		// при необходимости 
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// установить размер блока
			hProvider->SetLong(BCRYPT_BLOCK_LENGTH, parameters->BlockSize, 0); 
		}
		// вернуть синхропосылку
		return parameters->IV; 
	}
	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}
