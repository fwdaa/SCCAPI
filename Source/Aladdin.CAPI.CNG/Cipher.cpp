#include "stdafx.h" 
#include "Cipher.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Cipher.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ���� ��� ��������� ����������
///////////////////////////////////////////////////////////////////////////////
static Aladdin::CAPI::CNG::BKeyHandle^ ConstructKey(
	Aladdin::CAPI::CNG::BProviderHandle^ hProvider, array<BYTE>^ key)
{$
	using namespace Aladdin::CAPI::CNG; 

	// ������� ������������� ���������
	BCRYPT_KEY_DATA_BLOB_HEADER blobHeader = { 
		BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, (UINT)key->Length
	}; 
	// �������� �������� �����
	DWORD offsetKey = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER); DWORD cbBlob = offsetKey + key->Length;

	// �������� ����� ���������� �������
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 
	
	// ��������� �������������� ����
	BCRYPT_KEY_DATA_BLOB_HEADER* pHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)(PBYTE)ptrBlob; 

	// ����������� ����
	*pHeader = blobHeader; Array::Copy(key, 0, blob, offsetKey, key->Length); 

	// ������������� ����
	return hProvider->ImportKey(nullptr, BCRYPT_KEY_DATA_BLOB, IntPtr(pHeader), cbBlob, 0); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Encryption::Init() 
{$ 
	hKey.Close();

    // ���������� ��������� ���������
    array<BYTE>^ iv = cipher->SetParameters(hProvider.Get()); 

    // ����������� �������������
    if (iv != nullptr) this->iv = (array<BYTE>^) iv->Clone(); 

	// ������� ���� ��� ���������
	hKey.Attach(::ConstructKey(hProvider.Get(), key)); 
}

int Aladdin::CAPI::CNG::Encryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// ��������� ������������� ��������
	int blockSize = BlockSize; if (dataLen == 0) return 0; 

	// ��������� ��������� ������� �����
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();

	// ����������� ������ ����� ����� ����������
	hKey.Get()->Encrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); return dataLen; 
}

int Aladdin::CAPI::CNG::Encryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$ 
	int total = 0; 

	// ��� ������� ������
	if (dataLen > 0) { int blockSize = BlockSize; 

		// ���������� ������ ������ ������ ����� ����������
		int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

		// ������������� ������ �����
		total = (cbBlocks > 0) ? Update(data, dataOff, cbBlocks, buf, bufOff) : 0; 

		// ������� �� �������� ����
		dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += total; 
	}
	// ������� ������ ��������� ���������� �����
	DWORD padding = (Padding != PaddingMode::None) ? BCRYPT_BLOCK_PADDING : 0; 

	// ����������� ��������� �������� ����
	total += hKey.Get()->Encrypt(iv, data, dataOff, dataLen, padding, buf, bufOff); 

	// ���������� ���������� �������
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// �������� �������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Decryption::Init() 
{$ 
	hKey.Close();

    // ���������� ��������� ���������
    array<BYTE>^ iv = cipher->SetParameters(hProvider.Get()); 

    // ����������� �������������
    if (iv != nullptr) this->iv = (array<BYTE>^) iv->Clone(); 

	// ������� ���� ��� ���������
	hKey.Attach(::ConstructKey(hProvider.Get(), key)); 
}

int Aladdin::CAPI::CNG::Decryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// ��������� ������� ������
	if (dataLen == 0) return 0; int blockSize = BlockSize; 
	
	// ��������� ��������� ������� �����
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();
	
	// ��� ���������� ���������� ���������� �����
	if (Padding == PaddingMode::None) 
	{
		// ������������ ������
		return hKey.Get()->Decrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); 
	}
	// ���������� ������ ������ ������ ����� ����������
	int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

	// ��� ������� ���������� �����
	if (lastBlock != nullptr) 
	{
		// ����������� ������ ��� ������������
		array<BYTE>^ buffer = gcnew array<BYTE>(cbBlocks); Array::Copy(data, dataOff, buffer, 0, cbBlocks);
		
		// ������������ ��������� ����
		hKey.Get()->Decrypt(iv, lastBlock, 0, blockSize, 0, buf, bufOff); 
			
		// ��������� ��������� ����
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); bufOff += blockSize;  

		// ������������ ������ ����� ����� ����������
		hKey.Get()->Decrypt(iv, buffer, 0, cbBlocks, 0, buf, bufOff); return dataLen;
	}
	else {
		// �������� ������ ��� ���������� �����
		lastBlock = gcnew array<BYTE>(blockSize); 

		// ������������ ������ ����� ����� ����������
		hKey.Get()->Decrypt(iv, data, dataOff, cbBlocks, 0, buf, bufOff);

		// ��������� ��������� ����
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks;
	}
}

int Aladdin::CAPI::CNG::Decryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$ 
	int total = 0; 

	// ��� ���������� ���������� ���������� �����
	if (Padding == PaddingMode::None) 
	{
		// ������������ ������
		total = hKey.Get()->Decrypt(iv, data, dataOff, dataLen, 0, buf, bufOff); 
	}
	else {
		// ��������� ������������ ������
		if ((dataLen == 0 && lastBlock == nullptr) || (dataLen % BlockSize) != 0) 
		{
			// ��� ������ ��������� ����������
			throw gcnew InvalidDataException();
		}
		// ������������ ������
		total = Update(data, dataOff, dataLen, buf, bufOff); bufOff += total; 

		// ������������ ��������� ����
		total += hKey.Get()->Decrypt(
			iv, lastBlock, 0, BlockSize, BCRYPT_BLOCK_PADDING, buf, bufOff
		); 
	}
	// ���������� ���������� �������
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::Cipher::CreateEncryption(ISecretKey^ key)
{$
	// ��������� ��� �����
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// ������� �������� ������������ ������
	return gcnew Encryption(this, PaddingMode::None, key->Value); 
}
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::Cipher::CreateDecryption(ISecretKey^ key)
{$
	// ��������� ��� �����
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// ������� �������� ������������� ������
	return gcnew Decryption(this, PaddingMode::None, key->Value); 
}

///////////////////////////////////////////////////////////////////////////
// ������� �������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ Aladdin::CAPI::CNG::BlockCipher::CreateBlockMode(CipherMode^ mode)
{$
	// ��� ������ ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// ��� ������ CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::Any); 
	}
	// ��� ������ CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
	{
		// ������� ����� ���������
		return gcnew BlockMode(this, mode, PaddingMode::None); 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}

///////////////////////////////////////////////////////////////////////////
// ����� �������� ��������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::BlockMode::CreateEncryption(
	ISecretKey^ key, PaddingMode padding)
{$
	// ������� ����� ����������
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// ��������� ������ ����������
	PaddingMode oldPadding = this->padding; this->padding = padding; 
			
	// ������� ����� ����������
	BlockPadding^ paddingMode = GetPadding(); 
	
	// ��� ���������������� ������� ��������
	if (padding != PaddingMode::None && padding != PaddingMode::PKCS5)
	{
		// ������� ���������� ���������� � ������� ��������������
		this->padding = PaddingMode::None; 
	}
	try {
		// �������� ����� ������������ 
		Using<Transform^> encryption(CreateEncryption(key)); 
				
		// ������� ��������� ����������
		return paddingMode->CreateEncryption(encryption.Get(), Mode); 
	}
	// ������������ ������ ����������
	finally { this->padding = oldPadding; }
}

Aladdin::CAPI::Transform^ Aladdin::CAPI::CNG::BlockMode::CreateDecryption(
	ISecretKey^ key, PaddingMode padding)
{$
	// ������� ����� ����������
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// ��������� ������ ����������
	PaddingMode oldPadding = this->padding; this->padding = padding; 
			
	// ������� ����� ����������
	BlockPadding^ paddingMode = GetPadding(); 

	// ��� ���������������� ������� ��������
	if (padding != PaddingMode::None && padding != PaddingMode::PKCS5)
	{
		// ������� ���������� ���������� � ������� ��������������
		this->padding = PaddingMode::None; 
	}
	try {
		// �������� ����� ������������� 
		Using<Transform^> decryption(CreateDecryption(key)); 
				
		// ������� ��������� ����������
		return paddingMode->CreateDecryption(decryption.Get(), Mode);
	}
	// ������������ ������ ����������
	finally { this->padding = oldPadding; }
}

Aladdin::CAPI::BlockPadding^ Aladdin::CAPI::CNG::BlockMode::GetPadding() 
{$
    // ������� ���������� ����������
    if (padding == PaddingMode::None) return gcnew Pad::None();

    // ������� ���������� ������
    if (padding == PaddingMode::Zero) return gcnew Pad::Zero();

    // ������� ���������� PKCS
    if (padding == PaddingMode::PKCS5) return gcnew Pad::PKCS5(); 

    // ������� ���������� ISO
    if (padding == PaddingMode::ISO) return gcnew Pad::ISO(); 

    // ��� ������ ���������� CTS
    if (padding == PaddingMode::CTS) return gcnew Pad::CTS(); 

    // ��� ������ ��������� ����������
    throw gcnew NotSupportedException();
}

array<BYTE>^ Aladdin::CAPI::CNG::BlockMode::SetParameters(BProviderHandle^ hProvider)
{$
	// ���������� ��������� ���������
	blockCipher->SetParameters(hProvider); 

	// ��� ������ ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// ������� ����� ���������� 
		String^ modeCNG = BCRYPT_CHAIN_MODE_ECB; 

		// ���������� ����� ����������
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 
		
		return nullptr; 
	}
	// ��� ������ CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// ������������� ��� ����������
		CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

		// ������� ����� ���������� 
		String^ modeCNG = BCRYPT_CHAIN_MODE_CBC; 

		// ���������� ����� ����������
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 

		// ��� ������������� 
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// ���������� ������ �����
			hProvider->SetLong(BCRYPT_BLOCK_LENGTH, parameters->BlockSize, 0); 
		}
		// ������� �������������
		return parameters->IV; 
	}
	// ��� ������ CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// ������������� ��� ����������
		CipherMode::CFB^ parameters = (CipherMode::CFB^)mode; 

		// ������� ����� ���������� 
		String^ modeCNG = BCRYPT_CHAIN_MODE_CFB; 

		// ���������� ����� ����������
		hProvider->SetString(BCRYPT_CHAINING_MODE, modeCNG, 0); 

		// ��� ������������� 
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// ���������� ������ �����
			hProvider->SetLong(BCRYPT_BLOCK_LENGTH, parameters->BlockSize, 0); 
		}
		// ������� �������������
		return parameters->IV; 
	}
	// ��� ������ ��������� ����������
	throw gcnew NotSupportedException(); 
}
