#include "stdafx.h"
#include "Mac.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Cipher.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Encryption::Init() 
{$ 
	hKey.Close();
			
	// ��� ������� ������� �����
	if (dynamic_cast<SecretKey^>(key) != nullptr)
	{
		// ������� ��������� �����
		hKey.Attach(Handle::AddRef(((SecretKey^)key)->Handle));
	}
    // ��� ������� �������� �����
    else if (key->Value != nullptr)
    {
		// �������� ��� �����
		SecretKeyType^ keyType = cipher->Provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // ������� ���� ��� ���������
        hKey.Attach(keyType->ConstructKey(cipher->Context, key->Value, 0));  
    }
    // ��� ������ ��������� ����������
    else throw gcnew InvalidKeyException();  

    // ���������� ��������� ���������
    try { cipher->SetParameters(hKey.Get(), Padding); }

    // ���������� ��������� ����������
    catch(Exception^) { hKey.Close(); throw; }
}

int Aladdin::CAPI::CSP::Encryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// ��������� ������������� ��������
	int blockSize = BlockSize; if (dataLen == 0) return 0; 

	// ��������� ��������� ������� �����
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();

	// ����������� ������ ����� ����� ����������
	hKey.Get()->Encrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); return dataLen; 
}

int Aladdin::CAPI::CSP::Encryption::Finish(
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
	DWORD final = (padding != PaddingMode::None); 

	// ��� ������� ������
	if (dataLen > 0 || final) 
	{
		// ����������� ��������� �������� ����
		total += hKey.Get()->Encrypt(data, dataOff, dataLen, final, 0, buf, bufOff); 
	}
	// ���������� ���������� �������
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// �������� �������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::Decryption::Init() 
{$ 
	hKey.Close(); 

	// ��� ������� ������� �����
	if (dynamic_cast<SecretKey^>(key) != nullptr)
	{
		// ������� ��������� �����
		hKey.Attach(Handle::AddRef(((SecretKey^)key)->Handle)); 
	}
    // ��� ������� �������� �����
    else if (key->Value != nullptr)
    {
		// �������� ��� �����
		SecretKeyType^ keyType = cipher->Provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // ������� ���� ��� ���������
        hKey.Attach(keyType->ConstructKey(cipher->Context, key->Value, 0));  
    }
    // ��� ������ ��������� ����������
    else throw gcnew InvalidKeyException();  

    // ���������� ��������� ���������
    try { cipher->SetParameters(hKey.Get(), Padding); }

    // ���������� ��������� ����������
    catch(Exception^) { hKey.Close(); throw; }
}

int Aladdin::CAPI::CSP::Decryption::Update(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$
	// ��������� ������� ������
	if (dataLen == 0) return 0; int blockSize = BlockSize; 
	
	// ��������� ��������� ������� �����
	if ((dataLen % blockSize) != 0) throw gcnew InvalidDataException();
	
	// ��� ���������� ���������� ���������� �����
	if (padding != PaddingMode::PKCS5)
	{
		// ������������ ������
		return hKey.Get()->Decrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); 
	}
	// ���������� ������ ������ ������ ����� ����������
	int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

	// ��� ������� ���������� �����
	if (lastBlock != nullptr) { array<BYTE>^ buffer = gcnew array<BYTE>(cbBlocks); 
	
		// ����������� ������ ��� �������������
		Array::Copy(data, dataOff, buffer, 0, cbBlocks);
		
		// ������������ ��������� ����
		hKey.Get()->Decrypt(lastBlock, 0, blockSize, FALSE, 0, buf, bufOff); bufOff += blockSize;  
			
		// ��������� ��������� ����
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

		// ������������ ������ ����� ����� ����������
		hKey.Get()->Decrypt(buffer, 0, cbBlocks, FALSE, 0, buf, bufOff); return dataLen;
	}
	else {
		// �������� ������ ��� ���������� �����
		lastBlock = gcnew array<BYTE>(blockSize); 

		// ������������ ������ ����� ����� ����������
		hKey.Get()->Decrypt(data, dataOff, cbBlocks, FALSE, 0, buf, bufOff);

		// ��������� ��������� ����
		Array::Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks;
	}
}

int Aladdin::CAPI::CSP::Decryption::Finish(
	array<BYTE>^ data, int dataOff, int dataLen, array<BYTE>^ buf, int bufOff)
{$ 
	int total = 0; 

	// ��� ���������� ���������� ���������� �����
	if (padding != PaddingMode::PKCS5)
	{
		// ������������ ������
		if (dataLen > 0) total = hKey.Get()->Decrypt(data, dataOff, dataLen, FALSE, 0, buf, bufOff); 
	}
	else {
		// ��������� ������������ ������
		if ((dataLen == 0 && lastBlock == nullptr) || (dataLen % BlockSize) != 0) 
		{
			// ��� ������ ��������� ����������
			throw gcnew InvalidDataException();
		}
		// ������� ������ ��������� ���������� �����
		DWORD final = (padding != PaddingMode::None); 

		// ������������ ������
		total = Update(data, dataOff, dataLen, buf, bufOff); bufOff += total; 

		// ������������ ��������� ����
		total += hKey.Get()->Decrypt(lastBlock, 0, BlockSize, final, 0, buf, bufOff); 
	}
	// ���������� ���������� �������
	hKey.Close(); return total; 
}

///////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::Cipher::CreateEncryption(ISecretKey^ key)
{
	// ������� �������� ������������ ������
	return gcnew Encryption(this, PaddingMode::None, key); 
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::Cipher::CreateDecryption(ISecretKey^ key)
{
	// ������� �������� ������������� ������
	return gcnew Decryption(this, PaddingMode::None, key); 
}

///////////////////////////////////////////////////////////////////////////
// ������� �������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Cipher^ Aladdin::CAPI::CSP::BlockCipher::CreateBlockMode(CipherMode^ mode)
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
Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateEncryption(ISecretKey^ key, PaddingMode padding)
{$
	// ������� ����� ����������
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// ��������� ������ ����������
	PaddingMode oldPadding = this->padding; this->padding = padding; 

	// ������� ����� ����������
	BlockPadding^ paddingMode = GetPadding(); 

	// ��� ���������������� ������� ��������
	if (padding != PaddingMode::None && 
	    padding != PaddingMode::Zero &&
	    padding != PaddingMode::PKCS5)
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

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateDecryption(ISecretKey^ key, PaddingMode padding)
{$
	// ������� ����� ����������
	if (this->padding != PaddingMode::Any) padding = this->padding; 
        
	// ��������� ������ ����������
	PaddingMode oldPadding = this->padding; this->padding = padding; 

	// ������� ����� ����������
	BlockPadding^ paddingMode = GetPadding(); 

	// ��� ���������������� ������� ��������
	if (padding != PaddingMode::None && 
	    padding != PaddingMode::Zero &&
	    padding != PaddingMode::PKCS5)
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

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateEncryption(ISecretKey^ key)
{$
	// �������� ������������� ������������
	return gcnew Encryption(this, padding, key); 
}

Aladdin::CAPI::Transform^ 
Aladdin::CAPI::CSP::BlockMode::CreateDecryption(ISecretKey^ key)
{$
	// �������� ������������� �������������
	return gcnew Decryption(this, padding, key); 
}

Aladdin::CAPI::BlockPadding^ Aladdin::CAPI::CSP::BlockMode::GetPadding() 
{$
    // ������� ���������� ����������
    if (padding == PaddingMode::None) return gcnew Pad::None();

    // ������� ���������� ������
    if (padding == PaddingMode::Zero) return gcnew Pad::Zero();

    // ������� ���������� PKCS
    if (padding == PaddingMode::PKCS5) return gcnew Pad::PKCS5(); 

    // ������� ���������� ISO
    if (padding == PaddingMode::ISO9797) return gcnew Pad::ISO9797(); 

    // ��� ������ ���������� CTS
    if (padding == PaddingMode::CTS) return gcnew Pad::CTS(); 

    // ��� ������ ��������� ����������
    throw gcnew NotSupportedException();
}

void Aladdin::CAPI::CSP::BlockMode::SetParameters(KeyHandle^ hKey, PaddingMode padding)
{$
	// ���������� ��������� ���������
	blockCipher->SetParameters(hKey); switch (padding) 
	{
	case PaddingMode::Zero: 
	
		// ������������ ����� ����������
		hKey->SetLong(KP_PADDING, ZERO_PADDING,  0); break; 
	
	case PaddingMode::PKCS5: 

		// ������������ ����� ����������
		hKey->SetLong(KP_PADDING, PKCS5_PADDING,  0); break; 
	}
	// ��� ������ ECB
	if (dynamic_cast<CipherMode::ECB^>(mode) != nullptr)
	{
		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_ECB, 0);  
	}
	// ��� ������ CBC
	else if (dynamic_cast<CipherMode::CBC^>(mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::CBC^ parameters = (CipherMode::CBC^)mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_CBC, 0);  

		// ��� �������������
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// ���������� �������� ������
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// ��� ������ CFB
	else if (dynamic_cast<CipherMode::CFB^>(mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::CFB^ parameters = (CipherMode::CFB^)mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_CFB, 0);  

		// ��� �������������
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// ���������� �������� ������
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
	// ��� ������ OFB
	else if (dynamic_cast<CipherMode::OFB^>(mode) != nullptr)
	{
		// �������� ��������� ���������
		CipherMode::OFB^ parameters = (CipherMode::OFB^)mode; 

		// ���������� ����� ����������
		hKey->SetLong(KP_MODE, CRYPT_MODE_OFB, 0);  

		// ��� �������������
		if (parameters->BlockSize != parameters->IV->Length)
		{
			// ���������� �������� ������
			hKey->SetLong(KP_MODE_BITS, parameters->BlockSize * 8, 0);
		}
		// ���������� �������������
		hKey->SetParam(KP_IV, parameters->IV, 0);
	}
}

