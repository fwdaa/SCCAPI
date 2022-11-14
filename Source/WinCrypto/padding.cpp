#include "pcxx.h"
#include "padding.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "padding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����� ����������
///////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::BlockPadding> Crypto::BlockPadding::Create(uint32_t padding)
{
	switch (padding)
	{
	// ������� ����� ���������� 
	case CRYPTO_PADDING_NONE    : return std::shared_ptr<BlockPadding>(new Padding::None ()); 
	case CRYPTO_PADDING_PKCS5   : return std::shared_ptr<BlockPadding>(new Padding::PKCS5()); 
	case CRYPTO_PADDING_ISO10126: return std::shared_ptr<BlockPadding>(new Padding::PKCS5()); 
	case CRYPTO_PADDING_CTS     : return std::shared_ptr<BlockPadding>(new Padding::CTS  ()); 
	}
    // ����������� ����� ���������� 
	return std::shared_ptr<BlockPadding>(); 
}

std::shared_ptr<Crypto::ITransform> 
Crypto::BlockPadding::CreateEncryption(
    const std::shared_ptr<ITransform>& encryption, uint32_t, const std::vector<uint8_t>&) const 
{
    // ��������� ������������� ��������� ������
    if (encryption->Padding() == ID()) return encryption; 

    // ��������� ������������ ������
    if (encryption->Padding() != CRYPTO_PADDING_NONE) 
	{
		// ��� ������ ��������� ���������� 
		AE_CHECK_HRESULT(NTE_BAD_KEY_STATE); 
	}
	// �������� ���� �� �����������
    return std::shared_ptr<ITransform>(); 
}

std::shared_ptr<Crypto::ITransform> 
Crypto::BlockPadding::CreateDecryption(
	const std::shared_ptr<ITransform>& decryption, uint32_t, const std::vector<uint8_t>&) const 
{
    // ��������� ������������� ��������� ������
    if (decryption->Padding() == ID()) return decryption; 

    // ��������� ������������ ������
    if (decryption->Padding() != CRYPTO_PADDING_NONE) 
	{
		// ��� ������ ��������� ���������� 
		AE_CHECK_HRESULT(NTE_BAD_KEY_STATE); 
	}
	// �������� ���� �� �����������
    return std::shared_ptr<ITransform>(); 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� PKCS5/ISO10126
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::PKCS5::Encryption::Finish(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) 
{
    // ���������� ��������� ������ ������
    size_t cb = GetLength(cbData); if (!pvBuffer) return cb; 

    // ��������� ������������� ������
    if (cbBuffer < cb) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

    // ����������� ��������� �����
    return Encrypt(pvData, cbData, pvBuffer, cbBuffer, true, nullptr);
}

size_t Crypto::Padding::PKCS5::Encryption::Encrypt(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
    // ����������� ����������� �����
    if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

    // ��������� �������������� ���� 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // ���������� ������ ������ ������
    size_t cbBlocks = (cbData / _cbBlock) * _cbBlock; 

    // ����������� ������ �����
    size_t cb = _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ������� �� �������� ����
    pbData += cbBlocks; cbData -= cbBlocks; pbBuffer += cb; 

	// ������� �������� ����������� � ����������� �������� ������
	uint8_t pad = (uint8_t)(_cbBlock - cbData); memcpy(pbBuffer, pbData, cbData); 

	// ��������� ����������
	Fill(pbBuffer + cbData, pad - 1, pad); pbBuffer[_cbBlock - 1] = pad; 
    
    // ����������� ����������� ����
    return cb + _encryption->Update(pbBuffer, _cbBlock, pbBuffer, _cbBlock); 

}

size_t Crypto::Padding::PKCS5::Decryption::Decrypt(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
    // ������������ ����������� �����
    if (!last) return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

    // ��������� �������������� ���� 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // ���������� ������ ������ ������ ����� ���������� 
    size_t cbBlocks = ((cbData - 1) / _cbBlock) * _cbBlock; 

    // ������� ��������� ����
    std::vector<uint8_t> block(pbData + cbBlocks, pbData + cbData); 

    // ������������ ������ �����
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ������������ ��������� ����
    _decryption->Update(&block[0], _cbBlock, &block[0], _cbBlock); 

	// ��������� ������ ����������
	if (block[_cbBlock - 1] == 0 || block[_cbBlock - 1] > _cbBlock) 
	{
	    // ��� ������ ��������� ����������
		AE_CHECK_HRESULT(NTE_BAD_DATA);
	}
	// ���������� ������ ��������� �����
	size_t cb = _cbBlock - block[_cbBlock - 1]; 
    
    // ��������� �������� ���������� ������
    if (!FillCheck(&block[cb], _cbBlock - cb - 1, block[_cbBlock - 1]))
    {
        // ��� ������ ��������� ����������
        AE_CHECK_HRESULT(NTE_BAD_DATA);
    }
	// ����������� �������� ����
	memcpy((uint8_t*)pbBuffer + cbBlocks, &block[0], cb); return cbBlocks + cb;
}

///////////////////////////////////////////////////////////////////////////////
// ���������� CTS ��� ECB
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::CTS::EncryptionECB::EncryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // ����������� ������������ ����
	if (cbData == _cbBlock) return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
    
    // ���������� ������ ������ ������ ����� ���� ���������
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // ��������� ��������� �����
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // ���������� ��� �����, ����� ���� ���������
    pbBuffer += _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ����������� ������������� ����
    _encryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);
        
    // ����������� ����� ������������� ������ � ��������� ����
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // ����������� ��������� ���� ��� ������������
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock); 

    // ����������� ��������� ���� � ������������� ����
    _encryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData;
}

size_t Crypto::Padding::CTS::DecryptionECB::DecryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // ������������ ������������ ����
	if (cbData == _cbBlock) return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
    
    // ���������� ������ ������ ������ ����� ���� ���������
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // ��������� ��������� �����
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // ���������� ��� �����, ����� ���� ���������
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ������������ ������������� ����
    _decryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);

    // ����������� ����� �������������� ������ � ��������� ����
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // ����������� ��������� ���� ��� �������������
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock);

    // ������������ ���� � ������������� ����
    _decryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData; 
} 

///////////////////////////////////////////////////////////////////////////////
// ���������� CTS ��� CBC
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::CTS::EncryptionCBC::EncryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // ����������� ������������ ����
	if (cbData == _cbBlock) return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 

    // ���������� ������ ������ ������ ����� ���� ���������
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // ��������� ��������� �����
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // ���������� ��� �����, ����� ���� ���������
    pbBuffer += _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ����������� ������������� ����
    _encryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);

    // ����������� ����� ������������� ������ � ��������� ����
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // ����������� ��������� ���� ��� ������������
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock); 

    // ��������� ��������� ����
    for (size_t i = lasts.size() - _cbBlock; i < _cbBlock; i++) lasts[i] = 0; 

    // ����������� ��������� ���� � ������������� ����
    _encryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData; 
}

size_t Crypto::Padding::CTS::DecryptionCBC::DecryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // ������������ ������������ ���� 
	if (cbData == _cbBlock) return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 

    // ���������� ������ ������ ������ ����� ���� ���������
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // ��������� ��������� �����
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

	// ��������� ������� �������� �����
	if (cbBlocks > 0) memcpy(&_iv[0], pbData + cbBlocks - _cbBlock, _cbBlock); 

    // ���������� ��� �����, ����� ���� ���������
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // ��� �������� ����� ������ 
    if (lasts.size() == 2 * _cbBlock) 
    { 
        // ������������ ��������� ����
        _decryption->Update(&lasts[_cbBlock], _cbBlock, pbBuffer, _cbBlock); 
        
        // ������������ ������������� ����
        _decryption->Update(&lasts[0], _cbBlock, pbBuffer + _cbBlock, _cbBlock); 
    }
    else {
        // ������������ ������������� ����
        _decryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); 

        // ������� ������ �������� �����
        for (size_t i = 0; i < _cbBlock; i++) pbBuffer[i] ^= _iv[i];

        // ����������� ������ ��� ��������� 
        memcpy(pbBuffer + _cbBlock, pbBuffer, lasts.size() - _cbBlock); 

        // ��������� ����� �������� ����� ������ CBC
        for (size_t i = 0; i < lasts.size() - _cbBlock; i++) 
        {
            pbBuffer[_cbBlock + i] ^= lasts[i]; 
        }
        // ����������� ��������� ���� ��� �������������
        memcpy(pbBuffer, &lasts[_cbBlock], lasts.size() - _cbBlock); 

        // ������������ ������������� ����
        _decryption->Update(pbBuffer, _cbBlock, pbBuffer, _cbBlock); 

        // �������� �������� ����� ������ CBC
        for (size_t i = 0; i < _cbBlock; i++) pbBuffer[i] ^= lasts[i] ^ _iv[i];
    }
    return cbData; 
}
