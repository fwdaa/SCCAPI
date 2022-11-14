#include "pcxx.h"
#include "padding.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "padding.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Режим дополнения
///////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::BlockPadding> Crypto::BlockPadding::Create(uint32_t padding)
{
	switch (padding)
	{
	// создать режим дополнения 
	case CRYPTO_PADDING_NONE    : return std::shared_ptr<BlockPadding>(new Padding::None ()); 
	case CRYPTO_PADDING_PKCS5   : return std::shared_ptr<BlockPadding>(new Padding::PKCS5()); 
	case CRYPTO_PADDING_ISO10126: return std::shared_ptr<BlockPadding>(new Padding::PKCS5()); 
	case CRYPTO_PADDING_CTS     : return std::shared_ptr<BlockPadding>(new Padding::CTS  ()); 
	}
    // неизвестный режим дополнения 
	return std::shared_ptr<BlockPadding>(); 
}

std::shared_ptr<Crypto::ITransform> 
Crypto::BlockPadding::CreateEncryption(
    const std::shared_ptr<ITransform>& encryption, uint32_t, const std::vector<uint8_t>&) const 
{
    // проверить необходимость установки режима
    if (encryption->Padding() == ID()) return encryption; 

    // проверить корректность режима
    if (encryption->Padding() != CRYPTO_PADDING_NONE) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_HRESULT(NTE_BAD_KEY_STATE); 
	}
	// операция пока не реализована
    return std::shared_ptr<ITransform>(); 
}

std::shared_ptr<Crypto::ITransform> 
Crypto::BlockPadding::CreateDecryption(
	const std::shared_ptr<ITransform>& decryption, uint32_t, const std::vector<uint8_t>&) const 
{
    // проверить необходимость установки режима
    if (decryption->Padding() == ID()) return decryption; 

    // проверить корректность режима
    if (decryption->Padding() != CRYPTO_PADDING_NONE) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_HRESULT(NTE_BAD_KEY_STATE); 
	}
	// операция пока не реализована
    return std::shared_ptr<ITransform>(); 
};

///////////////////////////////////////////////////////////////////////////////
// Дополнение PKCS5/ISO10126
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::PKCS5::Encryption::Finish(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) 
{
    // определить требуемый размер буфера
    size_t cb = GetLength(cbData); if (!pvBuffer) return cb; 

    // проверить достаточность буфера
    if (cbBuffer < cb) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

    // зашифровать последние блоки
    return Encrypt(pvData, cbData, pvBuffer, cbBuffer, true, nullptr);
}

size_t Crypto::Padding::PKCS5::Encryption::Encrypt(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
    // зашифровать непоследние блоки
    if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

    // выполнить преобразование типа 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // определить размер полных блоков
    size_t cbBlocks = (cbData / _cbBlock) * _cbBlock; 

    // зашифровать полные блоки
    size_t cb = _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // перейти на неполный блок
    pbData += cbBlocks; cbData -= cbBlocks; pbBuffer += cb; 

	// указать значение заполнителя и скопировать исходные данные
	uint8_t pad = (uint8_t)(_cbBlock - cbData); memcpy(pbBuffer, pbData, cbData); 

	// заполнить дополнение
	Fill(pbBuffer + cbData, pad - 1, pad); pbBuffer[_cbBlock - 1] = pad; 
    
    // зашифровать дополненный блок
    return cb + _encryption->Update(pbBuffer, _cbBlock, pbBuffer, _cbBlock); 

}

size_t Crypto::Padding::PKCS5::Decryption::Decrypt(
    const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
    // расшифровать непоследние блоки
    if (!last) return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

    // выполнить преобразование типа 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // определить размер полных блоков кроме последнего 
    size_t cbBlocks = ((cbData - 1) / _cbBlock) * _cbBlock; 

    // извлечь последний блок
    std::vector<uint8_t> block(pbData + cbBlocks, pbData + cbData); 

    // расшифровать полные блоки
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // расшифровать последний блок
    _decryption->Update(&block[0], _cbBlock, &block[0], _cbBlock); 

	// проверить размер дополнения
	if (block[_cbBlock - 1] == 0 || block[_cbBlock - 1] > _cbBlock) 
	{
	    // при ошибке выбросить исключение
		AE_CHECK_HRESULT(NTE_BAD_DATA);
	}
	// определить размер исходного блока
	size_t cb = _cbBlock - block[_cbBlock - 1]; 
    
    // проверить значение внутренних байтов
    if (!FillCheck(&block[cb], _cbBlock - cb - 1, block[_cbBlock - 1]))
    {
        // при ошибке выбросить исключение
        AE_CHECK_HRESULT(NTE_BAD_DATA);
    }
	// скопировать неполный блок
	memcpy((uint8_t*)pbBuffer + cbBlocks, &block[0], cb); return cbBlocks + cb;
}

///////////////////////////////////////////////////////////////////////////////
// Дополнение CTS для ECB
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::CTS::EncryptionECB::EncryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // зашифровать единственный блок
	if (cbData == _cbBlock) return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
    
    // определить размер полных блоков кроме двух последних
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // сохранить последние блоки
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // обработать все блоки, кроме двух последних
    pbBuffer += _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // зашифровать предпоследний блок
    _encryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);
        
    // скопировать часть зашифрованных данных в последний блок
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // скопировать последний блок для зашифрования
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock); 

    // зашифровать последний блок в предпоследний блок
    _encryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData;
}

size_t Crypto::Padding::CTS::DecryptionECB::DecryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // расшифровать единственный блок
	if (cbData == _cbBlock) return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
    
    // определить размер полных блоков кроме двух последних
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // сохранить последние блоки
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // обработать все блоки, кроме двух последних
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // расшифровать предпоследний блок
    _decryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);

    // скопировать часть расшифрованных данных в последний блок
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // скопировать последний блок для расшифрования
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock);

    // расшифровать блок в предпоследний блок
    _decryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData; 
} 

///////////////////////////////////////////////////////////////////////////////
// Дополнение CTS для CBC
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::Padding::CTS::EncryptionCBC::EncryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // зашифровать единственный блок
	if (cbData == _cbBlock) return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 

    // определить размер полных блоков кроме двух последних
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // сохранить последние блоки
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

    // обработать все блоки, кроме двух последних
    pbBuffer += _encryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // зашифровать предпоследний блок
    _encryption->Update(&lasts[0], _cbBlock, &lasts[0], _cbBlock);

    // скопировать часть зашифрованных данных в последний блок
    memcpy(pbBuffer + _cbBlock, &lasts[0], lasts.size() - _cbBlock);

    // скопировать последний блок для зашифрования
    memcpy(&lasts[0], &lasts[_cbBlock], lasts.size() - _cbBlock); 

    // дополнить последний блок
    for (size_t i = lasts.size() - _cbBlock; i < _cbBlock; i++) lasts[i] = 0; 

    // зашифровать последний блок в предпоследний блок
    _encryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); return cbData; 
}

size_t Crypto::Padding::CTS::DecryptionCBC::DecryptSP3(
    const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
{
    // расшифровать единственный блок 
	if (cbData == _cbBlock) return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 

    // определить размер полных блоков кроме двух последних
    size_t cbBlocks = ((cbData - _cbBlock - 1) / _cbBlock) * _cbBlock;

    // сохранить последние блоки
	std::vector<BYTE> lasts(pbData + cbBlocks, pbData + cbData); 

	// сохранить регистр обратной связи
	if (cbBlocks > 0) memcpy(&_iv[0], pbData + cbBlocks - _cbBlock, _cbBlock); 

    // обработать все блоки, кроме двух последних
    pbBuffer += _decryption->Update(pbData, cbBlocks, pbBuffer, cbBuffer); 

    // для кратного числа блоков 
    if (lasts.size() == 2 * _cbBlock) 
    { 
        // расшифровать последний блок
        _decryption->Update(&lasts[_cbBlock], _cbBlock, pbBuffer, _cbBlock); 
        
        // расшифровать предпоследний блок
        _decryption->Update(&lasts[0], _cbBlock, pbBuffer + _cbBlock, _cbBlock); 
    }
    else {
        // расшифровать предпоследний блок
        _decryption->Update(&lasts[0], _cbBlock, pbBuffer, _cbBlock); 

        // удалить старую обратную связь
        for (size_t i = 0; i < _cbBlock; i++) pbBuffer[i] ^= _iv[i];

        // скопировать данные для изменения 
        memcpy(pbBuffer + _cbBlock, pbBuffer, lasts.size() - _cbBlock); 

        // применить новую обратную связь режима CBC
        for (size_t i = 0; i < lasts.size() - _cbBlock; i++) 
        {
            pbBuffer[_cbBlock + i] ^= lasts[i]; 
        }
        // скопировать последний блок для расшифрования
        memcpy(pbBuffer, &lasts[_cbBlock], lasts.size() - _cbBlock); 

        // расшифровать предпоследний блок
        _decryption->Update(pbBuffer, _cbBlock, pbBuffer, _cbBlock); 

        // изменить обратную связь режима CBC
        for (size_t i = 0; i < _cbBlock; i++) pbBuffer[i] ^= lasts[i] ^ _iv[i];
    }
    return cbData; 
}
