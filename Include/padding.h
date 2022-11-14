#pragma once
#include "crypto.h"

namespace Crypto { namespace Padding {

///////////////////////////////////////////////////////////////////////////////
// Отсутствие дополнения
///////////////////////////////////////////////////////////////////////////////
class None : public BlockPadding
{ 
    // идентификатор дополнения
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_NONE; }

	// требуемый размер буфера
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// требуемый размер буфера
		return (cb % cbBlock) ? size_t(-1) : cb; 
	}
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// требуемый размер буфера
		return (cb % cbBlock) ? size_t(-1) : cb; 
	}
    // алгоритм зашифрования данных
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // вызвать базовую функцию
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

		// алгоритм зашифрования данных
        return (transform) ? transform : encryption; 
    }
    // алгоритм расшифрования данных
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // вызвать базовую функцию
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // алгоритм расшифрования данных
       return (transform) ? transform : decryption; 
    }
}; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение PKCS
///////////////////////////////////////////////////////////////////////////////
class PKCS5 : public BlockPadding
{ 
    // идентификатор дополнения
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_PKCS5; }

	// требуемый размер буфера
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// увеличить размер до границы блока
		return (cb + cbBlock - 1) / cbBlock * cbBlock; 
	}
	// требуемый размер буфера
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// проверить кратность размеру блока
		return (cb > 0 && (cb % cbBlock) == 0) ? (cb - 1) : size_t(-1); 
	}
    // алгоритм зашифрования данных
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // вызвать базовую функцию
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

        // алгоритм зашифрования данных
        return (transform) ? transform : std::shared_ptr<ITransform>(new Encryption(encryption)); 
    }
    // алгоритм расшифрования данных
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // вызвать базовую функцию
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // алгоритм расшифрования данных
       return (transform) ? transform : std::shared_ptr<ITransform>(new Decryption(decryption)); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования с дополнением
    ///////////////////////////////////////////////////////////////////////////////
	public: class Encryption : public Crypto::Encryption
    {
		// режим зашифрования данных
		private: std::shared_ptr<ITransform> _encryption; size_t _cbBlock; 

		// конструктор
		public: Encryption(const std::shared_ptr<ITransform>& encryption) 
			
			// сохранить переданные параметры
			: _encryption(encryption), _cbBlock(_encryption->BlockSize()) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_PKCS5; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return PKCS5().GetEncryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// обработать данные
		public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
		{
			// зашифровать полные блоки
			return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, nullptr);
		}
		// завершить обработку данных
		public: WINCRYPT_CALL virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override; 

		// зашифровать данные
		protected: WINCRYPT_CALL virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) override; 

		// заполнить буфер заполнителем или случайными данными
		protected: virtual void Fill(void* pvBuffer, size_t cbBuffer, size_t pad) const 
		{
			// заполнить буфер заполнителем
			for (size_t i = 0; i < cbBuffer; i++) ((uint8_t*)pvBuffer)[i] = (uint8_t)pad;
		}
    };
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования с дополнением
    ///////////////////////////////////////////////////////////////////////////////
	public: class Decryption : public Crypto::Decryption
    {
		// режим расшифрования данных
		private: std::shared_ptr<ITransform> _decryption; size_t _cbBlock; 

        // конструктор
		public: Decryption(const std::shared_ptr<ITransform>& decryption) 
			
			// сохранить переданные параметры 
			: _decryption(decryption), _cbBlock(_decryption->BlockSize()) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_PKCS5; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return PKCS5().GetDecryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// расшифровать данные
		protected: WINCRYPT_CALL virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 

		// проверить корректность буфера
		protected: bool FillCheck(void* pvBuffer, size_t cbBuffer, uint8_t pad) const
		{
			// для всех добавленных байтов
			for (size_t i = 0; i < cbBuffer; i++)
			{
				// проверить совпадение байта
				if (((const uint8_t*)pvBuffer)[i] != pad) return false; 
			}
			return true; 
		}
    }; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение ISO10126
///////////////////////////////////////////////////////////////////////////////
class ISO10126 : public BlockPadding
{ 
	// конструктор
	public: ISO10126(const std::shared_ptr<IRand>& rand) 
		
		// сохранить переданные параметры 
		: _rand(rand) {} private: std::shared_ptr<IRand> _rand; 
			
    // идентификатор дополнения
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_ISO10126; }

	// требуемый размер буфера
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// увеличить размер до границы блока
		return (cb + cbBlock - 1) / cbBlock * cbBlock; 
	}
	// требуемый размер буфера
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// проверить кратность размеру блока
		return (cb > 0 && (cb % cbBlock) == 0) ? (cb - 1) : size_t(-1); 
	}
    // алгоритм зашифрования данных
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // вызвать базовую функцию
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

        // алгоритм зашифрования данных
        return (transform) ? transform : std::shared_ptr<ITransform>(new Encryption(encryption, _rand)); 
    }
    // алгоритм расшифрования данных
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // вызвать базовую функцию
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // алгоритм расшифрования данных
       return (transform) ? transform : std::shared_ptr<ITransform>(new Decryption(decryption)); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования с дополнением
    ///////////////////////////////////////////////////////////////////////////////
	private: class Encryption : public PKCS5::Encryption
    {
		// генератор случайных данных
		private: std::shared_ptr<IRand> _rand;

		// конструктор
		public: Encryption(const std::shared_ptr<ITransform>& encryption, const std::shared_ptr<IRand>& rand) 
			
			// сохранить переданные параметры
			: PKCS5::Encryption(encryption), _rand(rand) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_ISO10126; }

		// заполнить буфер заполнителем или случайными данными
		protected: virtual void Fill(void* pvBuffer, size_t cbBuffer, uint8_t) const 
		{
			// сгенерировать случайные данные 
			_rand->Generate(pvBuffer, cbBuffer); 
		}
    };
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования с дополнением
    ///////////////////////////////////////////////////////////////////////////////
	private: class Decryption : public PKCS5::Decryption
    {
        // конструктор
		public: Decryption(const std::shared_ptr<ITransform>& decryption) : PKCS5::Decryption(decryption) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_ISO10126; }

		// проверить корректность буфера
		protected: bool FillCheck(void* pvBuffer, size_t cbBuffer, uint8_t pad) const { return true; }
    }; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение CTS. Данные не могут быть меньше одного блока. 
///////////////////////////////////////////////////////////////////////////////
class CTS : public BlockPadding
{ 
	// конструктор
	public: CTS(int version = 2) : _version(version) {} private: int _version; 

    // идентификатор дополнения
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_CTS; }

	// требуемый размер буфера
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// проверить минимальный размер данных
		return (cb < cbBlock) ? size_t(-1) : cb; 
	}
	// требуемый размер буфера
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// проверить минимальный размер данных
		return (cb < cbBlock) ? size_t(-1) : cb; 
	}
    // алгоритм зашифрования данных
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // вызвать базовую функцию
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

		// проверить соответствие преобразования 
		if (transform) return transform; if (mode == CRYPTO_BLOCK_MODE_ECB)
		{
			// вернуть алгоритм зашифрования данных
			return std::shared_ptr<ITransform>(new EncryptionECB(encryption, _version));
		}
		// вернуть алгоритм зашифрования данных
		else return std::shared_ptr<ITransform>(new EncryptionCBC(encryption, _version));
    }
    // алгоритм расшифрования данных
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // вызвать базовую функцию
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

		// проверить соответствие преобразования 
		if (transform) return transform; if (mode == CRYPTO_BLOCK_MODE_ECB)
		{
			// вернуть алгоритм расшифрования данных
			return std::shared_ptr<ITransform>(new DecryptionECB(decryption, _version));
		}
		// вернуть алгоритм расшифрования данных
		else return std::shared_ptr<ITransform>(new DecryptionCBC(decryption, _version, iv));
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования ECB с дополнением CTS. Последний блок обязательно 
	// должен быть передан через Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class EncryptionECB : public Crypto::Encryption
    {
		// режим зашифрования данных 
		private: std::shared_ptr<ITransform> _encryption; int _version; size_t _cbBlock; 

        // конструктор
		public: EncryptionECB(const std::shared_ptr<ITransform>& encryption, int version) 
			
			// сохранить переданные параметры
			: _encryption(encryption), _version(version), _cbBlock(_encryption->BlockSize()) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return CTS().GetEncryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// зашифровать данные
		protected: virtual size_t Encrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// зашифровать непоследние блоки
			if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// завершить обработку данных
			if (_version == 3) return EncryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// завершить обработку данных
			else return EncryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// завершить обработку данных
		private: WINCRYPT_CALL size_t EncryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// завершить обработку данных
		private: size_t EncryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
		    // выполнить обработку некратного блока
			if ((cbData % _cbBlock) != 0) return EncryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// кратный случай совместим с обычным режимом
			return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования ECB с дополнением CTS. Последний блок обязательно 
	// должен быть передан через Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class DecryptionECB : public Crypto::Decryption
    {
		// режим расшифрования данных и последний блок данных
		private: std::shared_ptr<ITransform> _decryption; int _version; size_t _cbBlock; 

        // конструктор
		public: DecryptionECB(const std::shared_ptr<ITransform>& decryption, int version) 
			
			// сохранить переданные параметры
			: _decryption(decryption), _version(version), _cbBlock(_decryption->BlockSize()) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return CTS().GetDecryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// расшифровать данные
		protected: virtual size_t Decrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// расшифровать непоследние блоки
			if (!last) return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// завершить обработку данных
			if (_version == 3) return DecryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// завершить обработку данных
			else return DecryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// завершить обработку данных
		private: WINCRYPT_CALL size_t DecryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// завершить обработку данных
		private: size_t DecryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
		{
			// выполнить обработку некратного блока
			if ((cbData % _cbBlock) != 0) return DecryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// кратный случай совместим с обычным режимом
			return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CBC с дополнением CTS. Последний блок обязательно 
	// должен быть передан через Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class EncryptionCBC : public Crypto::Encryption
    {
		// режим зашифрования данных
		private: std::shared_ptr<ITransform> _encryption; int _version; size_t _cbBlock; 

        // конструктор
		public: EncryptionCBC(const std::shared_ptr<ITransform>& encryption, int version) 
			
			// сохранить переданные параметры 
			: _encryption(encryption), _version(version), _cbBlock(_encryption->BlockSize()) {}

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return CTS().GetEncryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// зашифровать данные
		protected: virtual size_t Encrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// зашифровать непоследние блоки
			if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// завершить обработку данных
			if (_version == 3) return EncryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// завершить обработку данных
			else return EncryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// завершить обработку данных
		private: WINCRYPT_CALL size_t EncryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// завершить обработку данных
		private: size_t EncryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
			// выполнить обработку некратного блока
			if ((cbData % _cbBlock) != 0) return EncryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// кратный случай совместим с обычным режимом
			return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CBC с дополнением CTS. Последний блок обязательно 
	// должен быть передан через Finish. Синхропосылка требуется для данных 
	// меньше двух блоков, но больше одного блока. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class DecryptionCBC : public Crypto::Decryption
    {
		// режим расшифрования данных и регистр обратной связи
		private: std::shared_ptr<ITransform> _decryption; int _version; 
		// синхропосылка
		private: std::vector<uint8_t> _iv; size_t _cbBlock; 

        // конструктор
		public: DecryptionCBC(const std::shared_ptr<ITransform>& decryption, int version, const std::vector<uint8_t>& iv)

			// сохранить переданные параметры 
			: _decryption(decryption), _version(version), _cbBlock(_decryption->BlockSize()), _iv(iv) {} private: 

		// идентификатор дополнения
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // размер блока алгоритма
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// требуемый размер буфера
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// требуемый размер буфера
			return CTS().GetDecryptLength(cb, _cbBlock); 
		}
		// инициализировать алгоритм
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// инициализировать алгоритм
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// расшифровать данные
		protected: virtual size_t Decrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// сохранить регистр обратной связи
			if (!last) { if (cbData > 0) memcpy(&_iv[0], (uint8_t*)pvData + cbData - _cbBlock, _cbBlock); 

				// расшифровать непоследние блоки
				return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 
			}
			// завершить обработку данных
			if (_version == 3) return DecryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// завершить обработку данных
			else return DecryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// завершить обработку данных
		private: WINCRYPT_CALL size_t DecryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// завершить обработку данных
		private: size_t DecryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
			// выполнить обработку некратного блока
			if ((cbData % _cbBlock) != 0) return DecryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// кратный случай совместим с обычным режимом
			return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
}; 
}}

