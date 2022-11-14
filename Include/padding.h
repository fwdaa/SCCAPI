#pragma once
#include "crypto.h"

namespace Crypto { namespace Padding {

///////////////////////////////////////////////////////////////////////////////
// ���������� ����������
///////////////////////////////////////////////////////////////////////////////
class None : public BlockPadding
{ 
    // ������������� ����������
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_NONE; }

	// ��������� ������ ������
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ������ ������
		return (cb % cbBlock) ? size_t(-1) : cb; 
	}
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ������ ������
		return (cb % cbBlock) ? size_t(-1) : cb; 
	}
    // �������� ������������ ������
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // ������� ������� �������
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

		// �������� ������������ ������
        return (transform) ? transform : encryption; 
    }
    // �������� ������������� ������
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // ������� ������� �������
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // �������� ������������� ������
       return (transform) ? transform : decryption; 
    }
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� PKCS
///////////////////////////////////////////////////////////////////////////////
class PKCS5 : public BlockPadding
{ 
    // ������������� ����������
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_PKCS5; }

	// ��������� ������ ������
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ������ �� ������� �����
		return (cb + cbBlock - 1) / cbBlock * cbBlock; 
	}
	// ��������� ������ ������
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ��������� ������� �����
		return (cb > 0 && (cb % cbBlock) == 0) ? (cb - 1) : size_t(-1); 
	}
    // �������� ������������ ������
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // ������� ������� �������
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

        // �������� ������������ ������
        return (transform) ? transform : std::shared_ptr<ITransform>(new Encryption(encryption)); 
    }
    // �������� ������������� ������
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // ������� ������� �������
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // �������� ������������� ������
       return (transform) ? transform : std::shared_ptr<ITransform>(new Decryption(decryption)); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������ � �����������
    ///////////////////////////////////////////////////////////////////////////////
	public: class Encryption : public Crypto::Encryption
    {
		// ����� ������������ ������
		private: std::shared_ptr<ITransform> _encryption; size_t _cbBlock; 

		// �����������
		public: Encryption(const std::shared_ptr<ITransform>& encryption) 
			
			// ��������� ���������� ���������
			: _encryption(encryption), _cbBlock(_encryption->BlockSize()) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_PKCS5; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return PKCS5().GetEncryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// ���������� ������
		public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
		{
			// ����������� ������ �����
			return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, nullptr);
		}
		// ��������� ��������� ������
		public: WINCRYPT_CALL virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override; 

		// ����������� ������
		protected: WINCRYPT_CALL virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) override; 

		// ��������� ����� ������������ ��� ���������� �������
		protected: virtual void Fill(void* pvBuffer, size_t cbBuffer, size_t pad) const 
		{
			// ��������� ����� ������������
			for (size_t i = 0; i < cbBuffer; i++) ((uint8_t*)pvBuffer)[i] = (uint8_t)pad;
		}
    };
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������� � �����������
    ///////////////////////////////////////////////////////////////////////////////
	public: class Decryption : public Crypto::Decryption
    {
		// ����� ������������� ������
		private: std::shared_ptr<ITransform> _decryption; size_t _cbBlock; 

        // �����������
		public: Decryption(const std::shared_ptr<ITransform>& decryption) 
			
			// ��������� ���������� ��������� 
			: _decryption(decryption), _cbBlock(_decryption->BlockSize()) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_PKCS5; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return PKCS5().GetDecryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// ������������ ������
		protected: WINCRYPT_CALL virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 

		// ��������� ������������ ������
		protected: bool FillCheck(void* pvBuffer, size_t cbBuffer, uint8_t pad) const
		{
			// ��� ���� ����������� ������
			for (size_t i = 0; i < cbBuffer; i++)
			{
				// ��������� ���������� �����
				if (((const uint8_t*)pvBuffer)[i] != pad) return false; 
			}
			return true; 
		}
    }; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� ISO10126
///////////////////////////////////////////////////////////////////////////////
class ISO10126 : public BlockPadding
{ 
	// �����������
	public: ISO10126(const std::shared_ptr<IRand>& rand) 
		
		// ��������� ���������� ��������� 
		: _rand(rand) {} private: std::shared_ptr<IRand> _rand; 
			
    // ������������� ����������
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_ISO10126; }

	// ��������� ������ ������
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ������ �� ������� �����
		return (cb + cbBlock - 1) / cbBlock * cbBlock; 
	}
	// ��������� ������ ������
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ��������� ������� �����
		return (cb > 0 && (cb % cbBlock) == 0) ? (cb - 1) : size_t(-1); 
	}
    // �������� ������������ ������
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // ������� ������� �������
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

        // �������� ������������ ������
        return (transform) ? transform : std::shared_ptr<ITransform>(new Encryption(encryption, _rand)); 
    }
    // �������� ������������� ������
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // ������� ������� �������
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

	   // �������� ������������� ������
       return (transform) ? transform : std::shared_ptr<ITransform>(new Decryption(decryption)); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������ � �����������
    ///////////////////////////////////////////////////////////////////////////////
	private: class Encryption : public PKCS5::Encryption
    {
		// ��������� ��������� ������
		private: std::shared_ptr<IRand> _rand;

		// �����������
		public: Encryption(const std::shared_ptr<ITransform>& encryption, const std::shared_ptr<IRand>& rand) 
			
			// ��������� ���������� ���������
			: PKCS5::Encryption(encryption), _rand(rand) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_ISO10126; }

		// ��������� ����� ������������ ��� ���������� �������
		protected: virtual void Fill(void* pvBuffer, size_t cbBuffer, uint8_t) const 
		{
			// ������������� ��������� ������ 
			_rand->Generate(pvBuffer, cbBuffer); 
		}
    };
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������� � �����������
    ///////////////////////////////////////////////////////////////////////////////
	private: class Decryption : public PKCS5::Decryption
    {
        // �����������
		public: Decryption(const std::shared_ptr<ITransform>& decryption) : PKCS5::Decryption(decryption) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_ISO10126; }

		// ��������� ������������ ������
		protected: bool FillCheck(void* pvBuffer, size_t cbBuffer, uint8_t pad) const { return true; }
    }; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� CTS. ������ �� ����� ���� ������ ������ �����. 
///////////////////////////////////////////////////////////////////////////////
class CTS : public BlockPadding
{ 
	// �����������
	public: CTS(int version = 2) : _version(version) {} private: int _version; 

    // ������������� ����������
	public: virtual uint32_t ID() const override { return CRYPTO_PADDING_CTS; }

	// ��������� ������ ������
	public: virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ����������� ������ ������
		return (cb < cbBlock) ? size_t(-1) : cb; 
	}
	// ��������� ������ ������
	public: virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const override 
	{
		// ��������� ����������� ������ ������
		return (cb < cbBlock) ? size_t(-1) : cb; 
	}
    // �������� ������������ ������
	public: virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>& encryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
        // ������� ������� �������
        std::shared_ptr<ITransform> transform = BlockPadding::CreateEncryption(encryption, mode, iv); 

		// ��������� ������������ �������������� 
		if (transform) return transform; if (mode == CRYPTO_BLOCK_MODE_ECB)
		{
			// ������� �������� ������������ ������
			return std::shared_ptr<ITransform>(new EncryptionECB(encryption, _version));
		}
		// ������� �������� ������������ ������
		else return std::shared_ptr<ITransform>(new EncryptionCBC(encryption, _version));
    }
    // �������� ������������� ������
    public: virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>& decryption, 
		uint32_t mode, const std::vector<uint8_t>& iv) const override
    {
       // ������� ������� �������
       std::shared_ptr<ITransform> transform = BlockPadding::CreateDecryption(decryption, mode, iv); 

		// ��������� ������������ �������������� 
		if (transform) return transform; if (mode == CRYPTO_BLOCK_MODE_ECB)
		{
			// ������� �������� ������������� ������
			return std::shared_ptr<ITransform>(new DecryptionECB(decryption, _version));
		}
		// ������� �������� ������������� ������
		else return std::shared_ptr<ITransform>(new DecryptionCBC(decryption, _version, iv));
    }
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������ ECB � ����������� CTS. ��������� ���� ����������� 
	// ������ ���� ������� ����� Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class EncryptionECB : public Crypto::Encryption
    {
		// ����� ������������ ������ 
		private: std::shared_ptr<ITransform> _encryption; int _version; size_t _cbBlock; 

        // �����������
		public: EncryptionECB(const std::shared_ptr<ITransform>& encryption, int version) 
			
			// ��������� ���������� ���������
			: _encryption(encryption), _version(version), _cbBlock(_encryption->BlockSize()) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return CTS().GetEncryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// ����������� ������
		protected: virtual size_t Encrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// ����������� ����������� �����
			if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			if (_version == 3) return EncryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			else return EncryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// ��������� ��������� ������
		private: WINCRYPT_CALL size_t EncryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// ��������� ��������� ������
		private: size_t EncryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
		    // ��������� ��������� ���������� �����
			if ((cbData % _cbBlock) != 0) return EncryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// ������� ������ ��������� � ������� �������
			return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������� ECB � ����������� CTS. ��������� ���� ����������� 
	// ������ ���� ������� ����� Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class DecryptionECB : public Crypto::Decryption
    {
		// ����� ������������� ������ � ��������� ���� ������
		private: std::shared_ptr<ITransform> _decryption; int _version; size_t _cbBlock; 

        // �����������
		public: DecryptionECB(const std::shared_ptr<ITransform>& decryption, int version) 
			
			// ��������� ���������� ���������
			: _decryption(decryption), _version(version), _cbBlock(_decryption->BlockSize()) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return CTS().GetDecryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// ������������ ������
		protected: virtual size_t Decrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// ������������ ����������� �����
			if (!last) return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			if (_version == 3) return DecryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			else return DecryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// ��������� ��������� ������
		private: WINCRYPT_CALL size_t DecryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// ��������� ��������� ������
		private: size_t DecryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer) 
		{
			// ��������� ��������� ���������� �����
			if ((cbData % _cbBlock) != 0) return DecryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// ������� ������ ��������� � ������� �������
			return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������ CBC � ����������� CTS. ��������� ���� ����������� 
	// ������ ���� ������� ����� Finish. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class EncryptionCBC : public Crypto::Encryption
    {
		// ����� ������������ ������
		private: std::shared_ptr<ITransform> _encryption; int _version; size_t _cbBlock; 

        // �����������
		public: EncryptionCBC(const std::shared_ptr<ITransform>& encryption, int version) 
			
			// ��������� ���������� ��������� 
			: _encryption(encryption), _version(version), _cbBlock(_encryption->BlockSize()) {}

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return CTS().GetEncryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Encryption::Init(key); return _encryption->Init(key); 
		}
		// ����������� ������
		protected: virtual size_t Encrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// ����������� ����������� �����
			if (!last) return _encryption->Update(pvData, cbData, pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			if (_version == 3) return EncryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			else return EncryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// ��������� ��������� ������
		private: WINCRYPT_CALL size_t EncryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// ��������� ��������� ������
		private: size_t EncryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
			// ��������� ��������� ���������� �����
			if ((cbData % _cbBlock) != 0) return EncryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// ������� ������ ��������� � ������� �������
			return _encryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
    ///////////////////////////////////////////////////////////////////////////////
    // ����� ������������� CBC � ����������� CTS. ��������� ���� ����������� 
	// ������ ���� ������� ����� Finish. ������������� ��������� ��� ������ 
	// ������ ���� ������, �� ������ ������ �����. 
    ///////////////////////////////////////////////////////////////////////////////
	private: class DecryptionCBC : public Crypto::Decryption
    {
		// ����� ������������� ������ � ������� �������� �����
		private: std::shared_ptr<ITransform> _decryption; int _version; 
		// �������������
		private: std::vector<uint8_t> _iv; size_t _cbBlock; 

        // �����������
		public: DecryptionCBC(const std::shared_ptr<ITransform>& decryption, int version, const std::vector<uint8_t>& iv)

			// ��������� ���������� ��������� 
			: _decryption(decryption), _version(version), _cbBlock(_decryption->BlockSize()), _iv(iv) {} private: 

		// ������������� ����������
		public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_CTS; }
        // ������ ����� ���������
		public: virtual size_t BlockSize() const override { return _cbBlock; }

		// ��������� ������ ������
		protected: virtual size_t GetLength(size_t cb) const override
		{
			// ��������� ������ ������
			return CTS().GetDecryptLength(cb, _cbBlock); 
		}
		// ���������������� ��������
		public: virtual size_t Init(const ISecretKey& key) override 
		{ 
			// ���������������� ��������
			Crypto::Decryption::Init(key); return _decryption->Init(key); 
		}
		// ������������ ������
		protected: virtual size_t Decrypt(const void* pvData, 
			size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*) override
		{
			// ��������� ������� �������� �����
			if (!last) { if (cbData > 0) memcpy(&_iv[0], (uint8_t*)pvData + cbData - _cbBlock, _cbBlock); 

				// ������������ ����������� �����
				return _decryption->Update(pvData, cbData, pvBuffer, cbBuffer); 
			}
			// ��������� ��������� ������
			if (_version == 3) return DecryptSP3((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 

			// ��������� ��������� ������
			else return DecryptSP2((const uint8_t*)pvData, cbData, (uint8_t*)pvBuffer, cbBuffer); 
		}
		// ��������� ��������� ������
		private: WINCRYPT_CALL size_t DecryptSP3(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer); 
		// ��������� ��������� ������
		private: size_t DecryptSP2(const uint8_t* pbData, size_t cbData, uint8_t* pbBuffer, size_t cbBuffer)
		{
			// ��������� ��������� ���������� �����
			if ((cbData % _cbBlock) != 0) return DecryptSP3(pbData, cbData, pbBuffer, cbBuffer); 

			// ������� ������ ��������� � ������� �������
			return _decryption->Update(pbData, cbData, pbBuffer, cbBuffer); 
		}
	}; 
}; 
}}

