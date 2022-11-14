#pragma once
#include "crypto.h"

namespace Crypto { 

// ������� ��� ���������
const wchar_t* BufferGetString(const Parameter* pParameters, size_t cParameters, size_t paramID); 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive
{ 
	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const { return true; }

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const IProvider& provider, const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const; 

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const = 0; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// �����������
	public: static std::shared_ptr<KeyDeriveTruncate> Create(const Parameter*, size_t)
	{
		// ������� �������� 
		return std::shared_ptr<KeyDeriveTruncate>(new KeyDeriveTruncate()); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHash : public KeyDerive
{ 
	// �������� ����������� � ��������� ���������
	private: std::wstring _hashName; std::vector<uint8_t> _prepend; std::vector<uint8_t> _append; 

	// �����������
	public: KeyDeriveHash(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHash(const wchar_t* szHashName, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _hashName(szHashName), _prepend(prepend), _append(append) {}

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Prepend() const { return _prepend; }	
	public: const std::vector<uint8_t>& Append () const { return _append;  }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDerive
{ 
	// �������� ����������� � ��������� ���������
	private: std::wstring _hashName; std::vector<uint8_t> _prepend; std::vector<uint8_t> _append; 
	// ������� ������������� ����� 
	private: std::vector<uint8_t> _key; bool _useKey; 

	// �����������
	public: KeyDeriveHMAC(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHMAC(const wchar_t* szHashName, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _hashName(szHashName), _useKey(false), _prepend(prepend), _append(append) {}

	// �����������
	public: KeyDeriveHMAC(const wchar_t* szHashName, const std::vector<uint8_t>& key, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _hashName(szHashName), _key(key), _useKey(true), _prepend(prepend), _append(append) {}

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ������������ ����
	public: const std::vector<uint8_t>* Key() const { return _useKey ? &_key : nullptr; }

	// ��������� ���������
	public: const std::vector<uint8_t>& Prepend() const { return _prepend; }	
	public: const std::vector<uint8_t>& Append () const { return _append;  }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveSP800_56A : public KeyDerive
{
	// ���������, �������� ����������� � �������������� ������
	private: std::wstring _hashName; std::vector<uint8_t> _generic; 

	// �����������
	public: KeyDeriveSP800_56A(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveSP800_56A(const wchar_t* szHashName, const std::vector<uint8_t>& generic) 

		// ��������� ���������� ��������� 
		: _hashName(szHashName), _generic(generic) {}

	// �����������
	public: KeyDeriveSP800_56A(const wchar_t* szHashName, const std::vector<uint8_t>& algID, 
		const std::vector<uint8_t>& partyUInfo, const std::vector<uint8_t>& partyVInfo, 
		const std::vector<uint8_t>& suppPubInfo, const std::vector<uint8_t>& suppPrivInfo) : _hashName(szHashName)
	{
		// ���������� ����� ������ ������
		size_t cb = algID.size() + partyUInfo.size() + partyVInfo.size() + suppPubInfo.size() + suppPrivInfo.size(); 

		// �������� ����� ���������� �������
		_generic.resize(cb); if (cb == 0) return; uint8_t* ptr = &_generic[0]; 

		// ����������� ��������
		if (algID       .size() != 0) memcpy(ptr, &algID       [0], algID       .size()); ptr += algID       .size();
		if (partyUInfo  .size() != 0) memcpy(ptr, &partyUInfo  [0], partyUInfo  .size()); ptr += partyUInfo  .size();
		if (partyVInfo  .size() != 0) memcpy(ptr, &partyVInfo  [0], partyVInfo  .size()); ptr += partyVInfo  .size();
		if (suppPubInfo .size() != 0) memcpy(ptr, &suppPubInfo [0], suppPubInfo .size()); ptr += suppPubInfo .size();
		if (suppPrivInfo.size() != 0) memcpy(ptr, &suppPrivInfo[0], suppPrivInfo.size()); ptr += suppPrivInfo.size();
	}
	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Generic() const { return _generic; }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDeriveSP800_108 : public KeyDerive
{
	// ���������, �������� ����������� � �������������� ������
	private: std::wstring _hashName; std::vector<uint8_t> _generic; 

	// �����������
	public: KeyDeriveSP800_108(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveSP800_108(const wchar_t* szHashName, const std::vector<uint8_t>& generic) 

		// ��������� ���������� ��������� 
		: _hashName(szHashName), _generic(generic) {}

	// �����������
	public: KeyDeriveSP800_108(const wchar_t* szHashName, 
		const std::vector<uint8_t>& label, const std::vector<uint8_t>& context)
		
		// ��������� ���������� ��������� 
		: _hashName(szHashName)
	{
		// ���������� ����� ������ ������
		size_t cb = label.size() + 1 + context.size(); 

		// �������� ����� ���������� �������
		_generic.resize(cb); uint8_t* ptr = &_generic[0]; 

		// ����������� ��������
		if (label  .size() != 0) memcpy(ptr, &label  [0], label  .size()); ptr += label  .size() + 1; 
		if (context.size() != 0) memcpy(ptr, &context[0], context.size()); ptr += context.size(); 
	}
	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Generic() const { return _generic; }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDerivePBKDF2 : public KeyDerive
{
	// ���������, �������� ����������� 
	private: std::wstring _hashName; std::vector<uint8_t> _salt; uint32_t _iterations;

	// �����������
	public: KeyDerivePBKDF2(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDerivePBKDF2(const wchar_t* szHashName, const std::vector<uint8_t>& salt, uint32_t iterations)
		
		// ��������� ���������� ��������� 
		: _hashName(szHashName), _salt(salt), _iterations(iterations ? iterations : 10000) {} 

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� �������� 
	public: const std::vector<uint8_t>& Salt() const { return _salt; }	
	// ����� ��������
	public: uint32_t Iterations() const { return _iterations; }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDeriveHKDF : public KeyDerive
{
	// ���������, �������� ����������� 
	private: std::wstring _hashName; std::vector<uint8_t> _salt; std::vector<uint8_t> _info;

	// �����������
	public: KeyDeriveHKDF(const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHKDF(const wchar_t* szHashName, 
		const std::vector<uint8_t>& salt, const std::vector<uint8_t>& info)
		
		// ��������� ���������� ��������� 
		: _hashName(szHashName), _salt(salt), _info(info) {}

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& SaltHKDF() const { return _salt; }	
	// ����� ��������
	public: const std::vector<uint8_t>& InfoHKDF() const { return _info; }	

	// ������� ������� ���������
	public: virtual bool Exists(const IProvider& provider) const override
	{
		// ��������� ������� ���������
		return (bool)provider.CreateHash(_hashName.c_str(), 0); 
	}
	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(const IProvider& provider, 
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};
}

