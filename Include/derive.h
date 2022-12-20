#pragma once
#include "crypto.h"

namespace Crypto { 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
class KeyDeriveTruncate : public IKeyDerive
{ 
	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"TRUNCATE"; }

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHash : public IKeyDerive
{ 
	// ��������� � �������� �����������
	private: const IProvider* _pProvider; std::wstring _hashName; 
	// ��������� ���������
	private: std::vector<uint8_t> _prepend; std::vector<uint8_t> _append; 

	// �����������
	public: KeyDeriveHash(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHash(const IProvider& provider, const wchar_t* szHashName, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _pProvider(&provider), _hashName(szHashName), _prepend(prepend), _append(append) {}

	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"HASH"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Prepend() const { return _prepend; }	
	public: const std::vector<uint8_t>& Append () const { return _append;  }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHMAC : public IKeyDerive
{ 
	// ��������� � �������� �����������
	private: const IProvider* _pProvider; std::wstring _hashName; 
	// ��������� ���������
	private: std::vector<uint8_t> _prepend; std::vector<uint8_t> _append; 
	// ������� ������������� ����� 
	private: std::vector<uint8_t> _key; bool _useKey; 

	// �����������
	public: KeyDeriveHMAC(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHMAC(const IProvider& provider, const wchar_t* szHashName, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _pProvider(&provider), _hashName(szHashName), _useKey(false), _prepend(prepend), _append(append) {}

	// �����������
	public: KeyDeriveHMAC(const IProvider& provider, const wchar_t* szHashName, const std::vector<uint8_t>& key, 
		const std::vector<uint8_t>& prepend, const std::vector<uint8_t>& append) 
		
		// ��������� ���������� ���������
		: _pProvider(&provider), _hashName(szHashName), _key(key), _useKey(true), _prepend(prepend), _append(append) {}

	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"HMAC"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ������������ ����
	public: const std::vector<uint8_t>* Key() const { return _useKey ? &_key : nullptr; }

	// ��������� ���������
	public: const std::vector<uint8_t>& Prepend() const { return _prepend; }	
	public: const std::vector<uint8_t>& Append () const { return _append;  }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveSP800_56A : public IKeyDerive
{
	// ���������, �������� ����������� � �������������� ������
	private: const IProvider* _pProvider; std::wstring _hashName; std::vector<uint8_t> _generic; 

	// �����������
	public: KeyDeriveSP800_56A(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveSP800_56A(const IProvider& provider, const wchar_t* szHashName, const std::vector<uint8_t>& generic) 

		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName), _generic(generic) {}

	// �����������
	public: KeyDeriveSP800_56A(const IProvider& provider, const wchar_t* szHashName, const std::vector<uint8_t>& algID, 
		const std::vector<uint8_t>& partyUInfo, const std::vector<uint8_t>& partyVInfo, 
		const std::vector<uint8_t>& suppPubInfo, const std::vector<uint8_t>& suppPrivInfo) 
		
		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName)
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
	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"SP800_56A_CONCAT"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Generic() const { return _generic; }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDeriveSP800_108 : public IKeyDerive
{
	// ���������, �������� ����������� � �������������� ������
	private: const IProvider* _pProvider; std::wstring _hashName; std::vector<uint8_t> _generic; 

	// �����������
	public: KeyDeriveSP800_108(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveSP800_108(const IProvider& provider, const wchar_t* szHashName, const std::vector<uint8_t>& generic) 

		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName), _generic(generic) {}

	// �����������
	public: KeyDeriveSP800_108(const IProvider& provider, const wchar_t* szHashName, 
		const std::vector<uint8_t>& label, const std::vector<uint8_t>& context)
		
		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName)
	{
		// ���������� ����� ������ ������
		size_t cb = label.size() + 1 + context.size(); 

		// �������� ����� ���������� �������
		_generic.resize(cb); uint8_t* ptr = &_generic[0]; 

		// ����������� ��������
		if (label  .size() != 0) memcpy(ptr, &label  [0], label  .size()); ptr += label  .size() + 1; 
		if (context.size() != 0) memcpy(ptr, &context[0], context.size()); ptr += context.size(); 
	}
	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"SP800_108_CTR_HMAC"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& Generic() const { return _generic; }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDerivePBKDF2 : public IKeyDerive
{
	// ��������� � �������� �����������
	private: const IProvider* _pProvider; std::wstring _hashName; 
	// ��������� ���������
	private: std::vector<uint8_t> _salt; uint32_t _iterations;

	// �����������
	public: KeyDerivePBKDF2(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDerivePBKDF2(const IProvider& provider, const wchar_t* szHashName, const std::vector<uint8_t>& salt, uint32_t iterations)
		
		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName), _salt(salt), _iterations(iterations ? iterations : 10000) {} 

	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"PBKDF2"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� �������� 
	public: const std::vector<uint8_t>& Salt() const { return _salt; }	
	// ����� ��������
	public: uint32_t Iterations() const { return _iterations; }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

class KeyDeriveHKDF : public IKeyDerive
{
	// ��������� � �������� �����������
	private: const IProvider* _pProvider; std::wstring _hashName; 
	// ��������� ���������
	private: std::vector<uint8_t> _salt; std::vector<uint8_t> _info;

	// �����������
	public: KeyDeriveHKDF(const IProvider& provider, const Parameter* pParameters, size_t cParameters); 
	// �����������
	public: KeyDeriveHKDF(const IProvider& provider, const wchar_t* szHashName, 
		const std::vector<uint8_t>& salt, const std::vector<uint8_t>& info)
		
		// ��������� ���������� ��������� 
		: _pProvider(&provider), _hashName(szHashName), _salt(salt), _info(info) {}

	// ��� ���������
	public: virtual const wchar_t* Name() const override { return L"HKDF"; }

	// ��� ��������� ����������� 
	public: const wchar_t* HashName() const { return _hashName.c_str(); }

	// ��������� ���������
	public: const std::vector<uint8_t>& SaltHKDF() const { return _salt; }	
	// ����� ��������
	public: const std::vector<uint8_t>& InfoHKDF() const { return _info; }	

	// ����������� ����
	public: virtual std::vector<uint8_t> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};
}

