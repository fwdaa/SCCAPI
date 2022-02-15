#pragma once
#include "ui.h"
#include <wincrypt.h>

namespace Aladdin { namespace CAPI { namespace OpenSSL { namespace Windows
{
// ������� �������������� � �������������
UI_METHOD* UI_Console(PCSTR); UI_METHOD* UI_GUI(HWND, PCSTR); 

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � ������������� ���������� ����
///////////////////////////////////////////////////////////////////////////////
class ConsoleAuthentication : public PasswordAuthentication
{
	// ������ �������������� � �������������
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// ������ �������������� � �������������
		return UI_Console(szTarget); 
	}
};

class DialogAuthentication : public PasswordAuthentication
{
	// �����������/����������
	public: DialogAuthentication(HWND hwnd) { this->hwnd = hwnd; } private: HWND hwnd; 

	// ������ �������������� � �������������
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// ������ �������������� � �������������
		return UI_GUI(hwnd, szTarget); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public OpenSSL::PrivateKey
{
	// ��� � ��� ��� ����������; 
	private: DWORD providerType; std::string provider; 
	// ������� ��������� � ��� ����������
	private: DWORD scope; std::string container; DWORD keyType; 
	// ������������ ������ � ������ ����
	private: ENGINE* pEngine; EVP_PKEY* pPrivateKey; X509* pCertificateX509; 

	// �����������
	public: PrivateKey(const class Provider& provider, PCSTR szContainer, 
		DWORD keyType, const std::vector<unsigned char>& certificate
	);  
	// ����������
	public: virtual ~PrivateKey(); 

	// ��������� �������������
	public: virtual std::wstring ToString() const override; 

	// ������� ���������� � ������
	public: virtual void SetCertificateContext(PCCERT_CONTEXT pCertContext) const override; 

	// ���������� ��������� ����� � ������ ����
	protected: virtual X509*     GetCertificateObject() const override { return pCertificateX509; }
	protected: virtual EVP_PKEY* GetPrivateKeyObject () const override { return pPrivateKey;      } 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� CryptoAPI CSP
///////////////////////////////////////////////////////////////////////////////
class Provider
{
	// ��� � ��� ����������
	private: DWORD providerType; private: std::string providerName;  
	// ������� ��������� � ��������� ����������
	private: DWORD scope; private: HCRYPTPROV hProvider;

	// �����������
	public: Provider(ENGINE* pEngine, DWORD providerType, PCSTR szName, DWORD scope); 
	// ����������
	public: ~Provider(); private: ENGINE* pEngine; 

	// ������������ ������
	public: ENGINE* GetEngine() const { return pEngine; }

	// ��� ����������
	public: std::string GetName() const { return providerName; }
	// ��� ����������
	public: DWORD GetType() const { return providerType; }
	// ������� ���������
	public: DWORD GetScope() const { return scope; }

	// ����� ���������� ��� �����
	public: std::vector<BYTE> FindCertificate(PCSTR szContainer, DWORD keyType) const; 
	// ����� ���� �� �����������
	public: DWORD FindContainerKey(
		PCSTR szContainer, const std::vector<BYTE>& certificate) const; 

    // ����������� ������ �����    
	public: void EnumeratePrivateKeys(KeyUsage keyUsage, 
		std::vector<std::string>& certificates, 
		std::vector<std::wstring>& privateKeys) const;
}; 

}}}}

