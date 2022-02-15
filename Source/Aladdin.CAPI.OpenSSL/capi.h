#pragma once
#include "ui.h"
#include <wincrypt.h>

namespace Aladdin { namespace CAPI { namespace OpenSSL { namespace Windows
{
// —пособы взаимодействи€ с пользователем
UI_METHOD* UI_Console(PCSTR); UI_METHOD* UI_GUI(HWND, PCSTR); 

///////////////////////////////////////////////////////////////////////////////
// —пособ аутентификации с использование диалоговых окон
///////////////////////////////////////////////////////////////////////////////
class ConsoleAuthentication : public PasswordAuthentication
{
	// способ взаимодействи€ с пользователем
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// способ взаимодействи€ с пользователем
		return UI_Console(szTarget); 
	}
};

class DialogAuthentication : public PasswordAuthentication
{
	// конструктор/деструктор
	public: DialogAuthentication(HWND hwnd) { this->hwnd = hwnd; } private: HWND hwnd; 

	// способ взаимодействи€ с пользователем
	public: virtual UI_METHOD* CreateInputMethod(const char* szTarget) const override
	{
		// способ взаимодействи€ с пользователем
		return UI_GUI(hwnd, szTarget); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Ћичный ключ
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public OpenSSL::PrivateKey
{
	// тип и им€ им€ провайдера; 
	private: DWORD providerType; std::string provider; 
	// область видимости и им€ контейнера
	private: DWORD scope; std::string container; DWORD keyType; 
	// используемый плагин и личный ключ
	private: ENGINE* pEngine; EVP_PKEY* pPrivateKey; X509* pCertificateX509; 

	// конструктор
	public: PrivateKey(const class Provider& provider, PCSTR szContainer, 
		DWORD keyType, const std::vector<unsigned char>& certificate
	);  
	// деструктор
	public: virtual ~PrivateKey(); 

	// строковое представление
	public: virtual std::wstring ToString() const override; 

	// св€зать сертификат с ключом
	public: virtual void SetCertificateContext(PCCERT_CONTEXT pCertContext) const override; 

	// сертификат открытого ключа и личный ключ
	protected: virtual X509*     GetCertificateObject() const override { return pCertificateX509; }
	protected: virtual EVP_PKEY* GetPrivateKeyObject () const override { return pPrivateKey;      } 
};

///////////////////////////////////////////////////////////////////////////////
// ѕровайдер CryptoAPI CSP
///////////////////////////////////////////////////////////////////////////////
class Provider
{
	// тип и им€ провайдера
	private: DWORD providerType; private: std::string providerName;  
	// область видимости и описатель провайдера
	private: DWORD scope; private: HCRYPTPROV hProvider;

	// конструктор
	public: Provider(ENGINE* pEngine, DWORD providerType, PCSTR szName, DWORD scope); 
	// деструктор
	public: ~Provider(); private: ENGINE* pEngine; 

	// используемый плагин
	public: ENGINE* GetEngine() const { return pEngine; }

	// им€ провайдера
	public: std::string GetName() const { return providerName; }
	// тип провайдера
	public: DWORD GetType() const { return providerType; }
	// область видимости
	public: DWORD GetScope() const { return scope; }

	// найти сертификат дл€ ключа
	public: std::vector<BYTE> FindCertificate(PCSTR szContainer, DWORD keyType) const; 
	// найти ключ по сертификату
	public: DWORD FindContainerKey(
		PCSTR szContainer, const std::vector<BYTE>& certificate) const; 

    // перечислить личные ключи    
	public: void EnumeratePrivateKeys(KeyUsage keyUsage, 
		std::vector<std::string>& certificates, 
		std::vector<std::wstring>& privateKeys) const;
}; 

}}}}

