#include "stdafx.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <openssl/crypto.h>

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������
///////////////////////////////////////////////////////////////////////////////
static std::wstring Test(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> > pFactories, 
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, 
	const std::shared_ptr<Aladdin::CAPI::IPrivateKey>& pPrivateKey, void* hwnd)
{
    // �������� ����� ��� ������������
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
    // ������� ���������� ������� ������������� �����
    Aladdin::CAPI::KeyUsage keyUsageMask = (Aladdin::CAPI::KeyUsage)
		(Aladdin::CAPI::KeyUsage::KeyEncipherment | 
		 Aladdin::CAPI::KeyUsage::KeyAgreement); 

    // ������� ���������� ������� ������������� �����
    Aladdin::CAPI::KeyUsage signMask = (Aladdin::CAPI::KeyUsage)
		(Aladdin::CAPI::KeyUsage::DataSignature			| 
		 Aladdin::CAPI::KeyUsage::CertificateSignature	| 
		 Aladdin::CAPI::KeyUsage::CrlSignature); 

    // �������� ���������� ������� �����            
	std::shared_ptr<Aladdin::CAPI::ICertificate> pCertificate = pPrivateKey->Certificate(); 

	// ������������ ����������
	std::vector<unsigned char> certificateEncoded = pPrivateKey->Certificate()->Encoded(); 

	// ������������ ������ ����
	std::wstring encodedPrivateKey = pPrivateKey->ToString(); 

	// ������� ������ ��� ������������
	std::vector<std::shared_ptr<Aladdin::CAPI::ICertificate> > pCertificates(pFactories.size()); 

	// ��� ���� ������ ����������
	for (size_t i = 0; i < pFactories.size(); i++)
	{
		// ������������� ����������
		pCertificates[i] = pFactories[i]->DecodeCertificate(
			&certificateEncoded[0], certificateEncoded.size()
		); 
		// �������� ��� ��������
		std::shared_ptr<Aladdin::CAPI::IDistinctName> pIssuer = pCertificates[i]->Issuer(); 
		std::vector<unsigned char> issuerEncoded = pIssuer->Encoded(); 
		std::wstring issuerName = pIssuer->ToString(); 

		// �������� ��� ��������
		std::shared_ptr<Aladdin::CAPI::IDistinctName> pSubject = pCertificates[i]->Subject(); 
		std::vector<unsigned char> subjectEncoded = pSubject->Encoded(); 
		std::wstring subjectName = pSubject->ToString(); 
	}
	// �������� ������ ������������� �����
	Aladdin::CAPI::KeyUsage keyUsage = pCertificate->KeyUsage(); 

	// ��� ����������� �������
	if ((keyUsage & signMask) != 0)
	{
		// ��������� ������
		std::vector<unsigned char> outputData = pPrivateKey->SignData(data, sizeof(data)); 

		// ��� ���� ������ ����������
		for (size_t i = 0; i < pFactories.size(); i++)
		{
			// ����� ���������� ��� �������� �������
			std::shared_ptr<Aladdin::CAPI::ICertificate> pFindCertificate = 
				pFactories[i]->FindVerifyCertificate(
					&outputData[0], outputData.size(), &certificateEncoded, 1
			); 
			// ��������� ������� �����
			if (!pFindCertificate) throw std::out_of_range(""); 

			// ��������� ������� ������
			std::vector<unsigned char> checked = 
				pFindCertificate->VerifySign(&outputData[0], outputData.size()); 

			// ��������� ���������� �������� ������
			if (checked.size() != sizeof(data)) throw std::out_of_range(""); 

			// ��������� ���������� ������
			if (memcmp(&checked[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
		}
	}
	// ��� ����������� ����������
	if ((keyUsage & keyUsageMask) != 0)
	{
		// ��� ���� ������ ����������
		for (size_t i = 0; i < pFactories.size(); i++)
		{
			// ����������� ������
			std::vector<unsigned char> outputData = 
				pCertificates[i]->Encrypt(data, sizeof(data)); 

			// ����� ���� ��� �������������
			std::shared_ptr<Aladdin::CAPI::IPrivateKey> pFindPrivateKey = 
				pFactory->FindDecryptPrivateKey(
					&outputData[0], outputData.size(), hwnd, &encodedPrivateKey, 1
			); 
			// ��������� ������� �����
			if (!pFindPrivateKey) throw std::out_of_range(""); 

			// ������������ ������
			std::vector<unsigned char> checked = 
				pFindPrivateKey->Decrypt(&outputData[0], outputData.size()); 

			// ��������� ���������� �������� ������
			if (checked.size() != sizeof(data)) throw std::out_of_range(""); 

			// ��������� ���������� ������
			if (memcmp(&checked[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
		}
	}
	// ������� ������������� �����
	return pCertificate->KeyOID(); 
}

static void Test(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> >& pFactories, 
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, bool system, void* hwnd)
{
	// ����������� ������ �����
    std::vector<std::wstring> encodedPrivateKeys = 
		pFactory->EnumeratePrivateKeys(NULL, system);

	// ��� ���� ������������ �� �����-������
	for (size_t i = 0; i < encodedPrivateKeys.size(); i++)
	{
		// ������������� ������ ����
		std::shared_ptr<Aladdin::CAPI::IPrivateKey> pPrivateKey = 
			pFactory->DecodePrivateKey(encodedPrivateKeys[i].c_str(), hwnd); 

		// ��������� ������������ ��������
		Test(pFactories, pFactory, pPrivateKey, hwnd); 
	}
}

static std::wstring TestPKCS12(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> >& pFactories,
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, 
	const char* szPathP12, const wchar_t* szPassword, void* hwnd)
{
	// ������� ���� � ������� �� ��� ����������
	std::ifstream stream(szPathP12, std::ios::binary | std::ios::ate);

	// ���������� ������ �����
    std::ifstream::pos_type pos = stream.tellg(); stream.seekg(0, std::ios::beg);

	// ��������� �������������� ����
	size_t cb = (size_t)(std::streamsize)(std::streamoff)pos; 

	// ��������� ���������� �����
    std::vector<unsigned char> content(cb, 0); stream.read((char*)&content[0], cb);

	// ������������� ��������� PKCS12
	std::shared_ptr<Aladdin::CAPI::IPrivateKey> pPrivateKey = 
		pFactory->DecodePKCS12(&content[0], cb, szPassword); 

	// ��������� ������������ ��������
	Test(pFactories, pFactory, pPrivateKey, hwnd); 

	// ������������ ���������
	std::wstring encoded = pPrivateKey->ToString(); 

	// ������������� ��������� PKCS12
	pPrivateKey = pFactory->DecodePrivateKey(encoded.c_str(), hwnd); 

	// ��������� ������������ ��������
	Test(pFactories, pFactory, pPrivateKey, hwnd);

	// ������� ������������� �����
	return pPrivateKey->Certificate()->KeyOID(); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������� ���������� COM
///////////////////////////////////////////////////////////////////////////////
static std::shared_ptr<Aladdin::CAPI::IFactory> CreateFactoryCOM(
	HMODULE hModule, PCWSTR szRuntime, PCWSTR szConfigName) 
{
	// ���������� ������ ��� ����� ������
	WCHAR szPath[MAX_PATH]; ::GetModuleFileNameW(hModule, szPath, MAX_PATH); 

	// ����� ������� ����� �����
	std::wstring configFile = szConfigName; if (PCWSTR szFileName = wcsrchr(szPath, '\\'))
	{
		// ������� ��� ��������
		configFile = std::wstring(szPath, szFileName + 1 - szPath) + configFile; 
	}
    // �������� ������� ����������
	return Aladdin::CAPI::COM::CreateFactory(szRuntime, configFile.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������� ���������� OpenSSL
///////////////////////////////////////////////////////////////////////////////
static std::shared_ptr<Aladdin::CAPI::IFactory> CreateFactoryOpenSSL(HMODULE hModule)
{
	// ���������� ������ ��� ����� ������
	WCHAR szPath[MAX_PATH]; ::GetModuleFileNameW(hModule, szPath, MAX_PATH); 

	// ����� ������� ����� �����
	std::wstring pluginFile = L"capi.dll"; if (PCWSTR szFileName = wcsrchr(szPath, L'\\'))
	{
		// ������� ��� ��������
		pluginFile = std::wstring(szPath, szFileName + 1 - szPath) + pluginFile; 
	}
	// ������� ������� ����������
	return Aladdin::CAPI::OpenSSL::CreateFactory(pluginFile.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ ������ ���������
///////////////////////////////////////////////////////////////////////////////
static void TestFactories(HMODULE hModule, PCWSTR szConfigName, 
	const char* szPathP12, const wchar_t* szPassword)
{
	// ������� ������������ ������ CLR
	PCWSTR szRuntimes[] = { L"v4.0.30319", L"v2.0.50727" }; std::wstring keyOID; 

	// ������� ������ ������ ����������
	std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> > pFactories(2); 

	// c������ ������� ���������� COM
	pFactories[0] = CreateFactoryCOM(hModule, szRuntimes[0], szConfigName); 

	// c������ ������� ���������� OpenSSL
	pFactories[1] = CreateFactoryOpenSSL(hModule); 

    // �������� �������� ����
    void* hwnd = ::GetActiveWindow(); if (hwnd == 0) hwnd = ::GetDesktopWindow();  

    // ��������� ������������
	Test(pFactories, pFactories[0], false, hwnd); 
	Test(pFactories, pFactories[1], false, hwnd); 
	
	// ��������� ��������� PKCS12
	keyOID = TestPKCS12(pFactories, pFactories[0], szPathP12, szPassword, hwnd);
	keyOID = TestPKCS12(pFactories, pFactories[1], szPathP12, szPassword, hwnd);

    // �������� ����� ��� ������������
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
	// ����������� ������ �� ������
	std::vector<unsigned char> encrypted = pFactories[0]->PasswordEncrypt(
		keyOID.c_str(), szPassword, data, sizeof(data)
	); 
	// ��� ���� ������ ����������
	for (size_t i = 0; i < pFactories.size(); i++)
	{
		// ������������ ������
		std::vector<unsigned char> decrypted = pFactories[i]->PasswordDecrypt(
			szPassword, &encrypted[0], encrypted.size()
		); 
		// ��������� ���������� �������� ������
		if (decrypted.size() != sizeof(data)) throw std::out_of_range(""); 

		// ��������� ���������� ������
		if (memcmp(&decrypted[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
	}
} 

///////////////////////////////////////////////////////////////////////////////
// ����� �����
///////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
try {
	// ������� ��� ���������� PKCS12
	const char* szPathP12 = "..\\..\\Build\\Sign\\Aladdin-SHA256.pfx"; 

	HMODULE hModule = ::GetModuleHandleW(0); // Sleep(20000); 
	
	// ����� � ����������
	HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED); 

	// ��������� �������������
	int code = ::OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL);

	// ��������� �����
	TestFactories(hModule, L"Env.Crypto.config", szPathP12, L"1234567890"); 

	// ��������� �������
	::OPENSSL_cleanup(); ::CoUninitialize(); return 0; 
}
catch (...) { return -1; }
