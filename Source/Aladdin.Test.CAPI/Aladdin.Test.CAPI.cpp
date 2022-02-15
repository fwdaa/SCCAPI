#include "stdafx.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <openssl/crypto.h>

///////////////////////////////////////////////////////////////////////////////
// Выполнить тестирование
///////////////////////////////////////////////////////////////////////////////
static std::wstring Test(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> > pFactories, 
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, 
	const std::shared_ptr<Aladdin::CAPI::IPrivateKey>& pPrivateKey, void* hwnd)
{
    // выделить буфер для зашифрования
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
    // указать допустимые способы использования ключа
    Aladdin::CAPI::KeyUsage keyUsageMask = (Aladdin::CAPI::KeyUsage)
		(Aladdin::CAPI::KeyUsage::KeyEncipherment | 
		 Aladdin::CAPI::KeyUsage::KeyAgreement); 

    // указать допустимые способы использования ключа
    Aladdin::CAPI::KeyUsage signMask = (Aladdin::CAPI::KeyUsage)
		(Aladdin::CAPI::KeyUsage::DataSignature			| 
		 Aladdin::CAPI::KeyUsage::CertificateSignature	| 
		 Aladdin::CAPI::KeyUsage::CrlSignature); 

    // получить сертификат личного ключа            
	std::shared_ptr<Aladdin::CAPI::ICertificate> pCertificate = pPrivateKey->Certificate(); 

	// закодировать сертификат
	std::vector<unsigned char> certificateEncoded = pPrivateKey->Certificate()->Encoded(); 

	// закодировать личный ключ
	std::wstring encodedPrivateKey = pPrivateKey->ToString(); 

	// создать вектор для сертификатов
	std::vector<std::shared_ptr<Aladdin::CAPI::ICertificate> > pCertificates(pFactories.size()); 

	// для всех фабрик алгоритмов
	for (size_t i = 0; i < pFactories.size(); i++)
	{
		// раскодировать сертификат
		pCertificates[i] = pFactories[i]->DecodeCertificate(
			&certificateEncoded[0], certificateEncoded.size()
		); 
		// получить имя издателя
		std::shared_ptr<Aladdin::CAPI::IDistinctName> pIssuer = pCertificates[i]->Issuer(); 
		std::vector<unsigned char> issuerEncoded = pIssuer->Encoded(); 
		std::wstring issuerName = pIssuer->ToString(); 

		// получить имя субъекта
		std::shared_ptr<Aladdin::CAPI::IDistinctName> pSubject = pCertificates[i]->Subject(); 
		std::vector<unsigned char> subjectEncoded = pSubject->Encoded(); 
		std::wstring subjectName = pSubject->ToString(); 
	}
	// получить способ использования ключа
	Aladdin::CAPI::KeyUsage keyUsage = pCertificate->KeyUsage(); 

	// при возможности подписи
	if ((keyUsage & signMask) != 0)
	{
		// подписать данные
		std::vector<unsigned char> outputData = pPrivateKey->SignData(data, sizeof(data)); 

		// для всех фабрик алгоритмов
		for (size_t i = 0; i < pFactories.size(); i++)
		{
			// найти сертификат для проверки подписи
			std::shared_ptr<Aladdin::CAPI::ICertificate> pFindCertificate = 
				pFactories[i]->FindVerifyCertificate(
					&outputData[0], outputData.size(), &certificateEncoded, 1
			); 
			// проверить наличие ключа
			if (!pFindCertificate) throw std::out_of_range(""); 

			// проверить подпись данных
			std::vector<unsigned char> checked = 
				pFindCertificate->VerifySign(&outputData[0], outputData.size()); 

			// проверить совпадение размеров данных
			if (checked.size() != sizeof(data)) throw std::out_of_range(""); 

			// проверить совпадение данных
			if (memcmp(&checked[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
		}
	}
	// при возможности шифрования
	if ((keyUsage & keyUsageMask) != 0)
	{
		// для всех фабрик алгоритмов
		for (size_t i = 0; i < pFactories.size(); i++)
		{
			// зашифровать данные
			std::vector<unsigned char> outputData = 
				pCertificates[i]->Encrypt(data, sizeof(data)); 

			// найти ключ для расшифрования
			std::shared_ptr<Aladdin::CAPI::IPrivateKey> pFindPrivateKey = 
				pFactory->FindDecryptPrivateKey(
					&outputData[0], outputData.size(), hwnd, &encodedPrivateKey, 1
			); 
			// проверить наличие ключа
			if (!pFindPrivateKey) throw std::out_of_range(""); 

			// расшифровать данные
			std::vector<unsigned char> checked = 
				pFindPrivateKey->Decrypt(&outputData[0], outputData.size()); 

			// проверить совпадение размеров данных
			if (checked.size() != sizeof(data)) throw std::out_of_range(""); 

			// проверить совпадение данных
			if (memcmp(&checked[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
		}
	}
	// вернуть идентификатор ключа
	return pCertificate->KeyOID(); 
}

static void Test(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> >& pFactories, 
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, bool system, void* hwnd)
{
	// перечислить личные ключи
    std::vector<std::wstring> encodedPrivateKeys = 
		pFactory->EnumeratePrivateKeys(NULL, system);

	// для всех сертификатов на смарт-картах
	for (size_t i = 0; i < encodedPrivateKeys.size(); i++)
	{
		// раскодировать личный ключ
		std::shared_ptr<Aladdin::CAPI::IPrivateKey> pPrivateKey = 
			pFactory->DecodePrivateKey(encodedPrivateKeys[i].c_str(), hwnd); 

		// проверить корректность операций
		Test(pFactories, pFactory, pPrivateKey, hwnd); 
	}
}

static std::wstring TestPKCS12(
	const std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> >& pFactories,
	const std::shared_ptr<Aladdin::CAPI::IFactory>& pFactory, 
	const char* szPathP12, const wchar_t* szPassword, void* hwnd)
{
	// открыть файл и перейти на его завершение
	std::ifstream stream(szPathP12, std::ios::binary | std::ios::ate);

	// определить размер файла
    std::ifstream::pos_type pos = stream.tellg(); stream.seekg(0, std::ios::beg);

	// выполнить преобразование типа
	size_t cb = (size_t)(std::streamsize)(std::streamoff)pos; 

	// прочитать содержимое файла
    std::vector<unsigned char> content(cb, 0); stream.read((char*)&content[0], cb);

	// раскодировать контейнер PKCS12
	std::shared_ptr<Aladdin::CAPI::IPrivateKey> pPrivateKey = 
		pFactory->DecodePKCS12(&content[0], cb, szPassword); 

	// проверить корректность операций
	Test(pFactories, pFactory, pPrivateKey, hwnd); 

	// закодировать контейнер
	std::wstring encoded = pPrivateKey->ToString(); 

	// раскодировать контейнер PKCS12
	pPrivateKey = pFactory->DecodePrivateKey(encoded.c_str(), hwnd); 

	// проверить корректность операций
	Test(pFactories, pFactory, pPrivateKey, hwnd);

	// вернуть идентификатор ключа
	return pPrivateKey->Certificate()->KeyOID(); 
}

///////////////////////////////////////////////////////////////////////////////
// Создать фабрику алгоритмов COM
///////////////////////////////////////////////////////////////////////////////
static std::shared_ptr<Aladdin::CAPI::IFactory> CreateFactoryCOM(
	HMODULE hModule, PCWSTR szRuntime, PCWSTR szConfigName) 
{
	// определить полное имя файла модуля
	WCHAR szPath[MAX_PATH]; ::GetModuleFileNameW(hModule, szPath, MAX_PATH); 

	// найти позицию имени файла
	std::wstring configFile = szConfigName; if (PCWSTR szFileName = wcsrchr(szPath, '\\'))
	{
		// извлечь имя каталога
		configFile = std::wstring(szPath, szFileName + 1 - szPath) + configFile; 
	}
    // получить фабрику алгоритмов
	return Aladdin::CAPI::COM::CreateFactory(szRuntime, configFile.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// Создать фабрику алгоритмов OpenSSL
///////////////////////////////////////////////////////////////////////////////
static std::shared_ptr<Aladdin::CAPI::IFactory> CreateFactoryOpenSSL(HMODULE hModule)
{
	// определить полное имя файла модуля
	WCHAR szPath[MAX_PATH]; ::GetModuleFileNameW(hModule, szPath, MAX_PATH); 

	// найти позицию имени файла
	std::wstring pluginFile = L"capi.dll"; if (PCWSTR szFileName = wcsrchr(szPath, L'\\'))
	{
		// извлечь имя каталога
		pluginFile = std::wstring(szPath, szFileName + 1 - szPath) + pluginFile; 
	}
	// создать фабрику алгоритмов
	return Aladdin::CAPI::OpenSSL::CreateFactory(pluginFile.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// Выполнить тестирование фабрик алгоримов
///////////////////////////////////////////////////////////////////////////////
static void TestFactories(HMODULE hModule, PCWSTR szConfigName, 
	const char* szPathP12, const wchar_t* szPassword)
{
	// указать используемую версию CLR
	PCWSTR szRuntimes[] = { L"v4.0.30319", L"v2.0.50727" }; std::wstring keyOID; 

	// создать список фабрик алгоритмов
	std::vector<std::shared_ptr<Aladdin::CAPI::IFactory> > pFactories(2); 

	// cоздать фабрику алгоритмов COM
	pFactories[0] = CreateFactoryCOM(hModule, szRuntimes[0], szConfigName); 

	// cоздать фабрику алгоритмов OpenSSL
	pFactories[1] = CreateFactoryOpenSSL(hModule); 

    // получить активное окно
    void* hwnd = ::GetActiveWindow(); if (hwnd == 0) hwnd = ::GetDesktopWindow();  

    // выполнить тестирование
	Test(pFactories, pFactories[0], false, hwnd); 
	Test(pFactories, pFactories[1], false, hwnd); 
	
	// проверить контейнер PKCS12
	keyOID = TestPKCS12(pFactories, pFactories[0], szPathP12, szPassword, hwnd);
	keyOID = TestPKCS12(pFactories, pFactories[1], szPathP12, szPassword, hwnd);

    // выделить буфер для зашифрования
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
	// зашифровать данные на пароле
	std::vector<unsigned char> encrypted = pFactories[0]->PasswordEncrypt(
		keyOID.c_str(), szPassword, data, sizeof(data)
	); 
	// для всех фабрик алгоритмов
	for (size_t i = 0; i < pFactories.size(); i++)
	{
		// расшифровать данные
		std::vector<unsigned char> decrypted = pFactories[i]->PasswordDecrypt(
			szPassword, &encrypted[0], encrypted.size()
		); 
		// проверить совпадение размеров данных
		if (decrypted.size() != sizeof(data)) throw std::out_of_range(""); 

		// проверить совпадение данных
		if (memcmp(&decrypted[0], data, sizeof(data)) != 0) throw std::out_of_range(""); 
	}
} 

///////////////////////////////////////////////////////////////////////////////
// Точка входа
///////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
try {
	// указать имя контейнера PKCS12
	const char* szPathP12 = "..\\..\\Build\\Sign\\Aladdin-SHA256.pfx"; 

	HMODULE hModule = ::GetModuleHandleW(0); // Sleep(20000); 
	
	// войти в апартамент
	HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED); 

	// выполнить инициализацию
	int code = ::OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL);

	// выполнить тесты
	TestFactories(hModule, L"Env.Crypto.config", szPathP12, L"1234567890"); 

	// выполнить очистку
	::OPENSSL_cleanup(); ::CoUninitialize(); return 0; 
}
catch (...) { return -1; }
