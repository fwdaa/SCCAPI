#include "stdafx.h"
#include <vector>
#include <string>

// Макрос проверки отсутствия ошибок
#define CHECK(hr) { HRESULT _hr = hr; if (FAILED(_hr)) return _hr; } 

///////////////////////////////////////////////////////////////////////////////
// Выполнить тестирование
///////////////////////////////////////////////////////////////////////////////
static HRESULT Test(Aladdin_CAPI_COM::IFactory* spFactory, VARIANT_BOOL system)
{
    // получить активное окно
    HWND hwnd = ::GetActiveWindow(); if (hwnd == 0) hwnd = ::GetDesktopWindow();  

    // выделить буфер для зашифрования
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
    // закодировать данные
	std::wstring encodedData = Aladdin::CAPI::COM::EncodeBase64(data, sizeof(data)); 

	// выделить буфер требуемого размера
    ATL::CComBSTR strData(encodedData.c_str()); 

    // указать допустимые способы использования ключа
    Aladdin_CAPI_COM::KeyUsage keyUsageMask = (Aladdin_CAPI_COM::KeyUsage)
		(Aladdin_CAPI_COM::KeyEncipherment | Aladdin_CAPI_COM::KeyAgreement); 

    // указать допустимые способы использования ключа
    Aladdin_CAPI_COM::KeyUsage signUsageMask = (Aladdin_CAPI_COM::KeyUsage)
		(Aladdin_CAPI_COM::DigitalSignature | Aladdin_CAPI_COM::CertificateSignature | 
		 Aladdin_CAPI_COM::CrlSignature); 

	// перечислить личные ключи
	SAFEARRAY* saEncodedPrivateKeys; 
	CHECK(spFactory->EnumeratePrivateKeys(NULL, 
		Aladdin_CAPI_COM::KeyUsage::None, system, &saEncodedPrivateKeys
	));
    // определить размерность массива
	LONG lBound; LONG uBound; 
	CHECK(::SafeArrayGetLBound(saEncodedPrivateKeys, 1, &lBound));
	CHECK(::SafeArrayGetUBound(saEncodedPrivateKeys, 1, &uBound));

	// получить способ аутентификации
    ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> spAuthentication; 
    CHECK(spFactory->PasswordAuthentication(hwnd, &spAuthentication)); 

	// для всех сертификатов на смарт-картах
	for (LONG i = lBound; i <= uBound; ++i)
	try {
		// получить описание личного ключа
        ATL::CComBSTR strEncodedPrivateKey; 
		CHECK(::SafeArrayGetElement(saEncodedPrivateKeys, &i, &strEncodedPrivateKey)); 

		// раскодировать личный ключ
		ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> spPrivateKey; 
		CHECK(spFactory->DecodePrivateKey(strEncodedPrivateKey, &spPrivateKey)); 

		// указать способ аутентификации
		CHECK(spPrivateKey->put_Authentication(spAuthentication)); 

        // получить сертификат личного ключа            
		ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> spCertificate; 
        CHECK(spPrivateKey->get_Certificate(&spCertificate)); 

		// получить имя издателя
		ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> spIssuer; 
        CHECK(spCertificate->get_Issuer(&spIssuer)); 
        ATL::CComBSTR strIssuerEncoded; ATL::CComBSTR strIssuerName;
        CHECK(spIssuer->get_Encoded(&strIssuerEncoded)); 
        CHECK(spIssuer->ToString(&strIssuerName)); 

		// получить имя субъекта
		ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> spSubject; 
        CHECK(spCertificate->get_Subject(&spSubject)); 
        ATL::CComBSTR strSubjectEncoded; ATL::CComBSTR strSubjectName;
        CHECK(spSubject->get_Encoded(&strSubjectEncoded)); 
        CHECK(spSubject->ToString(&strSubjectName)); 

		// получить способ использования ключа
		Aladdin_CAPI_COM::KeyUsage keyUsage; 
		CHECK(spCertificate->get_KeyUsage(&keyUsage)); 

		// при возможности подписи
		if ((keyUsage & signUsageMask) != Aladdin_CAPI_COM::None)
		{
			// подписать данные
			ATL::CComBSTR strOutput; 
			CHECK(spPrivateKey->SignData(strData, &strOutput)); 

			// проверить подпись данных
			ATL::CComBSTR strChecked; 
			CHECK(spCertificate->VerifySign(strOutput, &strChecked)); 

			// проверить совпадение данных
			if (strChecked != strData) return E_FAIL; 
		}
		// при возможности шифрования
		if ((keyUsage & keyUsageMask) != Aladdin_CAPI_COM::None)
		{
			// зашифровать данные
			ATL::CComBSTR strOutput; 
			CHECK(spCertificate->Encrypt(strData, &strOutput)); 

			// расшифровать данные
			ATL::CComBSTR strChecked; 
			CHECK(spPrivateKey->Decrypt(strOutput, &strChecked)); 

			// проверить совпадение данных
			if (strChecked != strData) return E_FAIL; 
		}
	}
	catch (...) {} return S_OK; 
}

static HRESULT Test(HMODULE hModule, const wchar_t* szConfigName, PCWSTR szRuntime)
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
    ATL::CComPtr<Aladdin_CAPI_COM::IFactory> spFactory;  
	CHECK(Aladdin::CAPI::COM::CreateFactory(
		szRuntime, configFile.c_str(), &spFactory
	)); 
	// выполнить тесты
	CHECK(Test(spFactory, VARIANT_TRUE )); 
	CHECK(Test(spFactory, VARIANT_FALSE)); return S_OK; 
}

int main(int argc, char* argv[])
try {
    // получить базовый адрес модуля
    HMODULE hModule = GetModuleHandleW(0); // Sleep(20000); 

	// войти в однопоточный апартамент
	CHECK(::CoInitializeEx(0, COINIT_MULTITHREADED)); 

    // выполнить тестирование
	HRESULT hr = Test(hModule, L"Env.Crypto.config", L"v4.0.30319");
	// HRESULT hr = Test(hModule, L"Env.Crypto.config", L"v2.0.50727");

    // вернуть код завершения
    ::CoUninitialize(); return hr; 
}
catch (...) { return -1; }
