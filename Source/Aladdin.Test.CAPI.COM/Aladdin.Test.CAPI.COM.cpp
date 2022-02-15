#include "stdafx.h"
#include <vector>
#include <string>

// ������ �������� ���������� ������
#define CHECK(hr) { HRESULT _hr = hr; if (FAILED(_hr)) return _hr; } 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������
///////////////////////////////////////////////////////////////////////////////
static HRESULT Test(Aladdin_CAPI_COM::IFactory* spFactory, VARIANT_BOOL system)
{
    // �������� �������� ����
    HWND hwnd = ::GetActiveWindow(); if (hwnd == 0) hwnd = ::GetDesktopWindow();  

    // �������� ����� ��� ������������
    BYTE data[] = { 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB 
	}; 
    // ������������ ������
	std::wstring encodedData = Aladdin::CAPI::COM::EncodeBase64(data, sizeof(data)); 

	// �������� ����� ���������� �������
    ATL::CComBSTR strData(encodedData.c_str()); 

    // ������� ���������� ������� ������������� �����
    Aladdin_CAPI_COM::KeyUsage keyUsageMask = (Aladdin_CAPI_COM::KeyUsage)
		(Aladdin_CAPI_COM::KeyEncipherment | Aladdin_CAPI_COM::KeyAgreement); 

    // ������� ���������� ������� ������������� �����
    Aladdin_CAPI_COM::KeyUsage signUsageMask = (Aladdin_CAPI_COM::KeyUsage)
		(Aladdin_CAPI_COM::DigitalSignature | Aladdin_CAPI_COM::CertificateSignature | 
		 Aladdin_CAPI_COM::CrlSignature); 

	// ����������� ������ �����
	SAFEARRAY* saEncodedPrivateKeys; 
	CHECK(spFactory->EnumeratePrivateKeys(NULL, 
		Aladdin_CAPI_COM::KeyUsage::None, system, &saEncodedPrivateKeys
	));
    // ���������� ����������� �������
	LONG lBound; LONG uBound; 
	CHECK(::SafeArrayGetLBound(saEncodedPrivateKeys, 1, &lBound));
	CHECK(::SafeArrayGetUBound(saEncodedPrivateKeys, 1, &uBound));

	// �������� ������ ��������������
    ATL::CComPtr<Aladdin_CAPI_COM::IAuthentication> spAuthentication; 
    CHECK(spFactory->PasswordAuthentication(hwnd, &spAuthentication)); 

	// ��� ���� ������������ �� �����-������
	for (LONG i = lBound; i <= uBound; ++i)
	try {
		// �������� �������� ������� �����
        ATL::CComBSTR strEncodedPrivateKey; 
		CHECK(::SafeArrayGetElement(saEncodedPrivateKeys, &i, &strEncodedPrivateKey)); 

		// ������������� ������ ����
		ATL::CComPtr<Aladdin_CAPI_COM::IPrivateKey> spPrivateKey; 
		CHECK(spFactory->DecodePrivateKey(strEncodedPrivateKey, &spPrivateKey)); 

		// ������� ������ ��������������
		CHECK(spPrivateKey->put_Authentication(spAuthentication)); 

        // �������� ���������� ������� �����            
		ATL::CComPtr<Aladdin_CAPI_COM::ICertificate> spCertificate; 
        CHECK(spPrivateKey->get_Certificate(&spCertificate)); 

		// �������� ��� ��������
		ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> spIssuer; 
        CHECK(spCertificate->get_Issuer(&spIssuer)); 
        ATL::CComBSTR strIssuerEncoded; ATL::CComBSTR strIssuerName;
        CHECK(spIssuer->get_Encoded(&strIssuerEncoded)); 
        CHECK(spIssuer->ToString(&strIssuerName)); 

		// �������� ��� ��������
		ATL::CComPtr<Aladdin_CAPI_COM::IDistinctName> spSubject; 
        CHECK(spCertificate->get_Subject(&spSubject)); 
        ATL::CComBSTR strSubjectEncoded; ATL::CComBSTR strSubjectName;
        CHECK(spSubject->get_Encoded(&strSubjectEncoded)); 
        CHECK(spSubject->ToString(&strSubjectName)); 

		// �������� ������ ������������� �����
		Aladdin_CAPI_COM::KeyUsage keyUsage; 
		CHECK(spCertificate->get_KeyUsage(&keyUsage)); 

		// ��� ����������� �������
		if ((keyUsage & signUsageMask) != Aladdin_CAPI_COM::None)
		{
			// ��������� ������
			ATL::CComBSTR strOutput; 
			CHECK(spPrivateKey->SignData(strData, &strOutput)); 

			// ��������� ������� ������
			ATL::CComBSTR strChecked; 
			CHECK(spCertificate->VerifySign(strOutput, &strChecked)); 

			// ��������� ���������� ������
			if (strChecked != strData) return E_FAIL; 
		}
		// ��� ����������� ����������
		if ((keyUsage & keyUsageMask) != Aladdin_CAPI_COM::None)
		{
			// ����������� ������
			ATL::CComBSTR strOutput; 
			CHECK(spCertificate->Encrypt(strData, &strOutput)); 

			// ������������ ������
			ATL::CComBSTR strChecked; 
			CHECK(spPrivateKey->Decrypt(strOutput, &strChecked)); 

			// ��������� ���������� ������
			if (strChecked != strData) return E_FAIL; 
		}
	}
	catch (...) {} return S_OK; 
}

static HRESULT Test(HMODULE hModule, const wchar_t* szConfigName, PCWSTR szRuntime)
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
    ATL::CComPtr<Aladdin_CAPI_COM::IFactory> spFactory;  
	CHECK(Aladdin::CAPI::COM::CreateFactory(
		szRuntime, configFile.c_str(), &spFactory
	)); 
	// ��������� �����
	CHECK(Test(spFactory, VARIANT_TRUE )); 
	CHECK(Test(spFactory, VARIANT_FALSE)); return S_OK; 
}

int main(int argc, char* argv[])
try {
    // �������� ������� ����� ������
    HMODULE hModule = GetModuleHandleW(0); // Sleep(20000); 

	// ����� � ������������ ����������
	CHECK(::CoInitializeEx(0, COINIT_MULTITHREADED)); 

    // ��������� ������������
	HRESULT hr = Test(hModule, L"Env.Crypto.config", L"v4.0.30319");
	// HRESULT hr = Test(hModule, L"Env.Crypto.config", L"v2.0.50727");

    // ������� ��� ����������
    ::CoUninitialize(); return hr; 
}
catch (...) { return -1; }
