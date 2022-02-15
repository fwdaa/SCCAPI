#include "stdafx.h"
#include "Generator.h"

//////////////////////////////////////////////////////////////////////////
// ���������� ������ ���������
//////////////////////////////////////////////////////////////////////////
#ifdef CERT_TEST
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE, LPCDLGTEMPLATEW, HWND, DLGPROC)
{
	static int entry = 0; entry++; HCRYPTPROV hProv = NULL; 

	// ���������������� ����������
	long long timer = pGenerator->GetMi�rosecondsSinceEpoch() + entry * 1000000LL * 64; 
	
	// ������� ��������� ��� ��������� ��������� ��������
	::CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT); 
	
	// ����������� ������� ������� �������
	for (ULONG value = 0; pGenerator->OnValidChar(timer, 0) < 100; value = 0) 
	{
		// ������������� ��������� ������
		::CryptGenRandom(hProv, sizeof(value), (PBYTE)&value); 

		// ��������� ����� �����
		timer += 500000LL + value % (1024 * 1024); 
	}
	// ������� ��������� ����������
	::CryptReleaseContext(hProv, 0); return TRUE; 
}
#endif 
