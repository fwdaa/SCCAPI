#include "stdafx.h"
#include "Rand.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Rnd::Sobol::RandFactory::RandFactory()
{$
	// ��������� ������ � �������� ������������
	if (sizeof(void*) == 4) hModule = ::LoadLibraryW(L"SnElLock.dll"); 
	
	// ��������� ������ � �������� ������������
	else hModule = ::LoadLibraryW(L"SnElLock64.dll"); 

	// ��������� ������� ������
	AE_CHECK_WINAPI(hModule != nullptr); typedef SNCODE (__stdcall *PFNPRESENT)();
	try {
		// ���������� ����� �������
		pfnGenerate = (Rand::PFNGENERATE)::GetProcAddress(hModule, "sbGetRand"); 

		// ��������� ������� �������
		AE_CHECK_WINAPI(pfnGenerate != nullptr); if (!pfnGenerate) return; 

		// ���������� ����� �������
		PFNPRESENT pfnPresent = (PFNPRESENT)::GetProcAddress(hModule, "sbisCard"); 

		// ��������� ������� �������
		AE_CHECK_WINAPI(pfnPresent != nullptr); if (!pfnPresent) return; 

		// ��������� ������� �����
		if ((*pfnPresent)() != SN_OK) AE_CHECK_WINERROR(ERROR_NOT_FOUND);  

		// ������������� ��������� ������
		BYTE test = 0; SNCODE code = (*pfnGenerate)(&test, 1); 

		// ��������� ���������� ������
		if (code != SN_OK) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 
	}
	// ��������� ������ �� ��������� ������������
	catch (Exception^) { ::FreeLibrary(hModule); throw; }
}

// ��������� ������ �� ��������� ������������
Aladdin::CAPI::Rnd::Sobol::RandFactory::~RandFactory() {$ ::FreeLibrary(hModule); }

void Aladdin::CAPI::Rnd::Sobol::Rand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) 
{$
	// ��������� ������� ����������
	if (buffer == nullptr) throw gcnew ArgumentException(); 

	// �������� ��������� �� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[bufferOff]; SNCODE code = SN_OK; 

	// ������������� ��������� ������
	if (bufferLen > 0) code = (*pfnGenerate)(ptrBuffer, bufferLen); 

	// ��������� ���������� ������
	if (code != SN_OK) AE_CHECK_HRESULT(E_FAIL); 
}


