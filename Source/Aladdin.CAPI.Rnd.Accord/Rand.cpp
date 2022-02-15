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
Aladdin::CAPI::Rnd::Accord::RandFactory::RandFactory()
{$
	// ��������� ������ � �������� ������������
	if (sizeof(void*) == 4) hModule = ::LoadLibraryW(L"tmdrv32.dll"); 
	
	// ��������� ������ � �������� ������������
	else hModule = ::LoadLibraryW(L"tmdrv64.dll"); 

	// ��������� ������� ������
	AE_CHECK_WINAPI(hModule != nullptr); typedef DWORD (*PFNPRESENT)();
	try {
		// ���������� ����� �������
		pfnGenerate = (Rand::PFNGENERATE)::GetProcAddress(hModule, "TmGetRandomBytes"); 

		// ��������� ������� �������
		AE_CHECK_WINAPI(pfnGenerate != nullptr); if (!pfnGenerate) return; 

		// ���������� ����� �������
		PFNPRESENT pfnPresent = (PFNPRESENT)::GetProcAddress(hModule, "TmDriverPresent"); 

		// ��������� ������� �������
		AE_CHECK_WINAPI(pfnPresent != nullptr); if (!pfnPresent) return; 

		// ��������� ������� �����
		if (!(*pfnPresent)()) AE_CHECK_WINERROR(ERROR_NOT_FOUND);  

		// ������������� ��������� ������
		BYTE test = 0; DWORD code = (*pfnGenerate)(&test, 1); 

		// ��������� ���������� ������
		if (code != 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 
	}
	// ��������� ������ �� ��������� ������������
	catch (Exception^) { ::FreeLibrary(hModule); throw; }
}

// ��������� ������ �� ��������� ������������
Aladdin::CAPI::Rnd::Accord::RandFactory::~RandFactory() {$ ::FreeLibrary(hModule); }

void Aladdin::CAPI::Rnd::Accord::Rand::Generate(array<BYTE>^ buffer, int bufferOff, int bufferLen) 
{$
	// ��������� ������� ����������
	if (buffer == nullptr) throw gcnew ArgumentException(); 

	// �������� ��������� �� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[bufferOff]; int blockSize = 60; DWORD code = 0; 

	// ��� ���� ����� ������ 
	for (; bufferLen > blockSize; bufferLen -= blockSize, ptrBuffer += blockSize)
	{
		// ������������� ��������� ������
		code = (*pfnGenerate)(ptrBuffer, blockSize); 

		// ��������� ���������� ������
		if (code != 0) AE_CHECK_HRESULT(E_FAIL); 
	}
	// ������������� ��������� ������
	if (bufferLen > 0) code = (*pfnGenerate)(ptrBuffer, bufferLen); 

	// ��������� ���������� ������
	if (code != 0) AE_CHECK_HRESULT(E_FAIL); 
}
