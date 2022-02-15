#include "stdafx.h"
#include "STB11761.h"

using namespace System::Runtime::InteropServices; 

///////////////////////////////////////////////////////////////////////////
// �������� ����������� ��� 1176.1
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::HashHandle Aladdin::CAPI::STB::Avest::CSP::STB11761::Hash::Construct()
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::STB11761::Hash::Construct); 

	// �������� ������ ��� ���������� ��������
	BYTE arrStart[32]; CRYPT_INTEGER_BLOB blobStart = { 32, arrStart }; 

	// ����������� ��������� ��������
	Marshal::Copy(start, 0, IntPtr(arrStart), 32); 

	// ������� �������� �����������
	CAPI::CSP::HashHandle hHash = CAPI::CSP::Hash::Construct(); 
	try {
		// ���������� ��������� ��������
		hHash.SetParam(HP_INIT_VECTOR, IntPtr(&blobStart), 0);

		// ���������� ������ ���-��������
		CAPI::CSP::Handle::SetParam(hHash, HP_BHF_L, 256, 0); 
	}
	// ���������� ��������� ������
	catch(Exception^) { hHash.Destroy(); throw; }  return hHash; 
}
