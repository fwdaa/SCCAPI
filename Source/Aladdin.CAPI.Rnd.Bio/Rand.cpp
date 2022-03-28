#include "stdafx.h"
#include "Rand.h"
#include "Generator.h"

using namespace System::Threading;
using namespace System::Runtime::InteropServices;
using namespace System::Windows::Forms;
 
///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Rand.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ������������� ��������� ������
///////////////////////////////////////////////////////////////////////
#pragma unmanaged
static bool GenerateSeed32(HWND hwnd, PBYTE seed, BOOL anyChar, BOOL legacy)
{
	if (anyChar)
	{
		// ������� ������������ ���������
		AnyChar_GeneratorGUI generator(hwnd, seed, legacy); 
	
		// ������������� ��������� ������
		return generator.GenerateSeed32() != 0;
	}
	else {
		// ������� ������������ ���������
		SpecifiedChar_GeneratorGUI generator(hwnd, seed, 10000); 
	
		// ������������� ��������� ������
		return generator.GenerateSeed32() != 0;
	}
}
#pragma managed

///////////////////////////////////////////////////////////////////////
// ��������� ��������� ������ (����� �������������)
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::Rnd::Bio::LegacyRandFactory::CreateRand(Object^ window)
{
	// ��������� �������� ����
	BYTE buffer[32] = {0}; if (window == nullptr) return nullptr; 
	
	// ������� ��������� ����
	HWND hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 

	// ������� ����������� ������
	if (!GenerateSeed32(hwnd, buffer, TRUE, TRUE))
	{
		// ��������� ����������
		throw gcnew OperationCanceledException(); 
	}
	// ������� ����� ���������� �������
	array<BYTE>^ seed = gcnew array<BYTE>(32); 

	// ����������� ��������� ������
	Marshal::Copy(IntPtr(buffer), seed, 0, seed->Length); 

	// ������� ��������� ��������� ������
	return gcnew GOST::Rnd::TC026_GOSTR3411_2012_512(window, seed); 
}

///////////////////////////////////////////////////////////////////////
// ��������� ��������� ������ (��� ������������)
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::IRand^ Aladdin::CAPI::Rnd::Bio::RandFactory::CreateRand(Object^ window)
{
	// ��������� �������� ����
	BYTE buffer[32] = {0}; if (window == nullptr) return nullptr; 
	
	// ������� ��������� ����
	HWND hwnd = (HWND)((IWin32Window^)window)->Handle.ToPointer(); 

	// ������� ����������� ������
	if (!GenerateSeed32(hwnd, buffer, anyChar, FALSE))
	{
		// ��������� ����������
		throw gcnew OperationCanceledException(); 
	}
	// ������� ����� ���������� �������
	array<BYTE>^ seed = gcnew array<BYTE>(32); 

	// ����������� ��������� ������
	Marshal::Copy(IntPtr(buffer), seed, 0, seed->Length); 

	// ������� ��������� ��������� ������
	return gcnew GOST::Rnd::TC026_GOSTR3411_2012_512(window, seed); 
}
