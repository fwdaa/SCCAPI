#include "stdafx.h"
#include "Rand.h"

void Aladdin::CSP::Rand::Generate(Binary^ buffer, int bufferOff, int bufferLen)
try{
	ATRACE_SCOPE(Aladdin::CSP::Rand::Generate); 

	// �������� ��������������� �����
	PBYTE pbBuffer = (PBYTE)_alloca(bufferLen);

	// ������������� ������ � ������
	AE_CHECK_WIN32_RESULT(::CryptGenRandom(hProvider, bufferLen, pbBuffer)); 

	// ����������� ������
	System::Runtime::InteropServices::Marshal::Copy(IntPtr(pbBuffer), buffer, bufferOff, bufferLen); 
}
// ��� ������ ��������� ����������
catch(const CAException& e) { throw gcnew InteropException(e.Code()); }

