#include "stdafx.h"
#include "Hash.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Hash.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Hash::Init() 
{$ 
	// ���������������� ��������
	hHash.Close(); hHash.Attach(hProvider.Get()->CreateHash(nullptr, 0)); 
}

void Aladdin::CAPI::CNG::Hash::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CNG::Hash::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// �������� ���-��������
	array<BYTE>^ hash = hHash.Get()->FinishHash(0);  
			
	// ����������� ���-��������
	Array::Copy(hash, 0, buffer, bufferOff, hash->Length); 

    // ���������� ���������� �������
    hHash.Close(); return hash->Length;
}
