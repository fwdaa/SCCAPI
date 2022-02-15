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
void Aladdin::CAPI::CSP::Hash::Init() 
{$ 
    // ������� �������� �����������
    hHash.Close(); hHash.Attach(Construct());
}

void Aladdin::CAPI::CSP::Hash::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CSP::Hash::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// �������� ���-��������
	array<BYTE>^ hash = hHash.Get()->GetParam(HP_HASHVAL, 0);  
			
	// ����������� ���-��������
	Array::Copy(hash, 0, buffer, bufferOff, hash->Length); 
	
	// ���������� ���������� �������
	hHash.Close(); return hash->Length;
}
