#include "stdafx.h"
#include "Mac.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Mac.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::Mac::Init(ISecretKey^ key) 
{$ 
	// ��������� ��� �����
	if (key->Value == nullptr) throw gcnew Win32Exception(NTE_BAD_KEY);

	// ���������������� ��������
	hHash.Close(); hHash.Attach(hProvider.Get()->CreateHash(key->Value, 0)); 
}

void Aladdin::CAPI::CNG::Mac::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CNG::Mac::Finish(array<BYTE>^ buffer, int bufferOff)
{$
	// �������� ������������
	array<BYTE>^ mac = hHash.Get()->FinishHash(0); 
			
	// ����������� ������������
	Array::Copy(mac, 0, buffer, bufferOff, mac->Length); 

    // ���������� ���������� �������
    hHash.Close(); return mac->Length; 
}
