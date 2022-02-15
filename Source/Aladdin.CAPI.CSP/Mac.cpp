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
void Aladdin::CAPI::CSP::Mac::Init(ISecretKey^ key) 
{$ 
    // ���������� ���������� �������
    hHash.Close(); hKey.Close(); 

	// ��� ������� ������� �����
	if (dynamic_cast<SecretKey^>(key) != nullptr)
	{
		// ������� ��������� �����
		hKey.Attach(Handle::AddRef(((SecretKey^)key)->Handle)); 
	}
    // ��� ������� �������� �����
    else if (key->Value != nullptr)
    {
		// �������� ��� �����
		SecretKeyType^ keyType = provider->GetSecretKeyType(
			key->KeyFactory, key->Value->Length
		); 
        // ������� ���� ��� ���������
        hKey.Attach(keyType->ConstructKey(hContext, key->Value, flags));  
    }
    // ��� ������ ��������� ����������
    else throw gcnew InvalidKeyException();  
    try { 
		// ���������� ��������� �����
		SetParameters(hKey.Get()); 
		
		// ������� �������� �����������
		hHash.Attach(Construct(hContext, hKey.Get())); 
	}
	// ��� ������ ������� ����
	catch(Exception^) { hKey.Close(); throw; }
}

void Aladdin::CAPI::CSP::Mac::Update(array<BYTE>^ data, int dataOff, int dataLen)
{$
	// ������������ ������
	if (dataLen > 0) hHash.Get()->HashData(data, dataOff, dataLen, 0); 
}

int Aladdin::CAPI::CSP::Mac::Finish(array<BYTE>^ buffer, int bufferOff)
{$ 
	// �������� ������������
	array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0); 
			
	// ����������� ������������
	Array::Copy(mac, 0, buffer, bufferOff, mac->Length); 
	
	// ������� ������ ������������
	hHash.Close(); hKey.Close(); return mac->Length;
}
