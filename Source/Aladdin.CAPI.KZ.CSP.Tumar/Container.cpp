#include "stdafx.h"
#include "Container.h"
#include "Provider.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Container.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����� ��� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KZ::CSP::Tumar::Container::SetActivePrivateKey::SetActivePrivateKey(
	Container^ container, CAPI::CSP::PrivateKey^ privateKey)
{$
	// ��������� ���������� ���������
	hContainer = container->Handle; 

	// �������� �������� ���� �������
	Using<CAPI::CSP::KeyHandle^> hActiveKey(hContainer->GetUserKey(privateKey->KeyType)); 

	// ��������� ������������ ������
	if (hActiveKey.Get() == nullptr) throw gcnew Win32Exception(NTE_NO_KEY); 

	// ���������� ������������� �����
	keyID = hActiveKey.Get()->GetParam(KP_KEY_SN, 0);  
	
	// �������� ��������� �����
	Using<CAPI::CSP::KeyHandle^> hPrivateKey(privateKey->OpenHandle()); 
	
	// ���������� �������� ����
	hPrivateKey.Get()->SetParam(KP_USER_KEY, IntPtr::Zero, 0);  
}

Aladdin::CAPI::KZ::CSP::Tumar::Container::SetActivePrivateKey::~SetActivePrivateKey()
{$
	// ������������ �������� ����
	hContainer->SetParam(PP_CNT_ENTER_BY_SN, keyID, 0);
}

///////////////////////////////////////////////////////////////////////////
// ���������� ��� ���������
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::KZ::CSP::Tumar::Container::GetUniqueID()
{$
    // �������� ���������� �����-����
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Store->Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// �������� ���������� ������������� �����-�����
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

///////////////////////////////////////////////////////////////////////////
// ������� ������ ����������
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::KZ::CSP::Tumar::Container::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ��� ����������
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// ���������� ��� ������
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// ��������� ��� ������
	return (code == NTE_SILENT_CONTEXT || code == NTE_PERM || code == NTE_BAD_KEY); 
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::SetPassword(String^ password) 
{$
	// �������� ��������� �����
	CAPI::CSP::KeyHandle^ hKey = Handle->GetUserKey(AT_KEYEXCHANGE); 

	// ��������� ������� �����
	if (hKey != nullptr) { CAPI::CSP::Handle::Release(hKey); 
	
		// ���������� ������ �� ���������
		Handle->SetString(PP_KEYEXCHANGE_PIN, password, 0); 
	}
	else {
		// �������� ��������� �����
		hKey = Handle->GetUserKey(AT_SIGNATURE); 

		// ��������� ������� �����
		if (hKey != nullptr) { CAPI::CSP::Handle::Release(hKey);
		
			// ���������� ������ �� ���������
			Handle->SetString(PP_SIGNATURE_PIN, password, 0); 
		}
	}
	// ������� ��������� 
	ContInfoEx info; DWORD cb = sizeof(info); std::memset(&info, 0, cb);
	
	// ������������ ������ ����������
	array<BYTE>^ encodedPassword = Encoding::UTF8->GetBytes(password); 

	// ��������� ������ ������
	if (encodedPassword->Length >= sizeof(info.pass)) throw gcnew ArgumentException(); 

	// ������������ ��� ����������
	array<BYTE>^ encodedName = Encoding::UTF8->GetBytes(nativeName); 

	// ����������� ��� ����������
	Marshal::Copy(encodedName, 0, IntPtr(info.Url), encodedName->Length); 

	// �������� ���������� ����������
	cb = Provider->Handle->GetParam(PP_URL_TO_PROF, IntPtr(&info), cb, 0); 

	// ����������� ������ ����������
	Marshal::Copy(encodedPassword, 0, IntPtr(info.pass), encodedPassword->Length); 

	// �������� ���������� ����������
	Provider->Handle->GetParam(PP_PROF_TO_URL, IntPtr(&info), cb, 0); 

	// ���������� ������ ������� ����� � ����� ����������
	for (cb = 0; cb < sizeof(info.Url) && info.Url[cb] != 0; cb++) {} 

	// �������� ������ ��� ������� ����� � ����� �����������
	encodedName = gcnew array<BYTE>(cb); Marshal::Copy(IntPtr(info.Url), encodedName, 0, cb);
	
	// ���������� ������ ���
	nativeName = Encoding::UTF8->GetString(encodedName); 
	
	// ������� ��������� ����������
	if (hKey == nullptr) { DetachHandle(); 
		
		// ������ ������� ��������� 
		AttachHandle(nativeName, CRYPT_NEWKEYSET | CRYPT_SILENT);  
	}
}

///////////////////////////////////////////////////////////////////////////
// ���������� �������
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::KZ::CSP::Tumar::Container::GetKeyType(String^ keyOID, KeyUsage keyUsage)
{$
	// ������������� ������������� �����
	ALG_ID algID = Provider->ConvertKeyOID(keyOID, 0); 

	// ���������� ��� �����
	return (GET_ALG_TYPE(algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 
}

array<array<BYTE>^>^ Aladdin::CAPI::KZ::CSP::Tumar::Container::GetKeyIDs()
{$
	// ������� ��������� �������
	DWORD maxSize = 0; DWORD flags = CRYPT_FIRST; 

	// �������� ������ ������ ��� �������� ����
	while (DWORD cb = Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr::Zero, 0, flags))
	{
		// ������� ������������ ������
		if (cb > maxSize) maxSize = cb; flags = 0; 
	}
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(maxSize); CNT_PRIVATE_KEY* pInfo = (CNT_PRIVATE_KEY*)&buffer[0];

	// ������� ������ ��������������� ������
	List<array<BYTE>^>^ keyOIDs = gcnew List<array<BYTE>^>(); flags = CRYPT_FIRST; 
	
	// ��� ���� ������
	for (; Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr(pInfo), maxSize, flags); flags = 0)
	{
		// ������� ��������� �����
		Using<CAPI::CSP::KeyHandle^> hKeyPair(
			gcnew CAPI::CSP::KeyHandle(Handle, pInfo->hKey, Handle->SSPI)
		); 
		// ���������� ��� �����
		DWORD keyType = (GET_ALG_TYPE(pInfo->algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 

		// �������� ������ ��� ��������������
		array<BYTE>^ keyID = gcnew array<BYTE>(pInfo->serialNum.cbData); 

		// ����������� �������� ��������������
		Marshal::Copy(IntPtr(pInfo->serialNum.pbData), keyID, 0, keyID->Length); 
			
		// �������� ������������� � ������
		keyOIDs->Add(keyID);
	}
	return keyOIDs->ToArray(); 
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::Container::GetUserKey(array<BYTE>^ keyID, DWORD% keyType)
{$
	// ������� ��������� �������
	DWORD maxSize = 0; DWORD flags = CRYPT_FIRST; 

	// �������� ������ ������ ��� �������� ����
	while (DWORD cb = Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr::Zero, 0, flags))
	{
		// ������� ������������ ������
		if (cb > maxSize) maxSize = cb; flags = 0; 
	}
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(maxSize); CNT_PRIVATE_KEY* pInfo = (CNT_PRIVATE_KEY*)&buffer[0];

	// �������� ����� ��� ��������� ������
	std::vector<BYTE> serial(keyID->Length); flags = CRYPT_FIRST; 
	
	// ����������� �������� ����� �����
	Marshal::Copy(keyID, 0, IntPtr(&serial[0]), keyID->Length); 

	// ��� ���� ������
	for (; Handle->GetSafeParam(PP_ENUM_CNT_PRIV_KEYS, IntPtr(pInfo), maxSize, flags); flags = 0)
	{
		// ������� ��������� �����
		Using<CAPI::CSP::KeyHandle^> hKeyPair(
			gcnew CAPI::CSP::KeyHandle(Handle, pInfo->hKey, Handle->SSPI)
		); 
		// ��������� ���������� ���������������
		if (keyID->Length != pInfo->serialNum.cbData) continue; 
				
		// ��������� ���������� ���������������
		if (std::memcmp(&serial[0], pInfo->serialNum.pbData, keyID->Length) != 0) continue; 

		// ���������� ��� �����
		keyType = (GET_ALG_TYPE(pInfo->algID) == ALG_TYPE_ANY) ? AT_KEYEXCHANGE : AT_SIGNATURE; 

		// ������� ��������� �����
		return hKeyPair.Detach();
	}
	return nullptr;
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::DeleteKeyPair(array<BYTE>^ keyID) 
{$
	// ������� ���� ������
	Handle->SetParam(PP_CNT_DEL_SN, keyID, 0); 
}

void Aladdin::CAPI::KZ::CSP::Tumar::Container::DeleteKeys()
{$
/*
	// ������� ����� ��������
	DWORD mode = CRYPT_SILENT; HWND hwnd = ::GetActiveWindow();

	// ������� �������� ����
	Provider->Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	try { 
		// ������� ���������
		Provider->Handle->DeleteContainer(nativeName, mode); 
	}
	finally { hwnd = NULL; 
	
		// �������� �������� ����
		Provider->Handle->SetParam(PP_CLIENT_HWND, IntPtr(&hwnd), 0); 
	}
*/
	// �������� �������������� ������
	//array<array<BYTE>^>^ keyIDs = GetKeyIDs(); if (keyIDs == nullptr) return; 

	// ��� ���� ������
	for each (array<BYTE>^ keyID in GetKeyIDs())
	{
		// ��������� ������� ��������������
		//if (keyID == nullptr) continue; 

		/* TODO */
		// if (Arrays::Equals(keyID, gcnew array<BYTE> {
		// 	0x78, 0x93, 0x95, 0x6F, 0xF8, 0x9A, 0x6D, 0x44, 
		// 	0x55, 0x2C, 0x07, 0x4D, 0x49, 0xA7, 0x64, 0x1D, 
		// 	0x6C, 0x34, 0x43, 0xE8, 0x36, 0xA4, 0x28, 0x1E, 
		// 	0xAB, 0x78, 0x55, 0x7E, 0x50, 0x8F, 0x7D, 0xD0
		// }))	continue; 

		// ������� ����
		DeleteKeyPair(keyID); 
	}
}

