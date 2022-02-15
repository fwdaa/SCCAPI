#include "stdafx.h"
#include "SCardStores.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SCardStores.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �����-����� ��� ���������� ��������
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::KZ::CSP::Tumar::SCardStores::GetNativeContainerName(String^ name)
{$
	// ������������ ��� �����������
	String^ reader = name->Replace(" ", "%20"); 

	// ������������ ������ ��� ����������
	return String::Format("kztoken://{0}@/{1}?ext=tok", "NONAME", reader); 
}

array<String^>^ Aladdin::CAPI::KZ::CSP::Tumar::SCardStores::EnumerateObjects()
{$
	// ������� ������ ���� ������������
	List<String^>^ names = gcnew List<String^>(); DWORD mode = CRYPT_SILENT;

    // �������� ���������� �����-����
    PCSC::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// ����������� �����������
	array<PCSC::Reader^>^ readers = provider->EnumerateReaders(readerScope); 

	// ��� ������ �����-�����
	for (int i = 0; i < readers->Length; i++) 
	try {
		// ��������� ������� �����-����� 
		if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 
		 			
		// ������������ ������ ��� ����������
		String^ nativeName = GetNativeContainerName(readers[i]->Name); 

		// ���������� ������� �����-�����
		Using<CAPI::CSP::ContainerHandle^> handle(
			Provider->Handle->AcquireContainer(nativeName, mode)
		); 
		// �������� ��� �����������
		names->Add(readers[i]->Name);
	}
	// ������� ������ ����
	catch (Exception^) {} return names->ToArray(); 
}

