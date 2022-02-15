#include "StdAfx.h"
#include "DataApplet.h"
#include "NativeAPI.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DataFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::DataStore::Applet::Format(
    String^ userPIN, SCard::FormatParameters^ parameters) 
{$
	// ������������� ��� ����������
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// ��������� ������������ ���� ����������
	if (params == nullptr) throw gcnew ArgumentException();  

    // ��������� ������ PKCS11
	PKCS11::Module^ module = PKCS11::Module::Create(gcnew NativeAPI()); 

    // ����������� ����������� �� ����������� �����-������
    array<UInt64>^ slotsIds = module->GetSlotList(true);

    // ��� ���� ������������
	for (int i = 0; i < slotsIds->Length; i++)
	{
        // �������� ���������� �����������
	    PKCS11::SlotInfo^ info = module->GetSlotInfo(slotsIds[i]);

        // ��������� ���������� �����
		if (info->SlotDescription != Card->Reader->Name) continue; 

        // ������� ��� ������ �����-�����
	    module->CloseAllSessions(slotsIds[i]);  

        // ��������� �������������� 
        module->InitToken(slotsIds[i], userPIN, String::Empty); return; 
    }
	// ��� ������ ��������� ����������
	throw gcnew NotFoundException(); 
}
