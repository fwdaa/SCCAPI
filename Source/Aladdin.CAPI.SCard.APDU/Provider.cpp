#include "stdafx.h"
#include "Provider.h"
#include "ProApplet.h"
#include "GostApplet.h"
#include "DataApplet.h"
#include "LaserApplet.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::SCard::APDU::ProviderImpl::EnumerateApplets(SCard::Card^ store)
{$
	// ������������� ��� �����������
	PCSC::Reader^ reader = (PCSC::Reader^)store->PCSCCard->Reader; 

	// ������� ���������� ���������
	Protocol protocols = Protocol::T0 | Protocol::T1; 

    // ������� �����
    PCSC::ReaderSession^ session = reader->CreateSession(OpenMode::Shared, protocols);
	try {
		// �������� ATR �����-�����
		array<BYTE>^ atr = session->ATR->Encoded; 

		// ����������� ������� EToken JavaCard � JaCarta
		if (jcFamily->Contains(atr)) return jcFamily->EnumerateApplets(session, atr); 

		// ����������� ������� EToken
		if (etFamily->Contains(atr)) return etFamily->EnumerateApplets(session, atr); 

		// �������� �� ����������
		return gcnew array<String^>(0); 
	}
	// ���������� ���������� �������
	finally { delete session; }
}

Aladdin::CAPI::SCard::Applet^ 
Aladdin::CAPI::SCard::APDU::ProviderImpl::OpenApplet(SCard::Card^ store, String^ name)
{$
	// ������������� ��� �����������
	PCSC::Reader^ reader = (PCSC::Reader^)store->PCSCCard->Reader; 

	// ������� ���������� ���������
	Protocol protocols = Protocol::T0 | Protocol::T1; 

    // ������� �����
    PCSC::ReaderSession^ session = reader->CreateSession(OpenMode::Shared, protocols);
	try {
		// �������� ATR �����-�����
		array<BYTE>^ atr = session->ATR->Encoded; 

		// ��� ��������� EToken JavaCard � JaCarta
		if (jcFamily->Contains(atr))
		{
			// ������� ������ ���������� ����
			if (name == "Laser"      ) return Laser      ::Applet::Create(store, session, atr); 
			if (name == "DataStore"  ) return DataStore  ::Applet::Create(store, session, atr); 
			if (name == "Cryptotoken") return Cryptotoken::Applet::Create(store, session, atr); 
			if (name == "ProJava"    ) return Pro    ::AppletJava::Create(store, session, atr); 
		}
		// ��� ��������� EToken
		if (etFamily->Contains(atr))
		{
			// ������� ������ ���������� ����
			if (name == "Pro") return Pro::Applet::Create(store, session, atr); 
		}
		// ��� ������ ��������� ����������
		throw gcnew NotSupportedException(); 
	}
	// ���������� ��������� ������
	catch (System::Exception^) { delete session; throw; }
}
