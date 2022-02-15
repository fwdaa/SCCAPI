#pragma once
#include "Applet.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace DataStore
{
    ///////////////////////////////////////////////////////////////////////////
	// ������ DataStore
    ///////////////////////////////////////////////////////////////////////////
	ref class Applet : LibApplet
	{
        // �����������
		public: static Applet^ Create(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
			// ������� ������
			Applet^ applet = gcnew Applet(store, session, atr); 

			// ������� ������
			try { return (Applet^)Proxy::SecurityObjectProxy::Create(applet); } 

			// ���������� ��������� ������
			catch (Exception^) { delete applet; throw; } 
		}
        // �����������
		protected: Applet(SCard::Card^ store, PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// ��������� ���������� ���������
			: LibApplet(store, "DataStore", libapdu::TAppletDataStore, session, atr) {}

		// �������� ����� �����-�����
		public: virtual array<BYTE>^ GetSerial() override;  

        ///////////////////////////////////////////////////////////////////////
        // �������������� ������� 
        ///////////////////////////////////////////////////////////////////////

        // ��������� �������������� �� ���������
		public: virtual SCard::FormatParameters^ GetDefaultFormatParameters() override
		{
			// ��������� �������������� �� ���������
			return gcnew SCard::FormatParameters(); 
		}
        // ��������� �������������� �������
		public: virtual void Format(String^ userPIN, SCard::FormatParameters^ parameters) override;  
	};
}}}}}

