#pragma once
#include "Applet.h"
#include "GostFormat.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Cryptotoken
{
    ///////////////////////////////////////////////////////////////////////////
	// ������ Cryptotoken
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
			: LibApplet(store, "Cryptotoken", libapdu::TAppletGost, session, atr) {}

		// �������� ����� �����-�����
		public: virtual array<BYTE>^ GetSerial() override;  

        ///////////////////////////////////////////////////////////////////////
        // �������������� ������� 
        ///////////////////////////////////////////////////////////////////////

        // ��������� �������������� �� ���������
		public: virtual SCard::FormatParameters^ GetDefaultFormatParameters() override
		{
			// ��������� �������������� �� ���������
			return gcnew FormatParameters(); 
		}
        // ��������� �������������� �������
		public: virtual void Format(String^ adminPIN, SCard::FormatParameters^ parameters) override;  

		// ������� ������� �������������� ��������������
		protected: virtual int HasAdminAuthentication() override { return 1; } 
	};
}}}}}

