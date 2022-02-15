#pragma once
#include "Applet.h"
#include "LaserFormat.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
    ///////////////////////////////////////////////////////////////////////////
	// ������ Laser
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
			: LibApplet(store, "Laser", libapdu::TAppletAthena, session, atr) {}

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

        ///////////////////////////////////////////////////////////////////////
        // �������������� 
        ///////////////////////////////////////////////////////////////////////

		// ������� ������� �������������� ��������������
		protected: virtual int HasAdminAuthentication() override;  

		// �������������� ���� ��������������
		public: virtual array<Type^>^GetAuthenticationTypes(String^ user) override; 

		// �������� �������� ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	};
}}}}}

