#pragma once
#include "Applet.h"
#include "ProFormat.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
    ///////////////////////////////////////////////////////////////////////////
	// ������ eToken Pro
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
		protected: Applet(SCard::Card^ store, String^ name, int id, 
            PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// ��������� ���������� ���������
			: LibApplet(store, name, id, session, atr) {}

        // �����������
		protected: Applet(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// ��������� ���������� ���������
			: LibApplet(store, "Pro", libapdu::TAppletPro, session, atr) {}

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

		// �������� �������� ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ authenticationType) override; 
	};

    ///////////////////////////////////////////////////////////////////////////
	// ������ eToken Pro Java
    ///////////////////////////////////////////////////////////////////////////
	ref class AppletJava : Applet
	{
        // �����������
		public: static AppletJava^ Create(SCard::Card^ store,
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
			// ������� ������
			AppletJava^ applet = gcnew AppletJava(store, session, atr); 

			// ������� ������
			try { return (AppletJava^)Proxy::SecurityObjectProxy::Create(applet); }

			// ���������� ��������� ������
			catch (Exception^) { delete applet; throw; } 
		}
        // �����������
		protected: AppletJava(SCard::Card^ store, 
			PCSC::ReaderSession^ session, array<BYTE>^ atr) 
			
			// ��������� ���������� ���������
			: Applet(store, "ProJava", libapdu::TAppletProJava, session, atr) {}

		// �������� ����� �����-�����
		public: virtual array<BYTE>^ GetSerial() override;  

        ///////////////////////////////////////////////////////////////////////
        // �������������� 
        ///////////////////////////////////////////////////////////////////////

		// ������� ������� �������������� ��������������
		protected: virtual int HasAdminAuthentication() override; 

		// �������� �������� ��������������
		public: virtual AuthenticationService^ GetAuthenticationService(
			String^ user, Type^ protocolType) override; 
	};
}}}}}

