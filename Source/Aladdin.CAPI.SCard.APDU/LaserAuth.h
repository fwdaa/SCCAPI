#pragma once 
#include "AppletAuth.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������������� �������������� ������� Laser ��� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseService : LibPinService
    {
        // �����������
		public: LibResponseService(LibApplet^ applet) 
			
			// ��������� ���������� ���������
			: LibPinService(applet, "ADMIN", true) {}

        // ���������� ������
        public: virtual void SetPassword(String^ pinCode) override; 

		// �������� ������ 
		public: virtual void ChangePassword(String^ pinCode) override;
    }; 
    ///////////////////////////////////////////////////////////////////////////
	// ����� �������������� ��������������
    ///////////////////////////////////////////////////////////////////////////
	public ref class LibBiometricTicket : Bio::MatchTemplate
	{
        // ������ �������������� ��������������
		private: array<BYTE>^ ticketData; private: libapdu::enumAuthMethod loginType;
        
        // �����������
		public: LibBiometricTicket(Bio::MatchTemplate^ matchTemplate, 
			libapdu::enumAuthMethod loginType, array<BYTE>^ ticketData) 

			// ��������� ���������� ���������
			: Bio::MatchTemplate(matchTemplate->Finger, matchTemplate->ValidationData)
		{	
            // ��������� ������������ ������
            if (ticketData->Length > 20) throw gcnew ArgumentException(); 

            // ��������� ���������� ���������
			this->ticketData = ticketData; this->loginType = loginType;
		}
        // �������� ��������� ������������� ������
		public: String^ GetEncoded(String^ pinCode); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ������ �������������� �������������� ������� Laser ��� ������������
	///////////////////////////////////////////////////////////////////////////
	public ref class BiometricService : Auth::BiometricService
    {
		// ������������ ���������
		private: static initonly Bio::Athena::Provider^ provider = gcnew Bio::Athena::Provider(); 

        // �����������
		public: BiometricService(LibApplet^ applet, bool canLogin) 
			
			// ��������� ���������� ���������
			: Auth::BiometricService(applet, "USER") 
		
			// ��������� ���������� ���������
			{ this->canLogin = canLogin; } private: bool canLogin; 

		// ����������� �������������
		public: virtual property bool CanLogin { bool get() override 
		{ 
			// ����������� �������������
			return canLogin && Provider->EnumerateReaders()->Length > 0; 
		}}
		// ����������� ���������
		public: virtual property bool CanChange { bool get() override 
		{ 
			// ����������� ���������
			return Provider->EnumerateReaders()->Length > 0; 
		}}
		// ���������� ������� ��������������
		public: virtual AuthenticationInfo^ GetAuthenticationInfo() override; 

        // ������������ ���������
		public: property Bio::Provider^ Provider 
		{ 
			// ������������ ���������
			virtual Bio::Provider^ get() override { return provider; } 
		}
        // ������������ ������ FAR � �������� ����������
        public: int GetFAR(); public: int GetImageQuality(); 

        // ������������ ����� ����������
        public: virtual int GetMaxAvailableFingers() override; 

        // ������������ ���������
		public: virtual array<Bio::Finger>^ GetAvailableFingers() override;

		// ������� ������ ��� �������� ���������
		public: virtual Bio::MatchTemplate^ CreateTemplate(Bio::Finger finger, Bio::Image^ image) override; 

		// ��������� ������������ ���������
		protected: virtual Bio::MatchTemplate^ MatchTemplate(Bio::MatchTemplate^ matchTemplate) override; 

        // ���������� ���������
		protected: virtual void EnrollTemplates(array<Bio::EnrollTemplate^>^ enrollTemplates) override; 
	}; 
}}}}}

