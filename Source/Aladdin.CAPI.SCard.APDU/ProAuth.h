#pragma once 
#include "AppletAuth.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������������� �������������� ������� Pro
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseService : LibPinService
    {
        // �����������
		public: LibResponseService(LibApplet^ applet, String^ user)

			// ��������� ���������� ���������
			: LibPinService(applet, user, true) {}

        // ���������� ������
        public: virtual void SetPassword(String^ pinCode) override; 

		// �������� salt-��������
		private: array<BYTE>^ GetSalt(); 
    }; 
	///////////////////////////////////////////////////////////////////////////
	// ������ ������������� �������������� ������� Pro Java
	///////////////////////////////////////////////////////////////////////////
	public ref class LibResponseServiceJava : LibPinService
    {
        // �����������
		public: LibResponseServiceJava(LibApplet^ applet, String^ user)

			// ��������� ���������� ���������
			: LibPinService(applet, user, true) {}

        // ���������� ������
        public: virtual void SetPassword(String^ pinCode) override; 

		// �������� salt-��������
		private: array<BYTE>^ GetSalt(); 
	}; 
}
}}}}
