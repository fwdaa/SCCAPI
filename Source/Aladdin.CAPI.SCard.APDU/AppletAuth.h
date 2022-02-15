#pragma once 
#include "Applet.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// ������ ��������� �������������� �������
///////////////////////////////////////////////////////////////////////////
public ref class LibPinService : Auth::PasswordService
{
	// ����������� ��������������
	private: bool canLogin; 

    // �����������
	public: LibPinService(LibApplet^ applet, String^ user, bool canLogin) 

        // ��������� ���������� ���������
		: Auth::PasswordService(applet, user) { this->canLogin = canLogin; } 

	// ����������� �������������
	public: virtual property bool CanLogin { bool get() override { return canLogin; }}
	// ����������� ���������
	public: virtual property bool CanChange { bool get() override { return true; }}

	// ���������� ������� ��������������
	public: virtual AuthenticationInfo^ GetAuthenticationInfo() override; 

    // ���������� ������
    protected: virtual void SetPassword(String^ pinCode) override; 
    // �������� ������ 
	protected: virtual void ChangePassword(String^ pinCode) override;
}; 
}}}}

