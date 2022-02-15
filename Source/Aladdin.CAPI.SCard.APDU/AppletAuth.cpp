#include "stdafx.h"
#include "AppletAuth.h"

#define CK_Win32
#include "cryptoki/asepkcs.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ��������� �������������� �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::AuthenticationInfo^ 
Aladdin::CAPI::SCard::APDU::LibPinService::GetAuthenticationInfo()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
        // ��� ��������������
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // ������� ��� ��������������
		    pin.select(pin.pathAdmin());
        }
        // ������� ��� �������������� ��� ������������
        else pin.select(pin.pathUser());

        // �������� ����� ������� ��������������
		libapdu::CPinInfo pinInfo = pin.info(); 

		// ��������� ����� �������
		int maximumAttempts = pinInfo.attemptsMax; 
		int currentAttempts = pinInfo.attemptsNow; 

        // ��������������� ����� �������
		if (maximumAttempts == 0xff) maximumAttempts = Int32::MaxValue;
		if (currentAttempts == 0xff) currentAttempts = Int32::MaxValue;

        // ������� ����� �������		
		return gcnew AuthenticationInfo(maximumAttempts, currentAttempts); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibPinService::SetPassword(String^ pinCode)
{$
    // ������������ PIN ��� UTF-8
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode);

    // �������� ����� ���������� �������
    libapdu::TBytes pinData(encoded->Length);

    // ����������� PIN � �����
    Marshal::Copy(encoded, 0, IntPtr(&pinData[0]), encoded->Length);

    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
        // ��� ��������������
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // ������� ��� ��������������
		    pin.select(pin.pathAdmin());
        }
        // ������� ��� �������������� ��� ������������
        else pin.select(pin.pathUser());

        // ��������� ��������������
		pin.login(pinData); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibPinService::ChangePassword(String^ pinCode)
{$
    // ������������ PIN ��� UTF-8
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode);

    // �������� ����� ���������� �������
    libapdu::TBytes pinData(encoded->Length);

    // ����������� PIN � �����
    Marshal::Copy(encoded, 0, IntPtr(&pinData[0]), encoded->Length);

    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try { 
        // ��� ��������������
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // ������� ��� ��������������
		    pin.select(pin.pathAdmin());
        }
        // ������� ��� �������������� ��� ������������
        else pin.select(pin.pathUser());

        // �������� ������������������ ������
		pin.change(pinData); 
    }
    // ���������� ��������� ������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// ������
///////////////////////////////////////////////////////////////////////////
array<Type^>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetAuthenticationTypes(String^ user)
{$ 
    // ��������� ������� �������������� �������������� 
	if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return gcnew array<Type^>(0); 

	// ������� ��������� ��������������
	return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
} 

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::LibApplet::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // ��������� ������� �������������� �������������� 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

    // ��������� ��� ��������������
    if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
    {
        // ������� �������� ��������������
        return gcnew LibPinService(this, user, true); 
    }
	return nullptr;
}

bool Aladdin::CAPI::SCard::APDU::LibApplet::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ��� ����������
	if (dynamic_cast<LibException^>(e) == nullptr) return false; 
			
	// ���������� ��� ������
	int code = (((LibException^)e)->ErrorCode); 

	// ��������� ��� ������
	return (code == libapdu::EPin) || (code == libapdu::ENotAllowed) || (code == 0x6982); 
}

bool Aladdin::CAPI::SCard::APDU::LibApplet::Logout()
{$ 
    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = Token()->pin(); 
	try {
		// �������� ��������������
		try { pin.logout(); return true; } 

	    // ������������� ��� ����������
		catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
	}
	// ������� ������� �������
	catch (Exception^) {} return false; 
}
