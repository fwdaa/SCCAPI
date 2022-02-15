#include "StdAfx.h"
#include "ProApplet.h"
#include "ProAuth.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ProAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ������������� �������������� ������� Pro
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::LibResponseService::GetSalt()
{$
	try { 
		// ������� ������ �������� ������� � ������ FIPS
		IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x000F);

		// ���������� ������ �����
		array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
		// ��������� ��������� ��������
		file->Read(salt, 0); return salt; 
	}
	// ��� ������������� ������
	catch (Exception^) 
	{
		// ������� ������ �������� �������
		IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x0002);

		// ���������� ������ �����
		array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
		// ��������� ��������� ��������
		file->Read(salt, 0); return salt; 
	}
}

void Aladdin::CAPI::SCard::APDU::Pro::LibResponseService::SetPassword(String^ pinCode)
{$
    // ������������ ������
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); pin_ptr<BYTE> ptrEncoded = &encoded[0];

	// ��������� ��������� ��������
	array<BYTE>^ salt = GetSalt(); pin_ptr<BYTE> ptrSalt = &salt[0]; BYTE key[24];

    // ������������ ���� ��� ��������� ��������� ��������
	libapdu::crypto_etoken_pro_sha1(1, ptrEncoded, encoded->Length, ptrSalt, salt->Length, &key[0], 24);

	// ��������� ������� GET CHALLENGE
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x00, 0x84, 0x00, 0x00, gcnew array<BYTE>(0), 8
	); 
	// ��������� ���������� ������
	if (ISO7816::Response::Error(response) || response->Data->Length != 8) 
	{
		// ��� ������ ��������� ����������
		throw gcnew AuthenticationException();
	}
    // ������� ����� ��������� ������
	array<BYTE>^ challenge = response->Data; pin_ptr<BYTE> ptrChallenge = &challenge[0]; 

	// �������� ����� ��� �������� ������
	array<BYTE>^ reply = gcnew array<BYTE>(8); pin_ptr<BYTE> ptrReply = &reply[0]; 

    // ��������� �����
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, &key[0], 24, ptrReply, 8); 

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
	}
	// ���������� ��������� ����������
	catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }

	// ��������� ������� EXTERNAL AUTHENTICATE
	response = ((Applet^)Target)->Session->SendCommand(0x00, 0x82, 0x00, 0x85, reply, 0); 

	// ��������� ���������� ������
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

///////////////////////////////////////////////////////////////////////////
// ������ eToken Pro
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Pro::Applet::HasAdminAuthentication()
try {$
	// ��������� ������� SELECT (FILE = {0x3F00, 0x6666})
	ISO7816::Response^ response = Session->SendCommand(
		0x00, 0xA4, 0x08, 0x00, gcnew array<BYTE> { 0x66, 0x66 }, 0
	); 
    // ��������� ���������� ������
    if (ISO7816::Response::Error(response)) return 2; 

	// ������������� FILE CONTROL INFORMATION
	ISO7816::DataObjectTemplate^ data = (ISO7816::DataObjectTemplate^)
		ISO7816::TagScheme::Default->Decode(
			ISO7816::Authority::ISO7816, ASN1::Encodable::Decode(response->Data)
	); 
	// ����� ������� SecurityAttribute
	array<ISO7816::DataObject^>^ item = data[ISO7816::Tag::Context(0x06, ASN1::PC::Primitive)]; 
	
    // ��������� ������� �����
    return ((item->Length == 0) || (item[0]->Content[1] == 0x05 && item[0]->Content[2] == 0x05)) ? 2 : 0; 
}
catch(Exception^) { return 2; } 

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Pro::Applet::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // ��������� ������� �������������� �������������� 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

	// ��� ��������� ��������������
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// ������� ������ ��������������
		return gcnew LibResponseService(this, user); 
	}
	// ������� ������� �������
	return LibApplet::GetAuthenticationService(user, authenticationType); 
}

///////////////////////////////////////////////////////////////////////////
// ������ ������������� �������������� ������� Pro Java
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::LibResponseServiceJava::GetSalt()
{$
	// ������� ������ �������� �������
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x000F);

	// ���������� ������ �����
	array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
	// ��������� ��������� ��������
	file->Read(salt, 0); return salt; 
}

void Aladdin::CAPI::SCard::APDU::Pro::LibResponseServiceJava::SetPassword(String^ pinCode)
{$
    // ������������ ������
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); pin_ptr<BYTE> ptrEncoded = &encoded[0];

	// ��������� ��������� ��������
	array<BYTE>^ salt = GetSalt(); pin_ptr<BYTE> ptrSalt = &salt[0]; BYTE key[24];

    // ������������ ���� ��� ��������� ��������� ��������
	libapdu::crypto_etoken_pro_sha1(1, ptrEncoded, encoded->Length, ptrSalt, salt->Length, &key[0], 24);

	// ��������� ������� GET CHALLENGE
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x80, 0x17, 0x00, 0x00, gcnew array<BYTE>(0), 8
	); 
	// ��������� ���������� ������
	if (ISO7816::Response::Error(response) || response->Data->Length != 8) 
	{
		// ��� ������ ��������� ����������
		throw gcnew AuthenticationException();
	}
    // ������� ����� ��������� ������
	array<BYTE>^ challenge = response->Data; pin_ptr<BYTE> ptrChallenge = &challenge[0]; 

	// �������� ����� ��� �������� ������
	array<BYTE>^ reply = gcnew array<BYTE>(10); 

	// ���������� ��������� ������
	pin_ptr<BYTE> ptrReply = &reply[2]; reply[0] = 0x10; reply[1] = 0x08; 

    // ��������� �����
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, &key[0], 24, ptrReply, 8); 

	// ��� ��������������
	if (String::Compare(User, "ADMIN", true) == 0)
	{
		// ������� ������� EXTERNAL AUTHENTICATE
		response = ((Applet^)Target)->Session->SendCommand(
			0x80, 0x11, 0x00, 0x21, reply, 0
		); 
	}
	else {
		// ������� ������� EXTERNAL AUTHENTICATE
		response = ((Applet^)Target)->Session->SendCommand(
			0x80, 0x11, 0x00, 0x11, reply, 0
		); 
	}
	// ��������� ���������� ������
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

///////////////////////////////////////////////////////////////////////////
// ������ eToken Pro Java
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Pro::AppletJava::HasAdminAuthentication()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = Token()->pin(); 
	try { 
		// ��������� ������� ����� ��������������
		pin.select(pin.pathAdmin()); return 2; 
	}
	// ���������� ��������� ������
	catch (libapdu::IException&) { return 0; }
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Pro::AppletJava::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // ��������� ������� �������������� �������������� 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

	// ��� ��������� ��������������
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// ������� ������ ��������������
		return gcnew LibResponseServiceJava(this, user); 
	}
	// ������� ������� �������
	return LibApplet::GetAuthenticationService(user, authenticationType); 
}
