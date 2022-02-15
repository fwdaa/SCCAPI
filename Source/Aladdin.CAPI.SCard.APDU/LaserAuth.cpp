#include "StdAfx.h"
#include "LaserApplet.h"
#include "LaserAuth.h"
#include <libapdu.laserbio.h>
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "LaserAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������������� ��������������� ������
///////////////////////////////////////////////////////////////////////////
static BYTE ConvertToLibAPDU(Aladdin::CAPI::Bio::Finger finger)
{
    switch (finger)
    {
    case Aladdin::CAPI::Bio::Finger::LeftLittle : return 0; 
    case Aladdin::CAPI::Bio::Finger::LeftRing   : return 1;
    case Aladdin::CAPI::Bio::Finger::LeftMiddle : return 2;
    case Aladdin::CAPI::Bio::Finger::LeftIndex  : return 3;
    case Aladdin::CAPI::Bio::Finger::LeftThumb  : return 4;
    case Aladdin::CAPI::Bio::Finger::RightLittle: return 9;
    case Aladdin::CAPI::Bio::Finger::RightRing  : return 8;
    case Aladdin::CAPI::Bio::Finger::RightMiddle: return 7;
    case Aladdin::CAPI::Bio::Finger::RightIndex : return 6;
    case Aladdin::CAPI::Bio::Finger::RightThumb : return 5;
    }
    return 0xFF; 
}

static Aladdin::CAPI::Bio::Finger ConvertFromLibAPDU(BYTE finger)
{
    switch (finger)
    {
    case 0: return Aladdin::CAPI::Bio::Finger::LeftLittle ; 
    case 1: return Aladdin::CAPI::Bio::Finger::LeftRing   ;
    case 2: return Aladdin::CAPI::Bio::Finger::LeftMiddle ;
    case 3: return Aladdin::CAPI::Bio::Finger::LeftIndex  ;
    case 4: return Aladdin::CAPI::Bio::Finger::LeftThumb  ;
    case 9: return Aladdin::CAPI::Bio::Finger::RightLittle;
    case 8: return Aladdin::CAPI::Bio::Finger::RightRing  ;
    case 7: return Aladdin::CAPI::Bio::Finger::RightMiddle;
    case 6: return Aladdin::CAPI::Bio::Finger::RightIndex ;
    case 5: return Aladdin::CAPI::Bio::Finger::RightThumb ;
    }
    return Aladdin::CAPI::Bio::Finger::None; 
}

///////////////////////////////////////////////////////////////////////////
// ������ ������������� �������������� ������� Laser ��� ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Laser::LibResponseService::SetPassword(String^ pinCode)
{$
    // ������������ ������
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); 

	// ��������� ������ ������
	if (encoded->Length > 24) throw gcnew AuthenticationException(); 
	
	// ��������� ������
	Array::Resize(encoded, 24); pin_ptr<BYTE> ptrEncoded = &encoded[0];

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
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, ptrEncoded, 24, ptrReply, 8); 

	// ��������� ������� SELECT (FILE = {0x3F00})
	ISO7816::ResponseException::Check(((Applet^)Target)->Session->SendCommand(
		0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE>(0), 0
	)); 
	// ��������� ������� SELECT (FILE = {0x3F00, 0x0010})
	ISO7816::ResponseException::Check(((Applet^)Target)->Session->SendCommand(
		0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE> { 0x00, 0x10}, 0
	)); 
	// ��������� ������� EXTERNAL AUTHENTICATE
	response = ((Applet^)Target)->Session->SendCommand(0x00, 0x82, 0x00, 0x85, reply, 0); 

	// ��������� ���������� ������
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

void Aladdin::CAPI::SCard::APDU::Laser::LibResponseService::ChangePassword(String^ pinCode)
{$
    // ������������ ������
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); 

	// ��������� ������ ������
	if (encoded->Length > 24) throw gcnew ArgumentOutOfRangeException(); 

	// ������� ��������� ������
	array<BYTE>^ data = gcnew array<BYTE> { 
		0x62, 0x1A, 0x82, 0x18,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}; 
	// ����������� ������
	Array::Copy(encoded, 0, data, 4, encoded->Length); 

	// ��������� ������� CHANGE REFERENCE DATA
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x80, 0x24, 0x00, 0x10, data, 0
	); 
	// ��������� ������ ������� � �����
	if (response->SW == 0x6982) throw gcnew LibException(response->SW); 
	
	// ��������� ���������� ������
	ISO7816::ResponseException::Check(response); 
}

///////////////////////////////////////////////////////////////////////////
// ����� �������������� ��������������
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::SCard::APDU::Laser::LibBiometricTicket::GetEncoded(String^ pinCode)
{$
    // ���������� ���������� ���-����
    if (pinCode == nullptr) pinCode = String::Empty; 

    // ������������ ������
	array<BYTE>^ pinBytes = Encoding::Unicode->GetBytes(pinCode);

    // ������� ��������� ����������
	libapdu::JcAuthTicket ticketObj = { loginType }; 

    // ����������� ������ ������
	Marshal::Copy(ticketData, 0, IntPtr(ticketObj.bioPlain), sizeof(ticketObj.bioPlain));

    // ����������� �������������� ���-���
	Marshal::Copy(pinBytes, 0, IntPtr(ticketObj.pin), pinBytes->Length);

    // ������������ �����
	libapdu::TBytes ticketBytes = libapdu::JcAuthHelper::encode_ticket(ticketObj);

    // �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>((int)ticketBytes.size());

    // ����������� ���������� ����� � �����
	Marshal::Copy(IntPtr(&ticketBytes[0]), buffer, 0, buffer->Length);

    // �������� ��������� ������������� ������			
	return Encoding::ASCII->GetString(buffer);
}

///////////////////////////////////////////////////////////////////////////
// ������ �������������� �������������� ������� Laser ��� ������������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::AuthenticationInfo^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetAuthenticationInfo()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
		// ������� �������� ������
		TWord keyPath[] = { 0x3F00, 0x0023 }; pin.select(TPath(keyPath, keyPath + 2));

		// �������� ����� ������� ��������������
		libapdu::CPinInfo pinInfo = pin.info();

		// ��������� ����� �������
		int maximumAttempts = pinInfo.attemptsMax; 
		int currentAttempts = pinInfo.attemptsNow; 

        // ��������������� ����� �������
		if (maximumAttempts == 0xFF) maximumAttempts = Int32::MaxValue;
		if (currentAttempts == 0xFF) currentAttempts = Int32::MaxValue;

        // ������� ����� �������		
		return gcnew AuthenticationInfo(maximumAttempts, currentAttempts); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetImageQuality()
{$
    // ������� ������ �������� �������
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);
    
	// ���������� ������ �����
	int fileSize = file->GetInfo().ObjectSize; 

    // ��������� ���������� �����
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // ��� ���� ������ ������
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // ��������� ��� ������
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02C9) return buffer[pos + 3]; 
	}
	return 0;
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetFAR()
{$
    // ������� ������ �������� �������
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);

	// ���������� ������ �����
	int fileSize = file->GetInfo().ObjectSize; 
    
    // ��������� ���������� �����
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // �������� ������ ��� ����������
    array<BYTE>^ value = gcnew array<BYTE>(4); 

    // ��� ���� ������ ������
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // ��������� ��� ������
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02CA) 
		{
            // ����������� ������
            Array::Copy(buffer, pos + 3, value, 0, buffer[pos + 2]); break; 
		}
	}
    // ��������� �������� 
    int maxFarLevel = (value[0] << 24) | (value[1] << 16) | (value[2] << 8) | value[3]; 

    // ������� ��������������� ��������
	if (maxFarLevel >= 0x7fffffff /    100) return 100; 
    if (maxFarLevel >= 0x7fffffff /   1000) return 1000; 
    if (maxFarLevel >= 0x7fffffff /  10000) return 10000; 
    if (maxFarLevel >= 0x7fffffff / 100000) return 100000;

    // ������� ��������������� ��������
	return 1000000;
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetMaxAvailableFingers()
{$
    // ������� ������ �������� �������
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);
    
	// ���������� ������ �����
	int fileSize = file->GetInfo().ObjectSize; 

    // ��������� ���������� �����
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // ��� ���� ������ ������
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // ��������� ��� ������
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02CB) return buffer[pos + 3];
	}
	return 0;
}

array<Aladdin::CAPI::Bio::Finger>^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetAvailableFingers() 
{$
    // �������� ��������� LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try {
		// ������� �������� ������
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

		// ��������� ������ �������
		libapdu::TBytes enrolledFingers = bio.getEnrolledFingers();

		// ������� ������ ������� ��� ����������
		array<Bio::Finger>^ fingers = gcnew array<Bio::Finger>(
			(int)enrolledFingers.size()
		);
		// ��� ���� ���������� �������
		for (int i = 0; i < fingers->Length; i++)
		{
			// ������� ������ ������
			fingers[i] = ConvertFromLibAPDU(enrolledFingers[i]);
		}
		return fingers;
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

Aladdin::CAPI::Bio::MatchTemplate^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::CreateTemplate(
	Bio::Finger finger, Bio::Image^ image)
{$
    // �������� ��������� LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); int index = ConvertToLibAPDU(finger);
	try { 
		// ������� �������� ������
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

		// ��������� ��������� ������
		libapdu::TBytes biometricData = bio.readPublicBioData(index + 1);

		// �������� ����� ���������� �������
		array<BYTE>^ publicData = gcnew array<BYTE>((int)biometricData.size()); 

		// ����������� ������ � �����
		Marshal::Copy(IntPtr(&biometricData[0]), publicData, 0, publicData->Length); 

		// ������� ������ ��� �������� ���������
		return provider->CreateMatchTemplate(finger, image, publicData); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

Aladdin::CAPI::Bio::MatchTemplate^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::MatchTemplate(Bio::MatchTemplate^ matchTemplate)
{$
	// ��������� ������� ����������
	if (matchTemplate == nullptr) throw gcnew ArgumentException(); 

    // �������� ��������� LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try { 
		// ������� �������� ������
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

	    // �������� ����� ���������� �������
	    array<BYTE>^ data = (array<BYTE>^)matchTemplate->ValidationData; 

        // ����������� ������ ������� � �����
        libapdu::TBytes tmp(data->Length, 0); Marshal::Copy(data, 0, IntPtr(&tmp[0]), data->Length);

        // ��������� ������������ ���������
	    libapdu::TBytes ticketData = bio.appletMoC(tmp, ConvertToLibAPDU(matchTemplate->Finger) + 1);

        // �������� ����� ���������� �������
        data = gcnew array<BYTE>((int)ticketData.size()); 

        // ����������� ������ ������ � �����
        Marshal::Copy(IntPtr(&ticketData[0]), data, 0, data->Length); 

        // ������� ��������� �����
	    return gcnew LibBiometricTicket(matchTemplate, bio.loginType(), data);
	}
	// ������������� ��� ����������
	catch(libapdu::IException &ex) { throw gcnew APDU::LibException(ex.code()); }
}

void Aladdin::CAPI::SCard::APDU::Laser::BiometricService::EnrollTemplates(
	array<Bio::EnrollTemplate^>^ enrollTemplates)
{$
    // ��������� ������������ ����� ����������
    if (enrollTemplates == nullptr || GetMaxAvailableFingers() > enrollTemplates->Length)
    {
        // ��� ������ ��������� ����������
        throw gcnew ArgumentOutOfRangeException();
    }
    // �������� ��������� LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try { 
		// ������� ���� �������
		TWord keyPath[] = { 0x3F00, 0x0023 }; 
		
		// ��������� ������ ������������������ ����������
		libapdu::TBytes enrolledFingers = bio.getEnrolledFingers();

		// ��� ���� �������������� ����������
		for each (CAPI::Bio::EnrollTemplate^ enrollTemplate in enrollTemplates)		
        {
			// ���������� ������������� ������
			BYTE index = ConvertToLibAPDU(enrollTemplate->Finger); 

			// �������� �������� � �������� ������ ������
			array<BYTE>^ refData = (array<BYTE>^)enrollTemplate->PrivateData;
			array<BYTE>^ pubData = (array<BYTE>^)enrollTemplate->PublicData ;

			// �������� ������ ���������� �������
			libapdu::TBytes refTmp(refData->Length, 0);
			libapdu::TBytes pubTmp(pubData->Length, 0);

			// ����������� ������ � ������
			Marshal::Copy(refData, 0, IntPtr(&refTmp[0]), refData->Length);
    		Marshal::Copy(pubData, 0, IntPtr(&pubTmp[0]), pubData->Length);

			// ������� �������� ������
			bio.select(TPath(keyPath, keyPath + 2));

			// ���������������� ������ �� �����-�����
			bio.enrollTemplate(refTmp, pubTmp, index + 1);

			// ����� ��������� ����� � ������ ������������������
			libapdu::TBytes::iterator itEnrolled = std::find(
				enrolledFingers.begin(), enrolledFingers.end(), index
			);
			// ������� ��������� ����� �� ������ ������������������
			if (enrolledFingers.end() != itEnrolled) enrolledFingers.erase(itEnrolled);
		}
		// ��� ���� ���������� ���������� �������
		for (libapdu::TBytes::iterator it = enrolledFingers.begin(); it != enrolledFingers.end(); it++)
		{
			// ������� �������� ������ � ������� ������ ��������� 
			bio.select(TPath(keyPath, keyPath + 2)); bio.eraseTemplate((*it) + 1);
		}
		// �������� ���������� ������ ��������������
		libapdu::enumAuthMethod loginType = bio.loginType();

		// ��� ������� ������ �������������� ��������������
		if (loginType == AuthTypeBIO && enrollTemplates->Length > 0)
		{
			// ������� ������ �������� �������
			IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xC000);
    
			// ��������� ������ �� �����
			array<BYTE>^ flagData = gcnew array<BYTE>(1); file->Read(flagData, 0x60);

			// �������� ���� CKF_USER_PIN_INITIALIZED
			flagData[0] |= 0x08; file->Write(flagData, 0x60);
		}
	}			
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// ������ Laser
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Laser::Applet::HasAdminAuthentication()
{$
	// ��������� ������� SELECT (FILE = {0x3F00})
	ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE>(0), 0)); 

	// ��������� ������� SELECT (FILE = {0x3F00, 0x0010})
	ISO7816::Response^ response = Session->SendCommand(
		0x80, 0xA4, 0x00, 0x0C, gcnew array<BYTE> { 0x00, 0x10 }, 0
	); 
	// ��������� ��������� ������
	ISO7816::ResponseException::Check(response); 

	// ������������� ������
	ISO7816::DataObjectTemplate^ tlv = (ISO7816::DataObjectTemplate^)
		ISO7816::TagScheme::Default->Decode(
			ISO7816::Authority::ISO7816, ASN1::Encodable::Decode(response->Data)
	); 
	// ������� FILE CONTROL PARAMETERS
	array<ISO7816::DataObject^>^ controlParameters = tlv[ISO7816::Tag::FileControlParameters];

	// ��� ������� ����������
	if (controlParameters->Length == 0) return 0; 
		
	// ������� ���������� ����������
	array<ISO7816::DataObject^>^ proprietaryData = 
		((ISO7816::DataObjectTemplate^)controlParameters[0])
			[ISO7816::Tag::Context(0x05, ASN1::PC::Primitive)]; 

	// ��������� ������� ����������
	if (proprietaryData->Length == 0) return 0; array<BYTE>^ data = proprietaryData[0]->Content; 

	// ������� ������������ ��������
	array<BYTE>^ dataAuth1 = gcnew array<BYTE>{ 0x00, 0x01, 0x00 }; 
	array<BYTE>^ dataAuth2 = gcnew array<BYTE>{ 0x01, 0x01, 0x10 }; 

	// ��������� ������� ��������������
	if (Arrays::Equals(data, 0, dataAuth1, 0, 3)) return 1; 
	if (Arrays::Equals(data, 0, dataAuth2, 0, 3)) return 2; 

	return 0; 
}

array<Type^>^ Aladdin::CAPI::SCard::APDU::Laser::Applet::GetAuthenticationTypes(String^ user)
{$
	// ������� �������������� ��������������
	if (String::Compare(user, "ADMIN", true) == 0) return LibApplet::GetAuthenticationTypes(user); 

	// ��������� ������� GET DATA
	ISO7816::Response^ response = Session->SendCommand(
		0x80, 0xCB, 0x01, 0x80, gcnew array<BYTE>(0), 0
	); 
	// ��� ������� ������
	if (ISO7816::Response::Error(response) || response->Data->Length < 3)
	{
		// ������� ������� �������
		return LibApplet::GetAuthenticationTypes(user); 
	}
	else {
		// ������� ��� ��������������
		Type^ type1 = Auth::BiometricCredentials::typeid; 
		Type^ type2 = Auth::PasswordCredentials ::typeid; 

		// ������� ������� �������������� � ��������� ��������������
		return gcnew array<Type^> { type1, type2 };
	}
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Laser::Applet::GetAuthenticationService(
	String^ user, Type^ authenticationType) 
{$
	// ��� �������������� ��������������
	if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// ��������� �������������� ������������
		if (String::Compare(user, "ADMIN", true) == 0) return nullptr; 

		// ��������� ������� GET DATA
		ISO7816::Response^ response = Session->SendCommand(
			0x80, 0xCB, 0x01, 0x80, gcnew array<BYTE>(0), 0
		); 
		// ��� ���������� ������
		if (!ISO7816::Response::Error(response) && response->Data->Length >= 3)
		{
			// �������� ��������� ��������������
			switch (Token()->bio().loginType())
			{
			case libapdu::AuthTypePIN: 

				// ������� ������ ��������������
				return gcnew BiometricService(this, false); 

			case libapdu::AuthTypeBIO:
			case libapdu::AuthTypeBIOandPIN:
			case libapdu::AuthTypeBIOorPIN:
	
				// ������� ������ ��������������
				return gcnew BiometricService(this, true); 
			}
		}
	}
	// ��� ��������� �������������� ��������������
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// ��� �������������� ������������
		if (String::Compare(user, "ADMIN", true) != 0) 
		{
			// �������� ��������� ��������������
			switch (Token()->bio().loginType())
			{
			case libapdu::AuthTypeBIO:

				// ������� ������ ��������������
				return gcnew LibPinService(this, user, false); 

			case libapdu::AuthTypePIN: 
			case libapdu::AuthTypeBIOandPIN:
			case libapdu::AuthTypeBIOorPIN:
	
				// ������� ������ ��������������
				return gcnew LibPinService(this, user, true); 
			}
		}
		// ��������� ������� ��������������
		else switch (HasAdminAuthentication())
		{
		// ������� ��������� ��������������
		case 1: return gcnew LibPinService(this, user, true); 

		// ������� challenge-response-��������������
		case 2: return gcnew LibResponseService(this); 
		}
	}
	return nullptr; 
}
