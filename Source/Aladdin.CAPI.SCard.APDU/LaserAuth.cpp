#include "StdAfx.h"
#include "LaserApplet.h"
#include "LaserAuth.h"
#include <libapdu.laserbio.h>
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "LaserAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Преобразования идентификаторов пальца
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
// Сервис двухсторонней аутентификации апплета Laser для администратора
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Laser::LibResponseService::SetPassword(String^ pinCode)
{$
    // закодировать пароль
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); 

	// проверить размер пароля
	if (encoded->Length > 24) throw gcnew AuthenticationException(); 
	
	// дополнить пароль
	Array::Resize(encoded, 24); pin_ptr<BYTE> ptrEncoded = &encoded[0];

	// выполнить команду GET CHALLENGE
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x00, 0x84, 0x00, 0x00, gcnew array<BYTE>(0), 8
	); 
	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response) || response->Data->Length != 8) 
	{
		// при ошибке выбросить исключение
		throw gcnew AuthenticationException();
	}
    // указать адрес случайных данных
	array<BYTE>^ challenge = response->Data; pin_ptr<BYTE> ptrChallenge = &challenge[0]; 

	// выделить буфер для ответных данных
	array<BYTE>^ reply = gcnew array<BYTE>(8); pin_ptr<BYTE> ptrReply = &reply[0]; 

    // вычислить ответ
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, ptrEncoded, 24, ptrReply, 8); 

	// выполнить команду SELECT (FILE = {0x3F00})
	ISO7816::ResponseException::Check(((Applet^)Target)->Session->SendCommand(
		0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE>(0), 0
	)); 
	// выполнить команду SELECT (FILE = {0x3F00, 0x0010})
	ISO7816::ResponseException::Check(((Applet^)Target)->Session->SendCommand(
		0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE> { 0x00, 0x10}, 0
	)); 
	// выполнить команду EXTERNAL AUTHENTICATE
	response = ((Applet^)Target)->Session->SendCommand(0x00, 0x82, 0x00, 0x85, reply, 0); 

	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

void Aladdin::CAPI::SCard::APDU::Laser::LibResponseService::ChangePassword(String^ pinCode)
{$
    // закодировать пароль
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); 

	// проверить размер пароля
	if (encoded->Length > 24) throw gcnew ArgumentOutOfRangeException(); 

	// создать структуру данных
	array<BYTE>^ data = gcnew array<BYTE> { 
		0x62, 0x1A, 0x82, 0x18,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}; 
	// скопировать пароль
	Array::Copy(encoded, 0, data, 4, encoded->Length); 

	// выполнить команду CHANGE REFERENCE DATA
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x80, 0x24, 0x00, 0x10, data, 0
	); 
	// проверить ошибку доступа к файлу
	if (response->SW == 0x6982) throw gcnew LibException(response->SW); 
	
	// проверить отсутствие ошибок
	ISO7816::ResponseException::Check(response); 
}

///////////////////////////////////////////////////////////////////////////
// Тикет биометрической аутентификации
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::SCard::APDU::Laser::LibBiometricTicket::GetEncoded(String^ pinCode)
{$
    // обработать отсутствие пин-кода
    if (pinCode == nullptr) pinCode = String::Empty; 

    // закодировать данные
	array<BYTE>^ pinBytes = Encoding::Unicode->GetBytes(pinCode);

    // создать структуру параметров
	libapdu::JcAuthTicket ticketObj = { loginType }; 

    // скопировать данные тикета
	Marshal::Copy(ticketData, 0, IntPtr(ticketObj.bioPlain), sizeof(ticketObj.bioPlain));

    // скопировать закодированный пин-код
	Marshal::Copy(pinBytes, 0, IntPtr(ticketObj.pin), pinBytes->Length);

    // закодировать тикет
	libapdu::TBytes ticketBytes = libapdu::JcAuthHelper::encode_ticket(ticketObj);

    // выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>((int)ticketBytes.size());

    // скопировать полученный тикет в буфер
	Marshal::Copy(IntPtr(&ticketBytes[0]), buffer, 0, buffer->Length);

    // получить текстовое представление тикета			
	return Encoding::ASCII->GetString(buffer);
}

///////////////////////////////////////////////////////////////////////////
// Сервис биометрической аутентификации апплета Laser для пользователя
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::AuthenticationInfo^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetAuthenticationInfo()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
		// выбрать ключевой объект
		TWord keyPath[] = { 0x3F00, 0x0023 }; pin.select(TPath(keyPath, keyPath + 2));

		// получить число попыток аутентификации
		libapdu::CPinInfo pinInfo = pin.info();

		// прочитать число попыток
		int maximumAttempts = pinInfo.attemptsMax; 
		int currentAttempts = pinInfo.attemptsNow; 

        // скорректировать число попыток
		if (maximumAttempts == 0xFF) maximumAttempts = Int32::MaxValue;
		if (currentAttempts == 0xFF) currentAttempts = Int32::MaxValue;

        // вернуть число попыток		
		return gcnew AuthenticationInfo(maximumAttempts, currentAttempts); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetImageQuality()
{$
    // открыть объект файловой системы
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);
    
	// определить размер файла
	int fileSize = file->GetInfo().ObjectSize; 

    // прочитать содержимое файла
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // для всех блоков данных
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // проверить тип данных
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02C9) return buffer[pos + 3]; 
	}
	return 0;
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetFAR()
{$
    // открыть объект файловой системы
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);

	// определить размер файла
	int fileSize = file->GetInfo().ObjectSize; 
    
    // прочитать содержимое файла
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // выделить память для результата
    array<BYTE>^ value = gcnew array<BYTE>(4); 

    // для всех блоков данных
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // проверить тип данных
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02CA) 
		{
            // скопировать данные
            Array::Copy(buffer, pos + 3, value, 0, buffer[pos + 2]); break; 
		}
	}
    // вычислить значение 
    int maxFarLevel = (value[0] << 24) | (value[1] << 16) | (value[2] << 8) | value[3]; 

    // вернуть преобразованное значение
	if (maxFarLevel >= 0x7fffffff /    100) return 100; 
    if (maxFarLevel >= 0x7fffffff /   1000) return 1000; 
    if (maxFarLevel >= 0x7fffffff /  10000) return 10000; 
    if (maxFarLevel >= 0x7fffffff / 100000) return 100000;

    // вернуть преобразованное значение
	return 1000000;
}

int Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetMaxAvailableFingers()
{$
    // открыть объект файловой системы
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xEEEE);
    
	// определить размер файла
	int fileSize = file->GetInfo().ObjectSize; 

    // прочитать содержимое файла
    array<BYTE>^ buffer = gcnew array<BYTE>(fileSize); file->Read(buffer, 0); 

    // для всех блоков данных
	for (int pos = 0; pos + 3 < buffer->Length; pos += 3 + buffer[pos + 2])
	{
        // проверить тип данных
    	if (MAKEWORD(buffer[pos + 1], buffer[pos]) == 0x02CB) return buffer[pos + 3];
	}
	return 0;
}

array<Aladdin::CAPI::Bio::Finger>^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::GetAvailableFingers() 
{$
    // получить интерфейс LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try {
		// выбрать ключевой объект
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

		// прочитать список пальцев
		libapdu::TBytes enrolledFingers = bio.getEnrolledFingers();

		// создать список пальцев для результата
		array<Bio::Finger>^ fingers = gcnew array<Bio::Finger>(
			(int)enrolledFingers.size()
		);
		// для всех полученных пальцев
		for (int i = 0; i < fingers->Length; i++)
		{
			// создать объект пальца
			fingers[i] = ConvertFromLibAPDU(enrolledFingers[i]);
		}
		return fingers;
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

Aladdin::CAPI::Bio::MatchTemplate^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::CreateTemplate(
	Bio::Finger finger, Bio::Image^ image)
{$
    // получить интерфейс LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); int index = ConvertToLibAPDU(finger);
	try { 
		// выбрать ключевой объект
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

		// прочитать требуемые данные
		libapdu::TBytes biometricData = bio.readPublicBioData(index + 1);

		// выделить буфер требуемого размера
		array<BYTE>^ publicData = gcnew array<BYTE>((int)biometricData.size()); 

		// скопировать данные в буфер
		Marshal::Copy(IntPtr(&biometricData[0]), publicData, 0, publicData->Length); 

		// создать шаблон для проверки отпечатка
		return provider->CreateMatchTemplate(finger, image, publicData); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

Aladdin::CAPI::Bio::MatchTemplate^ 
Aladdin::CAPI::SCard::APDU::Laser::BiometricService::MatchTemplate(Bio::MatchTemplate^ matchTemplate)
{$
	// проверить наличие параметров
	if (matchTemplate == nullptr) throw gcnew ArgumentException(); 

    // получить интерфейс LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try { 
		// выбрать ключевой объект
		TWord keyPath[] = { 0x3F00, 0x0023 }; bio.select(TPath(keyPath, keyPath + 2));

	    // выделить буфер требуемого размера
	    array<BYTE>^ data = (array<BYTE>^)matchTemplate->ValidationData; 

        // скопировать данные шаблона в буфер
        libapdu::TBytes tmp(data->Length, 0); Marshal::Copy(data, 0, IntPtr(&tmp[0]), data->Length);

        // проверить корректность отпечатка
	    libapdu::TBytes ticketData = bio.appletMoC(tmp, ConvertToLibAPDU(matchTemplate->Finger) + 1);

        // выделить буфер требуемого размера
        data = gcnew array<BYTE>((int)ticketData.size()); 

        // скопировать данные тикета в буфер
        Marshal::Copy(IntPtr(&ticketData[0]), data, 0, data->Length); 

        // вернуть созданный тикет
	    return gcnew LibBiometricTicket(matchTemplate, bio.loginType(), data);
	}
	// преобразовать тип исключения
	catch(libapdu::IException &ex) { throw gcnew APDU::LibException(ex.code()); }
}

void Aladdin::CAPI::SCard::APDU::Laser::BiometricService::EnrollTemplates(
	array<Bio::EnrollTemplate^>^ enrollTemplates)
{$
    // прочитать максимальное число отпечатков
    if (enrollTemplates == nullptr || GetMaxAvailableFingers() > enrollTemplates->Length)
    {
        // при ошибке выбросить исключение
        throw gcnew ArgumentOutOfRangeException();
    }
    // получить интерфейс LibAPDU
	libapdu::IAppBio& bio = ((LibApplet^)Target)->Token()->bio(); 
	try { 
		// указать путь объекта
		TWord keyPath[] = { 0x3F00, 0x0023 }; 
		
		// прочитать список зарегистрированных отпечатков
		libapdu::TBytes enrolledFingers = bio.getEnrolledFingers();

		// для всех регистрируемых отпечатков
		for each (CAPI::Bio::EnrollTemplate^ enrollTemplate in enrollTemplates)		
        {
			// определить идентификатор пальца
			BYTE index = ConvertToLibAPDU(enrollTemplate->Finger); 

			// получить закрытые и открытые данные данные
			array<BYTE>^ refData = (array<BYTE>^)enrollTemplate->PrivateData;
			array<BYTE>^ pubData = (array<BYTE>^)enrollTemplate->PublicData ;

			// выделить буферы требуемого размера
			libapdu::TBytes refTmp(refData->Length, 0);
			libapdu::TBytes pubTmp(pubData->Length, 0);

			// скопировать данные в буферы
			Marshal::Copy(refData, 0, IntPtr(&refTmp[0]), refData->Length);
    		Marshal::Copy(pubData, 0, IntPtr(&pubTmp[0]), pubData->Length);

			// выбрать ключевой объект
			bio.select(TPath(keyPath, keyPath + 2));

			// зарегистрировать шаблон на смарт-карте
			bio.enrollTemplate(refTmp, pubTmp, index + 1);

			// найти указанный палец в списке зарегистрированных
			libapdu::TBytes::iterator itEnrolled = std::find(
				enrolledFingers.begin(), enrolledFingers.end(), index
			);
			// удалить указанный палец из списка зарегистрированных
			if (enrolledFingers.end() != itEnrolled) enrolledFingers.erase(itEnrolled);
		}
		// для всех оставшихся отпечатков пальцев
		for (libapdu::TBytes::iterator it = enrolledFingers.begin(); it != enrolledFingers.end(); it++)
		{
			// выбрать ключевой объект и удалить шаблон отпечатка 
			bio.select(TPath(keyPath, keyPath + 2)); bio.eraseTemplate((*it) + 1);
		}
		// получить допустимый способ аутентификации
		libapdu::enumAuthMethod loginType = bio.loginType();

		// при наличии только биометрической аутентификации
		if (loginType == AuthTypeBIO && enrollTemplates->Length > 0)
		{
			// открыть объект файловой системы
			IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x3000, 0xC000);
    
			// прочитать данные из файла
			array<BYTE>^ flagData = gcnew array<BYTE>(1); file->Read(flagData, 0x60);

			// добавить флаг CKF_USER_PIN_INITIALIZED
			flagData[0] |= 0x08; file->Write(flagData, 0x60);
		}
	}			
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew APDU::LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// Апплет Laser
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Laser::Applet::HasAdminAuthentication()
{$
	// выполнить команду SELECT (FILE = {0x3F00})
	ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0xA4, 0x00, 0x00, gcnew array<BYTE>(0), 0)); 

	// выполнить команду SELECT (FILE = {0x3F00, 0x0010})
	ISO7816::Response^ response = Session->SendCommand(
		0x80, 0xA4, 0x00, 0x0C, gcnew array<BYTE> { 0x00, 0x10 }, 0
	); 
	// проверить отсуствие ошибок
	ISO7816::ResponseException::Check(response); 

	// раскодировать данные
	ISO7816::DataObjectTemplate^ tlv = (ISO7816::DataObjectTemplate^)
		ISO7816::TagScheme::Default->Decode(
			ISO7816::Authority::ISO7816, ASN1::Encodable::Decode(response->Data)
	); 
	// извлечь FILE CONTROL PARAMETERS
	array<ISO7816::DataObject^>^ controlParameters = tlv[ISO7816::Tag::FileControlParameters];

	// при наличии параметров
	if (controlParameters->Length == 0) return 0; 
		
	// извлечь внутреннюю информацию
	array<ISO7816::DataObject^>^ proprietaryData = 
		((ISO7816::DataObjectTemplate^)controlParameters[0])
			[ISO7816::Tag::Context(0x05, ASN1::PC::Primitive)]; 

	// проверить наличие информации
	if (proprietaryData->Length == 0) return 0; array<BYTE>^ data = proprietaryData[0]->Content; 

	// указать сравниваемые значения
	array<BYTE>^ dataAuth1 = gcnew array<BYTE>{ 0x00, 0x01, 0x00 }; 
	array<BYTE>^ dataAuth2 = gcnew array<BYTE>{ 0x01, 0x01, 0x10 }; 

	// проверить наличие аутентификации
	if (Arrays::Equals(data, 0, dataAuth1, 0, 3)) return 1; 
	if (Arrays::Equals(data, 0, dataAuth2, 0, 3)) return 2; 

	return 0; 
}

array<Type^>^ Aladdin::CAPI::SCard::APDU::Laser::Applet::GetAuthenticationTypes(String^ user)
{$
	// вернуть аутентификацию администратора
	if (String::Compare(user, "ADMIN", true) == 0) return LibApplet::GetAuthenticationTypes(user); 

	// выполнить команду GET DATA
	ISO7816::Response^ response = Session->SendCommand(
		0x80, 0xCB, 0x01, 0x80, gcnew array<BYTE>(0), 0
	); 
	// при наличии ошибок
	if (ISO7816::Response::Error(response) || response->Data->Length < 3)
	{
		// вызвать базовую функцию
		return LibApplet::GetAuthenticationTypes(user); 
	}
	else {
		// указать тип аутентификации
		Type^ type1 = Auth::BiometricCredentials::typeid; 
		Type^ type2 = Auth::PasswordCredentials ::typeid; 

		// указать наличие биометрической и парольной аутентификации
		return gcnew array<Type^> { type1, type2 };
	}
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Laser::Applet::GetAuthenticationService(
	String^ user, Type^ authenticationType) 
{$
	// для биометрической аутентификации
	if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// проверить аутентификацию пользователя
		if (String::Compare(user, "ADMIN", true) == 0) return nullptr; 

		// выполнить команду GET DATA
		ISO7816::Response^ response = Session->SendCommand(
			0x80, 0xCB, 0x01, 0x80, gcnew array<BYTE>(0), 0
		); 
		// при отсутствии ошибок
		if (!ISO7816::Response::Error(response) && response->Data->Length >= 3)
		{
			// получить состояние аутентификации
			switch (Token()->bio().loginType())
			{
			case libapdu::AuthTypePIN: 

				// вернуть сервис аутентификации
				return gcnew BiometricService(this, false); 

			case libapdu::AuthTypeBIO:
			case libapdu::AuthTypeBIOandPIN:
			case libapdu::AuthTypeBIOorPIN:
	
				// вернуть сервис аутентификации
				return gcnew BiometricService(this, true); 
			}
		}
	}
	// для парольной аутентификации администратора
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// для аутентификации пользователя
		if (String::Compare(user, "ADMIN", true) != 0) 
		{
			// получить состояние аутентификации
			switch (Token()->bio().loginType())
			{
			case libapdu::AuthTypeBIO:

				// вернуть сервис аутентификации
				return gcnew LibPinService(this, user, false); 

			case libapdu::AuthTypePIN: 
			case libapdu::AuthTypeBIOandPIN:
			case libapdu::AuthTypeBIOorPIN:
	
				// вернуть сервис аутентификации
				return gcnew LibPinService(this, user, true); 
			}
		}
		// проверить наличие аутентификации
		else switch (HasAdminAuthentication())
		{
		// вернуть парольную аутентификацию
		case 1: return gcnew LibPinService(this, user, true); 

		// вернуть challenge-response-аутентификацию
		case 2: return gcnew LibResponseService(this); 
		}
	}
	return nullptr; 
}
