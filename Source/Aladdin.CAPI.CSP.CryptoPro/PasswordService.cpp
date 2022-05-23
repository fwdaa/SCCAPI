#include "stdafx.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "PasswordService.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::PasswordService::SetPassword(String^ password) 
{$
	// �������� �������������� �������������
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(password); 

	// �������� ����� ���������� �������
	CRYPT_PIN_PARAM param; std::string strPasswd(encoded->Length + 1, 0); 

	// ����������� �������������� �������������
	Marshal::Copy(encoded, 0, IntPtr(&strPasswd[0]), encoded->Length); 

	// ������� ��������� �������� ������
	param.type = CRYPT_PIN_PASSWD; param.dest.passwd = &strPasswd[0];

	// ���������� ������ �� ���������
	Handle->SetParam(PP_SET_PIN, IntPtr(&param), 0); 

	// ��������� ������������� ����������
	Handle->GetLong(PP_HCRYPTPROV, 0); 
}

void Aladdin::CAPI::CSP::CryptoPro::PasswordService::ChangePassword(String^ password) 
{$
	// ��������� ����������� ���������
	if (!canChange) throw gcnew NotSupportedException(); 

	// �������� �������������� �������������
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(password); 

	// �������� ����� ���������� �������
	CRYPT_PIN_PARAM param; std::string strPasswd(encoded->Length + 1, 0); 

	// ����������� �������������� �������������
	Marshal::Copy(encoded, 0, IntPtr(&strPasswd[0]), encoded->Length); 

	// ������� ��������� �������� ������
	param.type = CRYPT_PIN_PASSWD; param.dest.passwd = &strPasswd[0];

	// �������� ������ ����������
	Handle->SetParam(PP_CHANGE_PIN, IntPtr(&param), 0); 

	// ��������� ������������� ����������
	Handle->GetLong(PP_HCRYPTPROV, 0);
}
