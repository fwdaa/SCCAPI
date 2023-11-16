#include "pch.h"
#include "ui.h"
#include "wxwidgets.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� Windows CAPI
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include "capi.h"
#include <wincred.h>
#pragma comment(lib, "credui.lib")
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ui.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������� ������
///////////////////////////////////////////////////////////////////////////////
static void SafeCopy(char* szDest, size_t sizeDest, const char* szSource)
{
#if defined _MSC_VER
	// ����������� ������
	strncpy_s(szDest, sizeDest, szSource, sizeDest - 1); 
#else
	// ��� �������� ������
	if (strlen(szSource) >= sizeDest)
	{
		// ����������� ����� ������
		strncpy(szDest, szSource, sizeDest - 1); 

		// ������� ����������� ������
		szDest[sizeDest - 1] = '\0'; 
	}
	// ����������� ������
	else { strcpy(szDest, szSource); } 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ����� ������
///////////////////////////////////////////////////////////////////////////////
static bool UI_PasswordCallback(const char* szTarget, const char* szError, 
	char* szUser, int sizeUser, char* szPassword, int sizePassword, 
	int verify, UI_METHOD* pMethodUI, void* pvUserData)
{
	// ������� ����� �����
	UI* pUI = ::UI_new_method(pMethodUI); AE_CHECK_OPENSSL(pUI); 
	try {
		// �������� ����������� ����� ������
		char* szPrompt = ::UI_construct_prompt(pUI, "password", szTarget);

		// ��������� ����������� ����� ������
		AE_CHECK_OPENSSL(szPrompt); ::UI_add_user_data(pUI, pvUserData); 

		// ��������� ����������� ����� ������
		std::string prompt = szPrompt; OPENSSL_free(szPrompt); int code = 0; 

		// ������� ������������ ��������� �� �������
		// code = ::UI_ctrl(pUI, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL); 

		// ��������� ���������� ������
		// if (code < 0) AE_CHECK_OPENSSL(0);

		// ������� ��������� �� ������
		if (szError && *szError) code = ::UI_add_error_string(pUI, szError); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0);
		
		// ������� ����������� ����� ������������ � �����
		if (sizeUser > 0) code = ::UI_add_input_string(
			pUI, "Enter user name:", UI_INPUT_FLAG_ECHO, szUser, 1, sizeUser - 1
		); 
		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0);

		// ������� ����������� ����� ������ � �����
		if (sizePassword > 0) code = ::UI_add_input_string(
			pUI, prompt.c_str(), 0, szPassword, 1, sizePassword - 1
		); 
		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0);

		// ��� ������������� �������������
		if (verify) { std::string buffer(sizePassword, 0); 

			// ������� ����������� ������������� � �����
			code = ::UI_add_verify_string(
				pUI, prompt.c_str(), 0, &buffer[0], 1, sizePassword - 1, szPassword
			);
			// ��������� ���������� ������
			if (code < 0) AE_CHECK_OPENSSL(0);

			// ���������� ������
			for (code = ::UI_process(pUI); code < 0; code = ::UI_process(pUI))
			{
				// ��������� ����������� ���������� �������������
				if (!::UI_ctrl(pUI, UI_CTRL_IS_REDOABLE, 0, NULL, NULL)) break; 
			}
			// �������� ���������� ������
			::OPENSSL_cleanse(&buffer[0], buffer.size()); 
		}
		else {
			// ���������� ������
			for (code = ::UI_process(pUI); code < 0; code = ::UI_process(pUI))
			{
				// ��������� ����������� ���������� �������������
				if (!::UI_ctrl(pUI, UI_CTRL_IS_REDOABLE, 0, NULL, NULL)) break; 
			}
		}
		// ���������� ���������� �������
		if (code < 0) ::OPENSSL_cleanse(szPassword, sizePassword); 
		 
		// ��������� ���������� ������
		if (code == -2) { return false; } if (code < 0) { AE_CHECK_OPENSSL(0); }

		// ���������� ���������� �������
		::UI_free(pUI); return true; 
	}
	// ���������� ���������� �������
	catch (...) { ::UI_free(pUI); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������� CredUICmdLinePromptForCredentials � CredUIPromptForCredentials
// ������������� ��� �������������� � ����������� ������� ������ Windows, 
// �� ����� ���� ������������ ��� ����� ������������������ ������ ��� 
// ���������� �� � ���� ������ ����������. ������������������ ������, 
// ����������� � ���������� ������� ������ Windows, ����� ���� ���� �����: 
// 1) ����� ������� ������ - ������� ������, �� ��������� � ������������� 
//    ��������� Windows, ��� ������� � ������� ���������� ������� ������ 
//    ������� ������; 
// 2) ������� ������ Windows - ������� � �������� ������� ��������� ������� 
//    ��� �������� ������� ������/�������� ������ Windows. ��������� ������
//    ������� �� ��������� ��� ����: 
//    2a) ��������� ������� ������ Windows - ������� ������, ��� ������� � 
//        ������� ���������� ������� ������ ������� ������; 
//    2b) ������� ������ Windows �� ������ ����������� - ������� ������,  
//        ��������� � ������������, ��� ������� � ������� ���������� ������� 
//        ������ � ����������, ��������� ������ ����, ��������������� 
//        ����������� (��������� ����� ���� �� �����-����� ��� � ���� 
//        PKCS12-�����, �������������� � ��������� �����).  
//
// ��� ������������� ������� CredUICmdLinePromptForCredentials � 
// CredUIPromptForCredentials ���������� �������, ����� ������� ������ 
// ��������� ��������. ��� ��������� ����� ������� ������ ���������� 
// ���������� ���� CREDUI_FLAGS_GENERIC_CREDENTIALS. ��� ��������� ���������� 
// ����� ����� �������� ������� ������ Windows. �����, ����������� � ���������
// ������ (��. ����), �������� ������� ������������ � ������ 
// CREDUI_FLAGS_GENERIC_CREDENTIALS. 
// ���� ��� ��������� ������� ������ Windows, ��������� ������������ ������ 
// ���������� �������� ������� Windows, �� ���������� ���������� ���� 
// CREDUI_FLAGS_EXCLUDE_CERTIFICATES. ���� ��������� ������������ ������ 
// �������� ������� Windows �� ������ �����������, �� ���������� ���������� 
// ���� CREDUI_FLAGS_REQUIRE_CERTIFICATE. � ����� ����� ������, ���� ��������� 
// ������������ ������ �������� ������� Windows �� ������ �����������, ��� 
// �������� ������ ���� ���������� �� �����-�����, �� ���������� ���������� 
// ���� CREDUI_FLAGS_REQUIRE_SMARTCARD. ����� CREDUI_FLAGS_EXCLUDE_CERTIFICATES, 
// CREDUI_FLAGS_REQUIRE_CERTIFICATE � CREDUI_FLAGS_REQUIRE_SMARTCARD
// �������� ������� ������������. ������������� ��������� ������ � ���������� 
// ������ ����� ���� �����������: ���� CREDUI_FLAGS_REQUIRE_CERTIFICATE �� 
// ��������������, � ���� CREDUI_FLAGS_REQUIRE_SMARTCARD ��������� ������� 
// ������ ������� ������ �����������, ��� �������� �������� ��������� ������� 
// ��������� � ��������� � ������� ������ ������������. 
// ���� ��� ��������� ������� ������ Windows, ��������� ������������ ������ 
// �������� ��������, �������� ���������������� ����������, �� � ����������� 
// ������ ���������� ���������� ���� CREDUI_FLAGS_REQUEST_ADMINISTRATOR. 
// ��������� ���������� ����� � ���������� ������ ������������. 

// ��� ������������� ���������� ������� ������ Windows (��� ���������� � 
// ��������� �������� �� ���������) � ������� � ��� ��������� ������� ������ 
// ������ � ������������� �� ������������. ��������� ��������� ����� �������� 
// ���������� ����� CREDUI_FLAGS_ALWAYS_SHOW_UI, ������ ������ ��� ������������� 
// ����� ������� ������ (��������� ����� CREDUI_FLAGS_GENERIC_CREDENTIALS). 
// ��� ������������� ������� � ������������� ������� ������ (������ ��� 
// ���������� ��������������) ����������� � ���� ������ ���������� ������� 
// ������ Windows, ���� � �������� ������� ��� ���������� ��������������� 
// ������ � ����������� ������ ��� ��� ��� �������������� ����� �� 
// ��������������� ��������� � ���������� ������. ���� ��������� ���������� 
// ������� ������ ��� ������������� ������ ��� ������ �� ���������, �� 
// ���������� ���������� ���� CREDUI_FLAGS_PERSIST, ����������� �� �����. 
// ��� ���������� ������� ������ � ���� ������ ���������� ������������� 
// ��������� ���� CREDUI_FLAGS_EXPECT_CONFIRMATION, ������������� �������� 
// ������������� � ����������� ������ ������� CredUIConfirmCredentials. 
// ��������� ������� ���������� ����� ���������� ������� � ������� (�, 
// ��������������, ���������� ��������������) � ������������� ���������� 
// ������� ������� ���������� � �������������� ��� ���������������� ������� 
// � �������. � ��������� ������, ��������� ������� ������� ������� �� 
// ����� ���� ����������� �������� ������� ������. 

// ������������� ���������� ������� ������ Windows ����������� ���������� 
// ����� CREDUI_FLAGS_DO_NOT_PERSIST. ���� ��� ���� �� ���������� ����  
// CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX, �� ��������������� ������ � ����������� 
// ������� ���������� �����������, � ��������������� ��������� � ������� 
// �� ����������. ��� ������������� ����� CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX
// ��������������� ������ � ��������� ���������� ������������, �� �� 
// ���������� ��� �� ������� � �������������� ���������� ������� �������
// Windows (����� ���� ������������ ��� �������� ���������� � ���� ������ 
// �������� ���������� ������� �������).

// ����� ������� ������ � ���������� ������ ������������ ����� ����� 
// ����� ������� ������ � ����� �� ��������������� �����������. ��� ���� 
// ����������� ����� ����� ���������� ������ ��� ���������� ������ ��������
// ����� � ���������� �������. ���� ��� ���� �������, �� ��� ���������� 
// ����� CREDUI_FLAGS_REQUIRE_SMARTCARD ��� ���������� ��� ����� ������� 
// ������ ��� ��� ��������� ������� ������ Windows, � ��� �������� �����
// CREDUI_FLAGS_REQUIRE_SMARTCARD - ���, �� ������ �������� ����� �������
// ������� ������ Windows �� ������ �����������. 

// ����� ������� ������ � ����������� ������ ������������ ����� ������ 
// ��������� ������� ������ � ���� �� ������� ��� �������������� ��������
// ���������� ����. ������ ���� �� ������� ����������� �� ������ ������
// CREDUI_FLAGS_EXCLUDE_CERTIFICATES, CREDUI_FLAGS_REQUIRE_CERTIFICATE, 
// CREDUI_FLAGS_REQUIRE_SMARTCARD � CREDUI_FLAGS_REQUEST_ADMINISTRATOR
// � ����� ���� �������� ������ ��� ������������� ������� ������ Windows 
// (��� ������������� ����� ������ ������ ����). �������������� �������� 
// ���� �������� ���, ���� ��������� ��� ������ �������. ���� �� ������� 
// �� ������������, ���� ������ ���� CREDUI_FLAGS_PASSWORD_ONLY_OK. ���� 
// �� ������� �������� ����������� (�� �������� ��� ���� ���, ���� 
// ��������� ��� ������ �������) ��� �������� ����� CREDUI_FLAGS_KEEP_USERNAME. 
// ���� �� ������� �������� ������������� ������ ��� ������������� �����
// ������� ������ ��� ��������� ����� CREDUI_FLAGS_COMPLETE_USERNAME ��� 
// ������������� ������� ������ Windows. 

// ��� ����� ����� ������� ������ ����� ���� ��������� �������������� 
// �������� ���������� ����� �����������, �������� � Windows. ��� �����
// ��� ������������� ����� ������� ������� ���������� ���������� ���� 
// CREDUI_FLAGS_VALIDATE_USERNAME, � ��� ������������� ������� �������
// Windows - ���������� ���� CREDUI_FLAGS_COMPLETE_USERNAME (������ � 
// ����������� ������). ��� ������������� ����� ��������� ��������� 
// � ������������ ������� �����. �������� ��������� ��������� �� 
// ���������� ��������� � ������������ �������������� �����, ��������� 
// ���� CREDUI_FLAGS_INCORRECT_PASSWORD. 

typedef bool (*PUI_SHOW_DIALOG)(
	const UI_METHOD* pImpl, const char* szError, const char* szMessage, 
	const char* szUserNamePrompt, char* szUserName, size_t sizeUserName, 
	const char* szPasswordPrompt, char* szPassword, size_t sizePassword 
); 

#if defined _WIN32
static bool WindowsConsole_ShowDialog(const UI_METHOD* pImpl, 
	const char* szError, const char* szMessage, 
	const char*, char* szUserName, size_t sizeUserName, 
	const char*, char* szPassword, size_t sizePassword)
{
	// �������� ��� �������
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// ������� ������ ���������� �������
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// ��� �������������
	CHAR szUser[] = "USER"; if (sizeUserName == 0) 
	{ 
		// ������� ����� ������������ ������
		szUserName = szUser; sizeUserName = sizeof(szUser) / sizeof(CHAR); 
	}
	// ������� ������ ��������������
	CHAR szBufferTarget[CREDUI_MAX_GENERIC_TARGET_LENGTH]; SafeCopy(
		szBufferTarget, sizeof(szBufferTarget) / sizeof(CHAR), szTarget
	); 
	// ��������� ������ � ������������� 
	AE_CHECK_WINERROR(::CredUICmdLinePromptForCredentialsA(
		szBufferTarget, NULL, ERROR_SUCCESS, szUserName, (DWORD)sizeUserName,
		szPassword, (DWORD)sizePassword, NULL, dwFlags
	));
	return true; 
}

static bool WindowsGUI_ShowDialog(const UI_METHOD* pImpl, 
	const char* szError, const char* szMessage, 
	const char* szUserNamePrompt, char* szUserName, size_t sizeUserName, 
	const char* szPasswordPrompt, char* szPassword, size_t sizePassword)
{
	// �������� ��� �������
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// �������� ��������� ������������� ����
	HWND hParent = (HWND)::UI_method_get_ex_data(pImpl, 2); 

	// ������� ������ ���������� �������
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// ��� �������������
	CHAR szUser[] = "USER"; if (szUserName && *szUserName) dwFlags |= CREDUI_FLAGS_KEEP_USERNAME; 
	else { 
		// ������� ����� ������������ ������
		szUserName = szUser; sizeUserName = sizeof(szUser) / sizeof(CHAR); 

		// ��������� ���� ����� ������������
		dwFlags |= CREDUI_FLAGS_KEEP_USERNAME | CREDUI_FLAGS_PASSWORD_ONLY_OK; 
	}
	// ������� ������� ������
	if (szError && *szError) dwFlags |= CREDUI_FLAGS_INCORRECT_PASSWORD; 

	// ������� ����������� ����� ������
	std::string message(szPasswordPrompt); UNREFERENCED_PARAMETER(szUserNamePrompt);

	// �������� �������������� ���������
	if (szError   && *szError  ) message = szError   + ("\r\n\r\n" + message); 
	if (szMessage && *szMessage) message = szMessage + ("\r\n\r\n" + message); 

	// ������� ������ ��������������
	CHAR szBufferTarget[CREDUI_MAX_GENERIC_TARGET_LENGTH]; SafeCopy(
		szBufferTarget, sizeof(szBufferTarget) / sizeof(CHAR), szTarget
	); 
	// ����������� ���������
	CHAR szBufferCaption[CREDUI_MAX_CAPTION_LENGTH]; SafeCopy(
		szBufferCaption, sizeof(szBufferCaption) / sizeof(CHAR), szTarget
	); 
	// ����������� ���������
	CHAR szBufferMessage[CREDUI_MAX_MESSAGE_LENGTH]; SafeCopy(
		szBufferMessage, sizeof(szBufferMessage) / sizeof(CHAR), message.c_str()
	); 
	// ������� ��������� �����������
	CREDUI_INFOA uiInfo = { sizeof(uiInfo), hParent, szBufferMessage, szBufferCaption }; 

	// ��������� ������ � ������������� 
	DWORD code = ::CredUIPromptForCredentialsA(&uiInfo, 
		szBufferTarget, NULL, ERROR_SUCCESS, szUserName, (DWORD)sizeUserName,
		szPassword, (DWORD)sizePassword, NULL, dwFlags
	);
	// ��������� ���������� ������
	if (code == ERROR_CANCELLED) return false; AE_CHECK_WINERROR(code); return true; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ ��������������. ����� �������������� ������ ��� ������� � 
// ��������, ��������� ������ ��� ��������������, �� �� ��������� ��� 
// �������������. ��� ���� ����� ������������� �� ������ ������, �� � 
// ��� ������������. 
///////////////////////////////////////////////////////////////////////////////
static char* UI_Prompt(UI* pUI, const char* szObjectDesc, const char* szObjectName)
try {
	// ��������� ������� �������� �������
	char* prompt = NULL; if (!szObjectDesc) return prompt; if (!szObjectName)
	{
		// ���������� ������ ������
		size_t size = 6 + strlen(szObjectDesc) + 1 + 1; 

		// �������� ����� ���������� �������
		prompt = (char*)OPENSSL_malloc(size); AE_CHECK_OPENSSL(prompt); 

		// ��������������� ������
		snprintf(prompt, size, "Enter %s:", szObjectDesc); 
	}
	else {
		// ���������� ������ ������
		size_t size = 6 + strlen(szObjectDesc) + 5 + strlen(szObjectName) + 1 + 1; 

		// �������� ����� ���������� �������
		prompt = (char*)OPENSSL_malloc(size); AE_CHECK_OPENSSL(prompt); 

		// ��������������� ������
		snprintf(prompt, size, "Enter %s for %s:", szObjectDesc, szObjectName); 
	}
	return prompt; 
}
catch (...) { return NULL; } 

static const std::vector<UI_STRING*>& UI_Strings(const UI_METHOD* pImpl)
{
	// �������� ����� ����������
	return *(const std::vector<UI_STRING*>*)::UI_method_get_ex_data(pImpl, 0); 
}

static std::vector<UI_STRING*>& UI_Strings(UI_METHOD* pImpl)
{
	// �������� ����� ����������
	return *(std::vector<UI_STRING*>*)::UI_method_get_ex_data(pImpl, 0); 
}

static int UI_Open(UI* pUI)
try {
	// �������� ����� ����������
	UI_METHOD* pImpl = (UI_METHOD*)::UI_get_method(pUI); 

	// ������� ����� ����������
	std::vector<UI_STRING*>* pStrings = new std::vector<UI_STRING*>(); 

	// ��������� ����� ����������
	AE_CHECK_OPENSSL(::UI_method_set_ex_data(pImpl, 0, pStrings)); return 1; 
}
catch (...) { return 0; }

static int UI_Close(UI* pUI)
{
	// �������� ����� ����������
	UI_METHOD* pImpl = const_cast<UI_METHOD*>(::UI_get_method(pUI)); 

	// �������� ����� ����������
	void* pStrings = const_cast<void*>(::UI_method_get_ex_data(pImpl, 0)); 

	// ������� ����� ���������� 
	if (pStrings) delete (std::vector<UI_STRING*>*)pStrings; 

	// �������� ����� ����������
	::UI_method_set_ex_data(pImpl, 0, NULL); return 1; 
}

static int UI_Write(UI* pUI, UI_STRING* pString)
try {
	// �������� ����� ����������
	UI_METHOD* pImpl = const_cast<UI_METHOD*>(::UI_get_method(pUI)); 

	// �������� ����� ����������
	std::vector<UI_STRING*>& strings = UI_Strings(pImpl); 

	// ��� ������ �������� ������
	if (::UI_get_string_type(pString) == UIT_ERROR)
	{
		// ������� ��� ���������
		typedef std::vector<UI_STRING*>::const_iterator const_iterator; 

		// ��� ���� ����������
		for (const_iterator p = strings.begin(); p != strings.end(); ++p)
		{
			// ������� ������ �������� ������
			if (::UI_get_string_type(*p) == UIT_ERROR) { strings.erase(p); break; }
		}
	}
	// �������� �������� � ������
	strings.push_back(pString); return 1; 
}
catch (...) { return 0; }

static int UI_Flush(UI* pUI, PUI_SHOW_DIALOG pShowDialog, 
	const char* szError, const char* szMessage, 
	const std::vector<UI_STRING*>& strings)
try {
	// ���������������� ����������
	size_t passwordIndex = -1; int passwordFlags = -1;

	// ��� ���� ����������
	for (size_t i = strings.size(); i > 0; i--)
	{
		// ��������� ��� ���������
		if (::UI_get_string_type(strings[i - 1]) != UIT_PROMPT) continue; 

		// �������� �������������� ��������
		int flags = ::UI_get_input_flags(strings[i - 1]); 

		// ��� �������� ������
		if ((flags & UI_INPUT_FLAG_DEFAULT_PWD) != 0) 
		{
			// ��������� ����� ���������� ��� ������
			passwordIndex = i - 1; passwordFlags = 2; break; 
		}
		// ��� ������� �����
		if ((flags & UI_INPUT_FLAG_ECHO) == 0 && passwordFlags < 1)
		{
			// ��������� ����� ���������� ��� ������
			passwordIndex = i - 1; passwordFlags = 1; 
		}
		else if (passwordFlags < 0)
		{
			// ��������� ����� ���������� ��� ������
			passwordIndex = i - 1; passwordFlags = 0; 
		}
	}
	// ���������������� ����������
	size_t userNameIndex = -1; int userNameFlags = -1;

	// ��� ���� ����������
	for (size_t i = strings.size(); i > 0; i--)
	{
		// ��������� ������������ ������ � �������
		if (i - 1 == passwordIndex) continue; 

		// ��������� ��� ���������
		if (::UI_get_string_type(strings[i - 1]) != UIT_PROMPT) continue; 

		// �������� �������������� ��������
		int flags = ::UI_get_input_flags(strings[i - 1]); 

		// ��� �������� ������
		if ((flags & UI_INPUT_FLAG_DEFAULT_PWD) != 0) 
		{
			// ��������� ����� ���������� ��� ������
			userNameIndex = i - 1; userNameFlags = 2; break; 
		}
		// ��� ������� �����
		if ((flags & UI_INPUT_FLAG_ECHO) == 0 && userNameFlags < 1)
		{
			// ��������� ����� ���������� ��� ������
			userNameIndex = i - 1; userNameFlags = 1; 
		}
		else if (userNameFlags < 0)
		{
			// ��������� ����� ���������� ��� ������
			userNameIndex = i - 1; userNameFlags = 0; 
		}
	}
	// ���������������� ����������
	const char* szUserNamePrompt = NULL; std::string userName;

	// ��� ������� ����� ������������
	if (userNameFlags >= 0)
	{
		// ���������� ������������ ������ ������
		size_t sizeUserName = ::UI_get_result_maxsize(strings[userNameIndex]); 

		// �������� ����� ���������� �������
		userName.resize(sizeUserName + 1); 

		// �������� �������� �� ���������
		const char* szUserName = ::UI_get0_result_string(strings[userNameIndex]); 

		// ����������� �������� �� ���������
		SafeCopy(&userName[0], sizeUserName + 1, szUserName); 

		// �������� ����������� ����� ����� ������������
		szUserNamePrompt = ::UI_get0_output_string(strings[userNameIndex]); 
	}
	// ���������������� ����������
	const char* szPasswordPrompt = NULL; std::string password;

	// ��� ������� ������
	if (passwordFlags >= 0)
	{
		// ���������� ������������ ������ ������
		size_t sizePassword = ::UI_get_result_maxsize(strings[passwordIndex]); 

		// �������� ����� ���������� �������
		password.resize(sizePassword + 1); 

		// �������� �������� �� ���������
		const char* szPassword = ::UI_get0_result_string(strings[passwordIndex]); 

		// ����������� �������� �� ���������
		SafeCopy(&password[0], sizePassword + 1, szPassword); 

		// �������� ����������� ����� ������
		szPasswordPrompt = ::UI_get0_output_string(strings[passwordIndex]); 
	}
	try {
		// �������� ����� ����������
		const UI_METHOD* pImpl = ::UI_get_method(pUI); 

		// ���������� ������
		if (!(*pShowDialog)(pImpl, szError, szMessage,  
			szUserNamePrompt, &userName[0], userName.size(), 
			szPasswordPrompt, &password[0], password.size())) return -1; 
	}
	// ���������� ��������� ������
	catch (...) { return 0; } 

	// ��� ������� ����� ������������
	if (userNameFlags >= 0)
	{
		// ��������� ��� ������������
		if (::UI_set_result(pUI, strings[userNameIndex], userName.c_str()) < 0) 
		{ 
			// �������� �������������� ������ ������
			const char* szErrorData = NULL; ::ERR_get_error_data(&szErrorData, NULL); 

			// ���������� ��������� �� ������
			if (szErrorData && *szErrorData) ::UI_dup_error_string(pUI, szErrorData); 

			// ��������� ����������
			AE_CHECK_OPENSSL(0); 
		}
	}
	// ��� ������� ������
	if (passwordFlags >= 0)
	{
		// ��������� ������ ������������
		if (::UI_set_result(pUI, strings[passwordIndex], password.c_str()) < 0)
		{
			// �������� �������������� ������ ������
			const char* szErrorData = NULL; ::ERR_peek_last_error_data(&szErrorData, NULL); 

			// ���������� ��������� �� ������
			if (szErrorData && *szErrorData) ::UI_dup_error_string(pUI, szErrorData); 

			// ��������� ����������
			AE_CHECK_OPENSSL(0); 
		}
	}
	return 1; 
}
catch (...) { return 0; }

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������������
///////////////////////////////////////////////////////////////////////////////
std::wstring Aladdin::CAPI::OpenSSL::IPasswordAuthentication::Authenticate(
	const wchar_t* szTarget, const wchar_t* szUser, size_t attempts, 
	pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// ��������� �������������� ����
	std::string target = szTarget ? from_unicode(szTarget) : std::string(); 

	// �������� ������ ��� ����� ������������ � ������
	char szUserName[PEM_BUFSIZE] = {0}; size_t sizeUser = 0; 
	
	// ��� �������� ����� ������������
	if (szUser) { sizeUser = sizeof(szUserName); 
		
		// ��������� �������������� ���������
		std::string user = from_unicode(szUser); 

		// ����������� ��� ������������
		SafeCopy(szUserName, sizeUser, user.c_str()); 
	}
	// �������� ������ ��� ������
	char szPassword[PEM_BUFSIZE] = {0}; std::string error;

	// ��� ���������� ����� �������
	for (size_t i = attempts; i != 0; i--)
	{
		// �������� ��� � ������ ������������
		if (!PasswordCallback(target.c_str(), error.c_str(), 
			szUserName, sizeUser, szPassword, sizeof(szPassword))) break; 

		// ��������� �������������� ����
		std::wstring user     = to_unicode(szUserName); 
		std::wstring password = to_unicode(szPassword); 
		try {
			// ��������� ������� ��������� ������
			(*pfnAuthenticate)(szTarget, user.c_str(), password.c_str(), pvData); 
			
			// ������� ��� ������������
			return szUser ? user : std::wstring(L"\0", 1); 
		}
		// ��������� ��������� �� ������
		catch (const std::exception& e) { error = e.what(); if (i == 1) throw; }
	}
	// �������� ��������
	return std::wstring(); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������������� ������
///////////////////////////////////////////////////////////////////////////////
static bool FixedPassword(const UI_METHOD* pImpl, 
	const char*, const char*, const char*, char*, size_t, 
	const char*, char* szPassword, size_t sizePassword)
{
	// �������� ������������ ������
	const char* szUserPassword = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// ����������� ������
	SafeCopy(szPassword, sizePassword, szUserPassword); return 1; 
}

static int FixedPassword_Flush(UI* pUI) 
{
	// �������� ����� ����������
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 

	// �������� ����� ����������
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// �������� ������������� ������
	return UI_Flush(pUI, FixedPassword, NULL, NULL, strings); 
}

static UI_METHOD* UI_FixedPassword(const char* szPassword)
{
	// ������� ����� �����
	UI_METHOD* pMethod = ::UI_create_method("Fixed Password"); 

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pMethod); int code = 0;  
	try {
		// ������� ������������ ������
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szPassword));

		// ������� ������������ �������
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_flusher(pMethod, FixedPassword_Flush); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// ���������� ��������� ������
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

UI_METHOD* Aladdin::CAPI::OpenSSL::FixedPasswordAuthentication::CreateInputMethod(const char*) const
{
	// ������� ������ �������������� � �������������
	return UI_FixedPassword(password.c_str()); 
}

bool Aladdin::CAPI::OpenSSL::FixedPasswordAuthentication::PasswordCallback(
	const char*, const char*, char*, size_t, 
	char* szPassword, size_t sizePassword) const
{
	// ����������� ������
	SafeCopy(szPassword, sizePassword, password.c_str()); return true; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ��������������
///////////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::OpenSSL::PasswordAuthentication::PasswordCallback(
	const char* szTarget, const char* szError, char* szUser, size_t sizeUser, 
	char* szPassword, size_t sizePassword) const
{$
	// ������� ������ �������������� � �������������
	UI_METHOD* pInputMethod = CreateInputMethod(szTarget); 
	try {
		// ������ ������ ������������
		bool success = UI_PasswordCallback(
			szTarget, szError, szUser, (int)sizeUser, 
			szPassword, (int)sizePassword, 0, pInputMethod, NULL
		); 
		// ���������� ���������� �������
		::UI_destroy_method(pInputMethod); return success; 
	}
	// ���������� ���������� �������
	catch (...) { ::UI_destroy_method(pInputMethod); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � �������������� �������
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
static int WindowsConsole_Flush(UI* pUI) 
{
	// �������� ����� ����������
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 

	// �������� ����� ����������
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// ��� ���� ����������
	for (size_t i = 0; i < strings.size(); i++)
	{
		// �������� ��� ���������
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR:
		{
			// �������� ��������� ��� ������
			PCSTR szError = ::UI_get0_output_string(strings[i]); 

			// ������� ���������
			fputs(szError, stderr); fputs("\n", stderr); break; 
		}
		case UIT_INFO:
		{
			// �������� ��������� ��� ������
			PCSTR szMessage = ::UI_get0_output_string(strings[i]); 

			// ������� ���������
			fputs(szMessage, stdout); fputs("\n", stdout); break; 
		}}
	}
	// ��������� �������� ������
	fflush(stdout);	fflush(stderr);

	// ���������� ������
	return UI_Flush(pUI, WindowsConsole_ShowDialog, NULL, NULL, strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::Windows::UI_Console(PCSTR szTarget)
{
	// ������� ����� �����
	UI_METHOD* pMethod = ::UI_create_method("Windows Console"); 

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// ������� ��� �������
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// ������� ������������ �������
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_flusher(pMethod, WindowsConsole_Flush); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// ���������� ��������� ������
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � �������������� ������������ ���������� (Windows)
///////////////////////////////////////////////////////////////////////////////
static int WindowsGUI_Flush(UI* pUI) 
{ 
	// �������� ����� ����������
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 
	
	// ���������������� ������
	std::string error; std::string message;

	// �������� ����� ����������
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// ��� ���� ����������
	for (size_t i = 0; i < strings.size(); i++)
	{
		// �������� ��� ���������
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR: 
		{
			// �������� ����������� ���������
			if (error.size() != 0) error += "\r\n"; 

			// �������� ����� ���������
			error += ::UI_get0_output_string(strings[i]); break; 
		}
		case UIT_INFO: 
		{
			// �������� ����������� ���������
			if (message.size() != 0) message += "\r\n"; 

			// �������� ����� ���������
			message += ::UI_get0_output_string(strings[i]); break; 
		}}
	}
	// ���������� ������
	return UI_Flush(pUI, WindowsGUI_ShowDialog, error.c_str(), message.c_str(), strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::Windows::UI_GUI(HWND hwnd, PCSTR szTarget)
{
	// ������� ����� �����
	UI_METHOD* pMethod = ::UI_create_method("Windows GUI"); 

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// ������� ��� �������
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// ������� ������������ ����
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 2, (void*)hwnd));

		// ������� ������������ �������
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_flusher(pMethod, WindowsGUI_Flush); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// ���������� ��������� ������
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ �������������� � �������������� ������������ ���������� (WxWidgets)
///////////////////////////////////////////////////////////////////////////////
static bool WxWidgetsGUI_ShowDialog(const UI_METHOD* pImpl, 
	const char* szError, const char* szMessage, 
	const char* szUserNamePrompt, char* szUserName, size_t sizeUserName, 
	const char* szPasswordPrompt, char* szPassword, size_t sizePassword)
{
	// �������� ��� �������
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// �������� ��������� ������������� ����
	wxWindow* pParent = (wxWindow*)::UI_method_get_ex_data(pImpl, 2); 

	// ������� ����������� ����� ������
	std::string message(szPasswordPrompt); (void)szUserNamePrompt;

	// �������� �������������� ���������
	if (szError   && *szError  ) message = szError   + ("\n" + message); 
	if (szMessage && *szMessage) message = szMessage + ("\n" + message); 

	// ��������� �������������� ����
	wxString wxMessage = message; wxString wxCaption = szTarget; if (sizeUserName != 0)
	{
		// ������� ������ ����� ������
		Aladdin::CAPI::OpenSSL::WxWidgets::UserPasswordDialog dialog(
			pParent, wxCaption, wxMessage, szUserName
		);  
		// ������� ������������ ������ ����� ������������ � ������
		dialog.SetMaxUserNameLength((unsigned long)sizeUserName); 
		dialog.SetMaxPasswordLength((unsigned long)sizePassword); 

		// ���������� ������
		int code = dialog.ShowModal(); if (code == wxID_CANCEL) return false; 

		// �������� ��� ������������ � ��������� ������
		std::string username = dialog.GetUser    ().ToStdString(); 
		std::string password = dialog.GetPassword().ToStdString(); 

		// ����������� ��� ������������ � ������
		SafeCopy(szUserName, sizeUserName, username.c_str()); 
		SafeCopy(szPassword, sizePassword, password.c_str()); 
	}
	else {
		// ������� ������ ����� ������
		Aladdin::CAPI::OpenSSL::WxWidgets::PasswordDialog dialog(
			pParent, wxCaption, wxMessage
		);  
		// ������� ������������ ������ ������
		dialog.SetMaxLength((unsigned long)sizePassword); 

		// ���������� ������
		int code = dialog.ShowModal(); if (code == wxID_CANCEL) return false; 

		// �������� ��������� ������
		std::string password = dialog.GetValue().ToStdString(); 

		// ����������� ������
		SafeCopy(szPassword, sizePassword, password.c_str()); 
	}
	return true; 
}

static int WxWidgetsGUI_Flush(UI* pUI) 
{ 
	// �������� ����� ����������
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 
	
	// ���������������� ������
	std::string error; std::string message;

	// �������� ����� ����������
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// ��� ���� ����������
	for (size_t i = 0; i < strings.size(); i++)
	{
		// �������� ��� ���������
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR: 
		{
			// �������� ����������� ���������
			if (error.size() != 0) error += "\n"; 

			// �������� ����� ���������
			error += ::UI_get0_output_string(strings[i]); break; 
		}
		case UIT_INFO: 
		{
			// �������� ����������� ���������
			if (message.size() != 0) message += "\n"; 

			// �������� ����� ���������
			message += ::UI_get0_output_string(strings[i]); break; 
		}
		default: break; 
		}
	}
	// ���������� ������
	return UI_Flush(pUI, WxWidgetsGUI_ShowDialog, error.c_str(), message.c_str(), strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::WxWidgets::UI_GUI(void* pParent, const char* szTarget)
{
	// ������� ����� �����
	UI_METHOD* pMethod = ::UI_create_method("WxWidgets GUI"); 

	// ��������� ���������� ������
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// ������� ��� �������
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// ������� ������������ ����
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 2, pParent));

		// ������� ������������ �������
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_flusher(pMethod, WxWidgetsGUI_Flush); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// ������� ������������ �������
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// ��������� ���������� ������
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// ���������� ��������� ������
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}
