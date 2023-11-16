#include "pch.h"
#include "ui.h"
#include "wxwidgets.h"

///////////////////////////////////////////////////////////////////////////////
// Определения Windows CAPI
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include "capi.h"
#include <wincred.h>
#pragma comment(lib, "credui.lib")
#endif 

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ui.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Выполнить копирование строки
///////////////////////////////////////////////////////////////////////////////
static void SafeCopy(char* szDest, size_t sizeDest, const char* szSource)
{
#if defined _MSC_VER
	// скопировать пароль
	strncpy_s(szDest, sizeDest, szSource, sizeDest - 1); 
#else
	// для длинного пароля
	if (strlen(szSource) >= sizeDest)
	{
		// скопировать часть пароля
		strncpy(szDest, szSource, sizeDest - 1); 

		// указать завершающий символ
		szDest[sizeDest - 1] = '\0'; 
	}
	// скопировать пароль
	else { strcpy(szDest, szSource); } 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Функция ввода пароля
///////////////////////////////////////////////////////////////////////////////
static bool UI_PasswordCallback(const char* szTarget, const char* szError, 
	char* szUser, int sizeUser, char* szPassword, int sizePassword, 
	int verify, UI_METHOD* pMethodUI, void* pvUserData)
{
	// указать метод ввода
	UI* pUI = ::UI_new_method(pMethodUI); AE_CHECK_OPENSSL(pUI); 
	try {
		// получить приглашение ввода пароля
		char* szPrompt = ::UI_construct_prompt(pUI, "password", szTarget);

		// сохранить приглашение ввода пароля
		AE_CHECK_OPENSSL(szPrompt); ::UI_add_user_data(pUI, pvUserData); 

		// сохранить приглашение ввода пароля
		std::string prompt = szPrompt; OPENSSL_free(szPrompt); int code = 0; 

		// указать формирование сообщений об ошибках
		// code = ::UI_ctrl(pUI, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL); 

		// проверить отсутствие ошибок
		// if (code < 0) AE_CHECK_OPENSSL(0);

		// указать сообщение об ошибке
		if (szError && *szError) code = ::UI_add_error_string(pUI, szError); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0);
		
		// указать приглашение ввода пользователя и буфер
		if (sizeUser > 0) code = ::UI_add_input_string(
			pUI, "Enter user name:", UI_INPUT_FLAG_ECHO, szUser, 1, sizeUser - 1
		); 
		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0);

		// указать приглашение ввода пароля и буфер
		if (sizePassword > 0) code = ::UI_add_input_string(
			pUI, prompt.c_str(), 0, szPassword, 1, sizePassword - 1
		); 
		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0);

		// при необходимости подтверждения
		if (verify) { std::string buffer(sizePassword, 0); 

			// указать приглашение подтверждения и буфер
			code = ::UI_add_verify_string(
				pUI, prompt.c_str(), 0, &buffer[0], 1, sizePassword - 1, szPassword
			);
			// проверить отсутствие ошибок
			if (code < 0) AE_CHECK_OPENSSL(0);

			// отобразить диалог
			for (code = ::UI_process(pUI); code < 0; code = ::UI_process(pUI))
			{
				// проверить возможность повторного использования
				if (!::UI_ctrl(pUI, UI_CTRL_IS_REDOABLE, 0, NULL, NULL)) break; 
			}
			// очистить содержимое буфера
			::OPENSSL_cleanse(&buffer[0], buffer.size()); 
		}
		else {
			// отобразить диалог
			for (code = ::UI_process(pUI); code < 0; code = ::UI_process(pUI))
			{
				// проверить возможность повторного использования
				if (!::UI_ctrl(pUI, UI_CTRL_IS_REDOABLE, 0, NULL, NULL)) break; 
			}
		}
		// освободить выделенные ресурсы
		if (code < 0) ::OPENSSL_cleanse(szPassword, sizePassword); 
		 
		// проверить отсутствие ошибок
		if (code == -2) { return false; } if (code < 0) { AE_CHECK_OPENSSL(0); }

		// освободить выделенные ресурсы
		::UI_free(pUI); return true; 
	}
	// освободить выделенные ресурсы
	catch (...) { ::UI_free(pUI); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Функции CredUICmdLinePromptForCredentials и CredUIPromptForCredentials
// предназначены для взаимодействия с диспетчером учетных данных Windows, 
// но могут быть использованы для ввода аутентификационных данных без 
// сохранения их в базе данных диспетчера. Аутентификационные данные, 
// сохраняемые в диспетчере учетных данных Windows, могут быть двух типов: 
// 1) общие учетные данные - учетные данные, не связанные с операционными 
//    системами Windows, для доступа к которым необходимо указать пароль 
//    учетной записи; 
// 2) учетные данные Windows - связаны с учетными данными локальной системы 
//    или учетными данными домена/ресурсов домена Windows. Указанные данные
//    делятся на следующие два типа: 
//    2a) парольные учетные данные Windows - учетные данные, для доступа к 
//        которым необходимо указать пароль учетной записи; 
//    2b) учетные данные Windows на основе сертификата - учетные данные,  
//        связанные с сертификатом, для доступа к которым необходимо указать 
//        пароль к контейнеру, хранящему личный ключ, соответствующий 
//        сертификату (контейнер может быть на смарт-карте или в виде 
//        PKCS12-файла, расположенного в известном месте).  
//
// При использовании функций CredUICmdLinePromptForCredentials и 
// CredUIPromptForCredentials необходимо указать, какие учетные данные 
// требуется получить. Для получения общих учетных данных необходимо 
// установить флаг CREDUI_FLAGS_GENERIC_CREDENTIALS. Без установки указанного 
// флага будут получены учетные данные Windows. Флаги, указываемые в последнем
// случае (см. ниже), являются взаимно исключающими с флагом 
// CREDUI_FLAGS_GENERIC_CREDENTIALS. 
// Если при получении учетных данных Windows, требуется ограничиться только 
// парольными учетными данными Windows, то необходимо установить флаг 
// CREDUI_FLAGS_EXCLUDE_CERTIFICATES. Если требуется ограничиться только 
// учетными данными Windows на основе сертификата, то необходимо установить 
// флаг CREDUI_FLAGS_REQUIRE_CERTIFICATE. В более узком случае, если требуется 
// ограничиться только учетными данными Windows на основе сертификата, для 
// которого личный ключ расположен на смарт-карте, то необходимо установить 
// флаг CREDUI_FLAGS_REQUIRE_SMARTCARD. Флаги CREDUI_FLAGS_EXCLUDE_CERTIFICATES, 
// CREDUI_FLAGS_REQUIRE_CERTIFICATE и CREDUI_FLAGS_REQUIRE_SMARTCARD
// являются взаимно исключающими. Использование указанных флагов в консольном 
// режиме имеет свои ограничения: флаг CREDUI_FLAGS_REQUIRE_CERTIFICATE не 
// поддерживается, а флаг CREDUI_FLAGS_REQUIRE_SMARTCARD позволяет выбрать 
// только учетную запись сертификата, имя субъекта которого наилучшим образом 
// совпадает с указанным в функции именем пользователя. 
// Если при получении учетных данных Windows, требуется ограничиться только 
// учетными записями, имеющими административные привилегии, то в графическом 
// режиме необходимо установить флаг CREDUI_FLAGS_REQUEST_ADMINISTRATOR. 
// Установка указанного флага в консольном режиме игнорируется. 

// При использовании диспетчера учетных данных Windows (что происходит в 
// указанных функциях по умолчанию) и наличии в нем требуемых учетных данных 
// диалог с пользователем не производится. Указанное поведение можно отменить 
// установкой флага CREDUI_FLAGS_ALWAYS_SHOW_UI, причем только при использовании 
// общих учетных данных (установке флага CREDUI_FLAGS_GENERIC_CREDENTIALS). 
// При использовании диалога с пользователем учетные данные (причем без 
// выполнения аутентификации) сохраняются в базе данных диспетчера учетных 
// данных Windows, если в процессе диалога был установлен соответствующий 
// флажок в графическом режиме или был дан утвердительный ответ на 
// соответствующее сообщение в консольном режиме. Если требуется сохранение 
// учетных данных без использования флажка или ответа на сообщение, то 
// необходимо установить флаг CREDUI_FLAGS_PERSIST, запрещающий их вывод. 
// При сохранении учетных данных в базе данных диспетчера рекомендуется 
// указывать флаг CREDUI_FLAGS_EXPECT_CONFIRMATION, использование которого 
// сигнализирует о последующем вызове функции CredUIConfirmCredentials. 
// Указанная функция вызывается после выполнения доступа к ресурсу (и, 
// соответственно, проведения аутентификации) и предоставляет диспетчеру 
// учетных записей информацию о предоставлении или непредоставлении доступа 
// к ресурсу. В последнем случае, диспетчер учетных записей удаляет из 
// своей базы непрошедшую контроль учетную запись. 

// Использование диспетчера учетных данных Windows отключается установкой 
// флага CREDUI_FLAGS_DO_NOT_PERSIST. Если при этом не установлен флаг  
// CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX, то соответствующий флажок в графическом 
// диалоге становится недоступным, а соответствующее сообщение в консоли 
// не появляется. При использовании флага CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX
// соответствующий флажок и сообщение продолжают отображаться, но их 
// назначение уже не связано с использованием диспетчера учетных записей
// Windows (может быть использовано для указания сохранения в базе данных 
// внешнего диспетчера учетных записей).

// Выбор учетной записи в консольном режиме производится путем ввода 
// имени учетной записи в ответ на соответствующее приглашение. При этом 
// приглашение ввода имени появляется только при отсутствии явного указания
// имени в вызываемой функции. Если имя явно указано, то при отсутствии 
// флага CREDUI_FLAGS_REQUIRE_SMARTCARD оно определяет имя общей учетной 
// записи или имя парольной учетной записи Windows, а при указании флага
// CREDUI_FLAGS_REQUIRE_SMARTCARD - имя, на основе которого будет выбрана
// учетная запись Windows на основе сертификата. 

// Выбор учетной записи в графическом режиме производится путем выбора 
// требуемой учетной записи в поле со списком или редактировании значения
// указанного поля. Список поля со списком заполняется на основе флагов
// CREDUI_FLAGS_EXCLUDE_CERTIFICATES, CREDUI_FLAGS_REQUIRE_CERTIFICATE, 
// CREDUI_FLAGS_REQUIRE_SMARTCARD и CREDUI_FLAGS_REQUEST_ADMINISTRATOR
// и может быть непустым только при использовании учетных данных Windows 
// (при использовании общих данных список пуст). Первоначальное значение 
// поля содержит имя, явно указанное при вызове функции. Поле со списком 
// не отображается, если указан флаг CREDUI_FLAGS_PASSWORD_ONLY_OK. Поле 
// со списком является недоступным (но содержит при этом имя, явно 
// указанное при вызове функции) при указании флага CREDUI_FLAGS_KEEP_USERNAME. 
// Поле со списком является редактируемым только при использовании общих
// учетных данных или установке флага CREDUI_FLAGS_COMPLETE_USERNAME при 
// использовании учетных данных Windows. 

// При вводе имени учетной записи может быть выполнена синтаксическая 
// проверка введенного имени соглашениям, принятым в Windows. Для этого
// при использовании общих учетных записей необходимо установить флаг 
// CREDUI_FLAGS_VALIDATE_USERNAME, а при использовании учетных записей
// Windows - установить флаг CREDUI_FLAGS_COMPLETE_USERNAME (только в 
// графическом режиме). Для некорректного имени выводится сообщение 
// о некорректном формате имени. Заменить указанное сообщение на 
// обобщенное сообщение о некорректной аутентификации можно, установив 
// флаг CREDUI_FLAGS_INCORRECT_PASSWORD. 

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
	// получить имя объекта
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// указать способ выполнения функции
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// при необходимости
	CHAR szUser[] = "USER"; if (sizeUserName == 0) 
	{ 
		// указать адрес статического буфера
		szUserName = szUser; sizeUserName = sizeof(szUser) / sizeof(CHAR); 
	}
	// указать объект аутентификации
	CHAR szBufferTarget[CREDUI_MAX_GENERIC_TARGET_LENGTH]; SafeCopy(
		szBufferTarget, sizeof(szBufferTarget) / sizeof(CHAR), szTarget
	); 
	// выполнить диалог с пользователем 
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
	// получить имя объекта
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// получить описатель родительского окна
	HWND hParent = (HWND)::UI_method_get_ex_data(pImpl, 2); 

	// указать способ выполнения функции
	DWORD dwFlags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | 
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_ALWAYS_SHOW_UI; 

	// при необходимости
	CHAR szUser[] = "USER"; if (szUserName && *szUserName) dwFlags |= CREDUI_FLAGS_KEEP_USERNAME; 
	else { 
		// указать адрес статического буфера
		szUserName = szUser; sizeUserName = sizeof(szUser) / sizeof(CHAR); 

		// запретить ввод имени пользователя
		dwFlags |= CREDUI_FLAGS_KEEP_USERNAME | CREDUI_FLAGS_PASSWORD_ONLY_OK; 
	}
	// указать наличие ошибки
	if (szError && *szError) dwFlags |= CREDUI_FLAGS_INCORRECT_PASSWORD; 

	// указать приглашение ввода пароля
	std::string message(szPasswordPrompt); UNREFERENCED_PARAMETER(szUserNamePrompt);

	// добавить информационное сообщение
	if (szError   && *szError  ) message = szError   + ("\r\n\r\n" + message); 
	if (szMessage && *szMessage) message = szMessage + ("\r\n\r\n" + message); 

	// указать объект аутентификации
	CHAR szBufferTarget[CREDUI_MAX_GENERIC_TARGET_LENGTH]; SafeCopy(
		szBufferTarget, sizeof(szBufferTarget) / sizeof(CHAR), szTarget
	); 
	// скопировать заголовок
	CHAR szBufferCaption[CREDUI_MAX_CAPTION_LENGTH]; SafeCopy(
		szBufferCaption, sizeof(szBufferCaption) / sizeof(CHAR), szTarget
	); 
	// скопировать сообщение
	CHAR szBufferMessage[CREDUI_MAX_MESSAGE_LENGTH]; SafeCopy(
		szBufferMessage, sizeof(szBufferMessage) / sizeof(CHAR), message.c_str()
	); 
	// указать параметры отображения
	CREDUI_INFOA uiInfo = { sizeof(uiInfo), hParent, szBufferMessage, szBufferCaption }; 

	// выполнить диалог с пользователем 
	DWORD code = ::CredUIPromptForCredentialsA(&uiInfo, 
		szBufferTarget, NULL, ERROR_SUCCESS, szUserName, (DWORD)sizeUserName,
		szPassword, (DWORD)sizePassword, NULL, dwFlags
	);
	// проверить отсутствие ошибок
	if (code == ERROR_CANCELLED) return false; AE_CHECK_WINERROR(code); return true; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Диалог аутентификации. Может использоваться только для доступа к 
// объектам, требующим пароль для аутентификации, но не требующим его 
// подтверждения. При этом может запрашиваться не только пароль, но и 
// имя пользователя. 
///////////////////////////////////////////////////////////////////////////////
static char* UI_Prompt(UI* pUI, const char* szObjectDesc, const char* szObjectName)
try {
	// проверить наличие описания объекта
	char* prompt = NULL; if (!szObjectDesc) return prompt; if (!szObjectName)
	{
		// определить размер строки
		size_t size = 6 + strlen(szObjectDesc) + 1 + 1; 

		// выделить буфер требуемого размера
		prompt = (char*)OPENSSL_malloc(size); AE_CHECK_OPENSSL(prompt); 

		// отформатировать строку
		snprintf(prompt, size, "Enter %s:", szObjectDesc); 
	}
	else {
		// определить размер строки
		size_t size = 6 + strlen(szObjectDesc) + 5 + strlen(szObjectName) + 1 + 1; 

		// выделить буфер требуемого размера
		prompt = (char*)OPENSSL_malloc(size); AE_CHECK_OPENSSL(prompt); 

		// отформатировать строку
		snprintf(prompt, size, "Enter %s for %s:", szObjectDesc, szObjectName); 
	}
	return prompt; 
}
catch (...) { return NULL; } 

static const std::vector<UI_STRING*>& UI_Strings(const UI_METHOD* pImpl)
{
	// получить набор параметров
	return *(const std::vector<UI_STRING*>*)::UI_method_get_ex_data(pImpl, 0); 
}

static std::vector<UI_STRING*>& UI_Strings(UI_METHOD* pImpl)
{
	// получить набор параметров
	return *(std::vector<UI_STRING*>*)::UI_method_get_ex_data(pImpl, 0); 
}

static int UI_Open(UI* pUI)
try {
	// получить адрес реализации
	UI_METHOD* pImpl = (UI_METHOD*)::UI_get_method(pUI); 

	// создать набор параметров
	std::vector<UI_STRING*>* pStrings = new std::vector<UI_STRING*>(); 

	// сохранить набор параметров
	AE_CHECK_OPENSSL(::UI_method_set_ex_data(pImpl, 0, pStrings)); return 1; 
}
catch (...) { return 0; }

static int UI_Close(UI* pUI)
{
	// получить адрес реализации
	UI_METHOD* pImpl = const_cast<UI_METHOD*>(::UI_get_method(pUI)); 

	// получить набор параметров
	void* pStrings = const_cast<void*>(::UI_method_get_ex_data(pImpl, 0)); 

	// удалить набор параметров 
	if (pStrings) delete (std::vector<UI_STRING*>*)pStrings; 

	// сбросить набор параметров
	::UI_method_set_ex_data(pImpl, 0, NULL); return 1; 
}

static int UI_Write(UI* pUI, UI_STRING* pString)
try {
	// получить адрес реализации
	UI_METHOD* pImpl = const_cast<UI_METHOD*>(::UI_get_method(pUI)); 

	// получить набор параметров
	std::vector<UI_STRING*>& strings = UI_Strings(pImpl); 

	// для строки описания ошибки
	if (::UI_get_string_type(pString) == UIT_ERROR)
	{
		// указать тип итератора
		typedef std::vector<UI_STRING*>::const_iterator const_iterator; 

		// для всех параметров
		for (const_iterator p = strings.begin(); p != strings.end(); ++p)
		{
			// удалить строку описания ошибки
			if (::UI_get_string_type(*p) == UIT_ERROR) { strings.erase(p); break; }
		}
	}
	// добавить параметр в список
	strings.push_back(pString); return 1; 
}
catch (...) { return 0; }

static int UI_Flush(UI* pUI, PUI_SHOW_DIALOG pShowDialog, 
	const char* szError, const char* szMessage, 
	const std::vector<UI_STRING*>& strings)
try {
	// инициализировать переменные
	size_t passwordIndex = -1; int passwordFlags = -1;

	// для всех параметров
	for (size_t i = strings.size(); i > 0; i--)
	{
		// проверить тип параметра
		if (::UI_get_string_type(strings[i - 1]) != UIT_PROMPT) continue; 

		// получить дополнительные сведения
		int flags = ::UI_get_input_flags(strings[i - 1]); 

		// при указании пароля
		if ((flags & UI_INPUT_FLAG_DEFAULT_PWD) != 0) 
		{
			// сохранить номер переменной для пароля
			passwordIndex = i - 1; passwordFlags = 2; break; 
		}
		// при скрытом вводе
		if ((flags & UI_INPUT_FLAG_ECHO) == 0 && passwordFlags < 1)
		{
			// сохранить номер переменной для пароля
			passwordIndex = i - 1; passwordFlags = 1; 
		}
		else if (passwordFlags < 0)
		{
			// сохранить номер переменной для пароля
			passwordIndex = i - 1; passwordFlags = 0; 
		}
	}
	// инициализировать переменные
	size_t userNameIndex = -1; int userNameFlags = -1;

	// для всех параметров
	for (size_t i = strings.size(); i > 0; i--)
	{
		// проверить несовпадение номера с паролем
		if (i - 1 == passwordIndex) continue; 

		// проверить тип параметра
		if (::UI_get_string_type(strings[i - 1]) != UIT_PROMPT) continue; 

		// получить дополнительные сведения
		int flags = ::UI_get_input_flags(strings[i - 1]); 

		// при указании пароля
		if ((flags & UI_INPUT_FLAG_DEFAULT_PWD) != 0) 
		{
			// сохранить номер переменной для пароля
			userNameIndex = i - 1; userNameFlags = 2; break; 
		}
		// при скрытом вводе
		if ((flags & UI_INPUT_FLAG_ECHO) == 0 && userNameFlags < 1)
		{
			// сохранить номер переменной для пароля
			userNameIndex = i - 1; userNameFlags = 1; 
		}
		else if (userNameFlags < 0)
		{
			// сохранить номер переменной для пароля
			userNameIndex = i - 1; userNameFlags = 0; 
		}
	}
	// инициализировать переменные
	const char* szUserNamePrompt = NULL; std::string userName;

	// при наличии имени пользователя
	if (userNameFlags >= 0)
	{
		// определить максимальный размер буфера
		size_t sizeUserName = ::UI_get_result_maxsize(strings[userNameIndex]); 

		// выделить буфер требуемого размера
		userName.resize(sizeUserName + 1); 

		// получить значение по умолчанию
		const char* szUserName = ::UI_get0_result_string(strings[userNameIndex]); 

		// скопировать значение по умолчанию
		SafeCopy(&userName[0], sizeUserName + 1, szUserName); 

		// получить приглашение ввода имени пользователя
		szUserNamePrompt = ::UI_get0_output_string(strings[userNameIndex]); 
	}
	// инициализировать переменные
	const char* szPasswordPrompt = NULL; std::string password;

	// при наличии пароля
	if (passwordFlags >= 0)
	{
		// определить максимальный размер буфера
		size_t sizePassword = ::UI_get_result_maxsize(strings[passwordIndex]); 

		// выделить буфер требуемого размера
		password.resize(sizePassword + 1); 

		// получить значение по умолчанию
		const char* szPassword = ::UI_get0_result_string(strings[passwordIndex]); 

		// скопировать значение по умолчанию
		SafeCopy(&password[0], sizePassword + 1, szPassword); 

		// получить приглашение ввода пароля
		szPasswordPrompt = ::UI_get0_output_string(strings[passwordIndex]); 
	}
	try {
		// получить адрес реализации
		const UI_METHOD* pImpl = ::UI_get_method(pUI); 

		// отобразить диалог
		if (!(*pShowDialog)(pImpl, szError, szMessage,  
			szUserNamePrompt, &userName[0], userName.size(), 
			szPasswordPrompt, &password[0], password.size())) return -1; 
	}
	// обработать возможную ошибку
	catch (...) { return 0; } 

	// при наличии имени пользователя
	if (userNameFlags >= 0)
	{
		// сохранить имя пользователя
		if (::UI_set_result(pUI, strings[userNameIndex], userName.c_str()) < 0) 
		{ 
			// получить дополнительные данные ошибки
			const char* szErrorData = NULL; ::ERR_get_error_data(&szErrorData, NULL); 

			// установить сообщение об ошибке
			if (szErrorData && *szErrorData) ::UI_dup_error_string(pUI, szErrorData); 

			// выбросить исключение
			AE_CHECK_OPENSSL(0); 
		}
	}
	// при наличии пароля
	if (passwordFlags >= 0)
	{
		// сохранить пароль пользователя
		if (::UI_set_result(pUI, strings[passwordIndex], password.c_str()) < 0)
		{
			// получить дополнительные данные ошибки
			const char* szErrorData = NULL; ::ERR_peek_last_error_data(&szErrorData, NULL); 

			// установить сообщение об ошибке
			if (szErrorData && *szErrorData) ::UI_dup_error_string(pUI, szErrorData); 

			// выбросить исключение
			AE_CHECK_OPENSSL(0); 
		}
	}
	return 1; 
}
catch (...) { return 0; }

///////////////////////////////////////////////////////////////////////////////
// Выполнить аутентификацию
///////////////////////////////////////////////////////////////////////////////
std::wstring Aladdin::CAPI::OpenSSL::IPasswordAuthentication::Authenticate(
	const wchar_t* szTarget, const wchar_t* szUser, size_t attempts, 
	pfnAuthenticate pfnAuthenticate, void* pvData) const
{$
	// выполнить преобразование типа
	std::string target = szTarget ? from_unicode(szTarget) : std::string(); 

	// выделить память для имени пользователя и пароля
	char szUserName[PEM_BUFSIZE] = {0}; size_t sizeUser = 0; 
	
	// при указании имени пользователя
	if (szUser) { sizeUser = sizeof(szUserName); 
		
		// выполнить преобразование кодировки
		std::string user = from_unicode(szUser); 

		// скопировать имя пользователя
		SafeCopy(szUserName, sizeUser, user.c_str()); 
	}
	// выделить память для пароля
	char szPassword[PEM_BUFSIZE] = {0}; std::string error;

	// для указанного числа попыток
	for (size_t i = attempts; i != 0; i--)
	{
		// получить имя и пароль пользователя
		if (!PasswordCallback(target.c_str(), error.c_str(), 
			szUserName, sizeUser, szPassword, sizeof(szPassword))) break; 

		// выполнить преобразование типа
		std::wstring user     = to_unicode(szUserName); 
		std::wstring password = to_unicode(szPassword); 
		try {
			// выполнить функцию обратного вызова
			(*pfnAuthenticate)(szTarget, user.c_str(), password.c_str(), pvData); 
			
			// вернуть имя пользователя
			return szUser ? user : std::wstring(L"\0", 1); 
		}
		// сохранить сообщение об ошибке
		catch (const std::exception& e) { error = e.what(); if (i == 1) throw; }
	}
	// операция отменена
	return std::wstring(); 
}

///////////////////////////////////////////////////////////////////////////////
// Передача фиксированного пароля
///////////////////////////////////////////////////////////////////////////////
static bool FixedPassword(const UI_METHOD* pImpl, 
	const char*, const char*, const char*, char*, size_t, 
	const char*, char* szPassword, size_t sizePassword)
{
	// получить используемый пароль
	const char* szUserPassword = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// скопировать пароль
	SafeCopy(szPassword, sizePassword, szUserPassword); return 1; 
}

static int FixedPassword_Flush(UI* pUI) 
{
	// получить адрес реализации
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 

	// получить набор параметров
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// передать фиксированный пароль
	return UI_Flush(pUI, FixedPassword, NULL, NULL, strings); 
}

static UI_METHOD* UI_FixedPassword(const char* szPassword)
{
	// создать метод ввода
	UI_METHOD* pMethod = ::UI_create_method("Fixed Password"); 

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pMethod); int code = 0;  
	try {
		// указать используемый пароль
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szPassword));

		// указать используемую функцию
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_flusher(pMethod, FixedPassword_Flush); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// обработать возможную ошибку
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

UI_METHOD* Aladdin::CAPI::OpenSSL::FixedPasswordAuthentication::CreateInputMethod(const char*) const
{
	// указать способ взаимодействия с пользователем
	return UI_FixedPassword(password.c_str()); 
}

bool Aladdin::CAPI::OpenSSL::FixedPasswordAuthentication::PasswordCallback(
	const char*, const char*, char*, size_t, 
	char* szPassword, size_t sizePassword) const
{
	// скопировать пароль
	SafeCopy(szPassword, sizePassword, password.c_str()); return true; 
}

///////////////////////////////////////////////////////////////////////////////
// Диалог аутентификации
///////////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::OpenSSL::PasswordAuthentication::PasswordCallback(
	const char* szTarget, const char* szError, char* szUser, size_t sizeUser, 
	char* szPassword, size_t sizePassword) const
{$
	// указать способ взаимодействия с пользователем
	UI_METHOD* pInputMethod = CreateInputMethod(szTarget); 
	try {
		// ввести пароль пользователя
		bool success = UI_PasswordCallback(
			szTarget, szError, szUser, (int)sizeUser, 
			szPassword, (int)sizePassword, 0, pInputMethod, NULL
		); 
		// освободить выделенные ресурсы
		::UI_destroy_method(pInputMethod); return success; 
	}
	// освободить выделенные ресурсы
	catch (...) { ::UI_destroy_method(pInputMethod); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Диалог аутентификации с использованием консоли
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
static int WindowsConsole_Flush(UI* pUI) 
{
	// получить адрес реализации
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 

	// получить набор параметров
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// для всех параметров
	for (size_t i = 0; i < strings.size(); i++)
	{
		// получить тип параметра
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR:
		{
			// получить сообщение для вывода
			PCSTR szError = ::UI_get0_output_string(strings[i]); 

			// вывести сообщение
			fputs(szError, stderr); fputs("\n", stderr); break; 
		}
		case UIT_INFO:
		{
			// получить сообщение для вывода
			PCSTR szMessage = ::UI_get0_output_string(strings[i]); 

			// вывести сообщение
			fputs(szMessage, stdout); fputs("\n", stdout); break; 
		}}
	}
	// завершить операции вывода
	fflush(stdout);	fflush(stderr);

	// отобразить диалог
	return UI_Flush(pUI, WindowsConsole_ShowDialog, NULL, NULL, strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::Windows::UI_Console(PCSTR szTarget)
{
	// создать метод ввода
	UI_METHOD* pMethod = ::UI_create_method("Windows Console"); 

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// указать имя объекта
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// указать используемую функцию
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_flusher(pMethod, WindowsConsole_Flush); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// обработать возможную ошибку
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Диалог аутентификации с использованием графического интерфейса (Windows)
///////////////////////////////////////////////////////////////////////////////
static int WindowsGUI_Flush(UI* pUI) 
{ 
	// получить адрес реализации
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 
	
	// инициализировать строки
	std::string error; std::string message;

	// получить набор параметров
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// для всех параметров
	for (size_t i = 0; i < strings.size(); i++)
	{
		// получить тип параметра
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR: 
		{
			// добавить разделитель сообщений
			if (error.size() != 0) error += "\r\n"; 

			// добавить новое сообщение
			error += ::UI_get0_output_string(strings[i]); break; 
		}
		case UIT_INFO: 
		{
			// добавить разделитель сообщений
			if (message.size() != 0) message += "\r\n"; 

			// добавить новое сообщение
			message += ::UI_get0_output_string(strings[i]); break; 
		}}
	}
	// отобразить диалог
	return UI_Flush(pUI, WindowsGUI_ShowDialog, error.c_str(), message.c_str(), strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::Windows::UI_GUI(HWND hwnd, PCSTR szTarget)
{
	// создать метод ввода
	UI_METHOD* pMethod = ::UI_create_method("Windows GUI"); 

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// указать имя объекта
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// указать родительское окно
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 2, (void*)hwnd));

		// указать используемую функцию
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_flusher(pMethod, WindowsGUI_Flush); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// обработать возможную ошибку
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}

#endif 

///////////////////////////////////////////////////////////////////////////////
// Диалог аутентификации с использованием графического интерфейса (WxWidgets)
///////////////////////////////////////////////////////////////////////////////
static bool WxWidgetsGUI_ShowDialog(const UI_METHOD* pImpl, 
	const char* szError, const char* szMessage, 
	const char* szUserNamePrompt, char* szUserName, size_t sizeUserName, 
	const char* szPasswordPrompt, char* szPassword, size_t sizePassword)
{
	// получить имя объекта
	const char* szTarget = (const char*)::UI_method_get_ex_data(pImpl, 1); 

	// получить описатель родительского окна
	wxWindow* pParent = (wxWindow*)::UI_method_get_ex_data(pImpl, 2); 

	// указать приглашение ввода пароля
	std::string message(szPasswordPrompt); (void)szUserNamePrompt;

	// добавить информационное сообщение
	if (szError   && *szError  ) message = szError   + ("\n" + message); 
	if (szMessage && *szMessage) message = szMessage + ("\n" + message); 

	// выполнить преобразование типа
	wxString wxMessage = message; wxString wxCaption = szTarget; if (sizeUserName != 0)
	{
		// создать диалог ввода пароля
		Aladdin::CAPI::OpenSSL::WxWidgets::UserPasswordDialog dialog(
			pParent, wxCaption, wxMessage, szUserName
		);  
		// указать максимальный размер имени пользователя и пароля
		dialog.SetMaxUserNameLength((unsigned long)sizeUserName); 
		dialog.SetMaxPasswordLength((unsigned long)sizePassword); 

		// отобразить диалог
		int code = dialog.ShowModal(); if (code == wxID_CANCEL) return false; 

		// получить имя пользователя и введенный пароль
		std::string username = dialog.GetUser    ().ToStdString(); 
		std::string password = dialog.GetPassword().ToStdString(); 

		// скопировать имя пользователя и пароль
		SafeCopy(szUserName, sizeUserName, username.c_str()); 
		SafeCopy(szPassword, sizePassword, password.c_str()); 
	}
	else {
		// создать диалог ввода пароля
		Aladdin::CAPI::OpenSSL::WxWidgets::PasswordDialog dialog(
			pParent, wxCaption, wxMessage
		);  
		// указать максимальный размер пароля
		dialog.SetMaxLength((unsigned long)sizePassword); 

		// отобразить диалог
		int code = dialog.ShowModal(); if (code == wxID_CANCEL) return false; 

		// получить введенный пароль
		std::string password = dialog.GetValue().ToStdString(); 

		// скопировать пароль
		SafeCopy(szPassword, sizePassword, password.c_str()); 
	}
	return true; 
}

static int WxWidgetsGUI_Flush(UI* pUI) 
{ 
	// получить адрес реализации
	const UI_METHOD* pImpl = ::UI_get_method(pUI); 
	
	// инициализировать строки
	std::string error; std::string message;

	// получить набор параметров
	const std::vector<UI_STRING*>& strings = UI_Strings(pImpl);

	// для всех параметров
	for (size_t i = 0; i < strings.size(); i++)
	{
		// получить тип параметра
		switch (::UI_get_string_type(strings[i]))
		{
		case UIT_ERROR: 
		{
			// добавить разделитель сообщений
			if (error.size() != 0) error += "\n"; 

			// добавить новое сообщение
			error += ::UI_get0_output_string(strings[i]); break; 
		}
		case UIT_INFO: 
		{
			// добавить разделитель сообщений
			if (message.size() != 0) message += "\n"; 

			// добавить новое сообщение
			message += ::UI_get0_output_string(strings[i]); break; 
		}
		default: break; 
		}
	}
	// отобразить диалог
	return UI_Flush(pUI, WxWidgetsGUI_ShowDialog, error.c_str(), message.c_str(), strings); 
}

UI_METHOD* Aladdin::CAPI::OpenSSL::WxWidgets::UI_GUI(void* pParent, const char* szTarget)
{
	// создать метод ввода
	UI_METHOD* pMethod = ::UI_create_method("WxWidgets GUI"); 

	// проверить отсутствие ошибок
	AE_CHECK_OPENSSL(pMethod); int code = 0; 
	try {
		// указать имя объекта
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 1, (char*)szTarget));

		// указать родительское окно
		AE_CHECK_OPENSSL(::UI_method_set_ex_data(pMethod, 2, pParent));

		// указать используемую функцию
		code = ::UI_method_set_prompt_constructor(pMethod, UI_Prompt); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_opener(pMethod, UI_Open); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_writer(pMethod, UI_Write); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_flusher(pMethod, WxWidgetsGUI_Flush); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); 

		// указать используемую функцию
		code = ::UI_method_set_closer(pMethod, UI_Close); 

		// проверить отсутствие ошибок
		if (code < 0) AE_CHECK_OPENSSL(0); return pMethod; 
	}
	// обработать возможную ошибку
	catch (...) { ::UI_destroy_method(pMethod); throw; }
}
