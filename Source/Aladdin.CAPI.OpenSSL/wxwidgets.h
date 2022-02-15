#pragma once
#include <wx/app.h>
#include <wx/window.h>

///////////////////////////////////////////////////////////////////////////////
// Инициализация и очистка библиотеки
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void _WxCreateThread(LPTHREAD_START_ROUTINE pfn, PVOID pvData); 
template <class WxApp>
inline DWORD WINAPI WxThreadProc(PVOID pvData)
{
    // указать класс приложения
	WxApp* app = new WxApp(); wxApp::SetInstance(app);
	
	// запрет выхода из цикла при отсутствии окон
	app->SetExitOnFrameDelete(false); 

    // запустить цикл обработки сообщений
    wxEntry((HMODULE)pvData, NULL, NULL, SW_HIDE); return 0; 
}
template <class WxApp>
inline void WxDllEntryStartup(HMODULE hModule)
{
    // создать отдельный поток обработки событий
	_WxCreateThread(&WxThreadProc<WxApp>, (PVOID)hModule); 
}
#else 
void _WxCreateThread(void* (*pfn)(void*), void* pvData); 
template <class WxApp>
inline void* WxThreadProc(void*)
{
    // указать класс приложения
	WxApp* app = new WxApp(); wxApp::SetInstance(app);
	
	// запрет выхода из цикла при отсутствии окон
	app->SetExitOnFrameDelete(false); 
	
    // запустить цикл обработки сообщений
	int argc = 0; wxEntry(argc, (char**)NULL); return NULL; 
}
template <class WxApp>
inline void WxDllEntryStartup()
{
    // создать отдельный поток обработки событий
	_WxCreateThread(&WxThreadProc<WxApp>, NULL); 
}
#endif 

// освободить используемые ресурсы
inline void WxDllEntryCleanup() 
{ 
    // получить класс приложения
	wxApp* app = static_cast<wxApp*>(wxApp::GetInstance()); 

	// освободить используемые ресурсы
	if (app) app->Exit(); wxEntryCleanup(); 
}

///////////////////////////////////////////////////////////////////////////////
// Обработка событий в отдельном потоке
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace OpenSSL { namespace WxWidgets
{
class WxDllApp : public wxApp 
{ 
	// функция инициализации
    public: virtual bool OnInit() override;  
};

///////////////////////////////////////////////////////////////////////////////
// Диалог ввода пароля
///////////////////////////////////////////////////////////////////////////////
class PasswordDialog : public wxEvtHandler
{
	// родительское окно, заголовок и сообщение диалога
	private: wxWindow* parent; wxString caption; wxString message; 

	// максимальный размер пароля
	private: unsigned long maxPasswordChars; 

	// конструктор
    public: PasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message)
	{
		// сохранить переданные параметры
		this->parent = parent; this->caption = caption; this->message = message; 

		// указать значения по умолчанию
		this->maxPasswordChars = ULONG_MAX; 
	}
	// указать максимальный размер пароля
	public: void SetMaxLength(unsigned long maxChars)
	{
		// сохранить переданные параметры
		this->maxPasswordChars = maxChars; 
	}
	// отобразить диалог
	public: int ShowModal(); private: wxString password;   

	// введенный пароль
	public: const wxString& GetValue() const { return password; }
};

///////////////////////////////////////////////////////////////////////////////
// Диалог ввода имени пользователя и пароля
///////////////////////////////////////////////////////////////////////////////
class UserPasswordDialog : public wxEvtHandler
{
	// родительское окно и имя пользователя 
	private: wxWindow* parent; wxString user;
	// заголовок и сообщение диалога
	private: wxString caption; wxString message; 

	// максимальный размер имени пользователя
	private: unsigned long maxUserNameChars; 
	// максимальный размер пароля
	private: unsigned long maxPasswordChars; 

	// конструктор
    public: UserPasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message, const wxString& user)
	{
		// сохранить переданные параметры
		this->parent = parent; this->user = user; 
		
		// сохранить переданные параметры
		this->caption = caption; this->message = message; 

		// указать значения по умолчанию
		this->maxUserNameChars = ULONG_MAX; 
		this->maxPasswordChars = ULONG_MAX; 
	}
	// указать максимальный размер имени пользователя
	public: void SetMaxUserNameLength(unsigned long maxChars)
	{
		// сохранить переданные параметры
		this->maxUserNameChars = maxChars; 
	}
	// указать максимальный размер пароля
	public: void SetMaxPasswordLength(unsigned long maxChars)
	{
		// сохранить переданные параметры
		this->maxPasswordChars = maxChars; 
	}
	// отобразить диалог
	public: int ShowModal(); private: wxString password;   

	// имя пользователя
	public: const wxString& GetUser() const { return user; }
	// введенный пароль
	public: const wxString& GetPassword() const { return password; }
};

}}}}

