#include "pch.h"
#include "wxwidgets.h"
#include <wx/frame.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/button.h>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#include "TraceWindows.h"
#ifdef WPP_CONTROL_GUIDS
#include "wxwidgets.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Создать отдельный поток
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void _WxCreateThread(LPTHREAD_START_ROUTINE pfn, PVOID pvData)
{
    // создать отдельный поток
    HANDLE hThread = ::CreateThread(NULL, 0, pfn, pvData, 0, NULL); 

    // проверить отсутствие ошибок
    AE_CHECK_WINAPI(hThread); ::CloseHandle(hThread);
}
#else 
void _WxCreateThread(void* (*pfn)(void*), void* pvData)
{
    pthread_t hThread; 

    // создать поток
    AE_CHECK_POSIX(::pthread_create(&hThread, NULL, pfn, NULL)); 

    // указать отдельное выполнение потока
    AE_CHECK_POSIX(::pthread_detach(hThread));
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Диалог ввода пароля
///////////////////////////////////////////////////////////////////////////////
wxDEFINE_EVENT(wxEVT_SHOW_PASSWORD_DIALOG, wxCommandEvent);

struct PASSWORD_DIALOG_DATA { wxCondition* condition; 

    // входные данные
    wxWindow* parent; wxString caption; wxString message; 

    // максимальный размер пароля
    unsigned long maxPasswordChars;  

    // выходные данные
    int code; wxString password; 
};
static void OnShowPasswordDialog(wxCommandEvent& event)
{
    // извлечь параметры сообщения
    PASSWORD_DIALOG_DATA* pData = (PASSWORD_DIALOG_DATA*)event.GetClientData(); 

    // создать диалог ввода пароля
	wxPasswordEntryDialog dialog(pData->parent, 
        pData->message, pData->caption, wxEmptyString, wxOK | wxCANCEL | wxCENTRE
    );  
    // при указании максимального размера пароля
    if (pData->maxPasswordChars != ULONG_MAX) 
    {
        // установить максимальный размер пароля
        dialog.SetMaxLength(pData->maxPasswordChars); 
    }
	// отобразить диалог
	int code = dialog.ShowModal(); if (code == wxID_OK)
    {
        // извлечь введенный пароль
        pData->password = dialog.GetValue(); 
    }
    // вернуть результат отправителю
    pData->code = code; pData->condition->Signal(); 
}

int Aladdin::CAPI::OpenSSL::WxWidgets::PasswordDialog::ShowModal() 
{
    // создать объект синхронизации
    wxMutex mutex; wxCondition condition(mutex); 
    
    // указать объект синхронизации
    PASSWORD_DIALOG_DATA data; data.condition = &condition; 

    // указать передаваемые параметры
    data.parent = parent; data.caption = caption; data.message = message; 

    // указать максимальный размер пароля
    data.maxPasswordChars = maxPasswordChars; 

    // инициализировать результат
    data.code = wxCANCEL; data.password = wxEmptyString; 

	// создать объект события 
	wxCommandEvent event(wxEVT_SHOW_PASSWORD_DIALOG);

    // передать сообщение в основной цикл
	event.SetClientData(&data); wxPostEvent(wxTheApp, event);

	// дождаться обработки сообщения
    mutex.Lock(); condition.Wait(); mutex.Unlock(); 

    // вернуть результат выполнения диалога
    password = data.password; return data.code;
}

///////////////////////////////////////////////////////////////////////////////
// Диалог ввода имени пользователя и пароля
///////////////////////////////////////////////////////////////////////////////
wxDEFINE_EVENT(wxEVT_SHOW_USER_PASSWORD_DIALOG, wxCommandEvent);

struct USER_PASSWORD_DIALOG_DATA { wxCondition* condition; 

    // входные данные
    wxWindow* parent; wxString caption; wxString message; 

    // максимальный размер имени пользователя и пароля
    unsigned long maxUserNameChars;  
    unsigned long maxPasswordChars;  

    // выходные данные
    int code; wxString user; wxString password; 
};

class WxUserPasswordDialog : public wxDialog
{
    // элементы управления диалога
    private: wxStaticText*   messageLabel;      // сообщение диалога
    private: wxStaticText*   usernameLabel;     // метка имени пользователя
    private: wxTextCtrl*     usernameTextBox;   // поле ввода имени пользователя
    private: wxStaticText*   passwordLabel;     // метка пароля
    private: wxTextCtrl*     passwordTextBox;   // поле ввода пароля
    private: wxButton*       buttonOK;          // кнопка OK
    private: wxButton*       buttonCancel;      // кнопка Cancel

    // конструктор
    public: WxUserPasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message, const wxString& user)

        // указать параметры создания окна
        : wxDialog(GetParentForModalDialog(parent, 0), wxID_ANY, caption, 
            wxPoint(wxID_ANY, wxID_ANY), wxSize(350, 175), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
	{
        // переустановить форму курсора
        wxBeginBusyCursor();

        // создать удвоенную границу
        wxSizerFlags doubleBorder; doubleBorder.DoubleBorder();

        // указать вертикальное размещение
        if (wxBoxSizer* topSizer = new wxBoxSizer(wxVERTICAL))
        {
            // создать статический текст
            if (wxSizer* hbox = CreateTextSizer(message))
            {
                // указать размещение метки
                topSizer->Add(hbox, doubleBorder);
            }
            // указать горизонтальное размещение
            if (wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL))
            {
                // создать метку имени пользователя
                usernameLabel = new wxStaticText(this, 
                    wxID_ANY, wxT("Username: "), wxDefaultPosition, wxSize(70, -1)
                );
                // указать размещение метки
                hbox->Add(usernameLabel, 0);
 
                // создать поле ввода имени пользователя
                usernameTextBox = new wxTextCtrl(this, wxID_ANY);

                // указать размещение поле ввода
                hbox->Add(usernameTextBox, 1);

                // при указании имени пользователя
                if (!user.empty()) { usernameTextBox->SetEditable(false); 
                    
                    // указать имя пользователя
                    usernameTextBox->SetLabelText(user); 
                }
                // указать привязку к верхней части диалога
                topSizer->Add(hbox, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
            }
            // указать горизонтальное размещение
            if (wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL))
            {
                // создать метку пароля
                passwordLabel = new wxStaticText(this, 
                    wxID_ANY, wxT("Password: "), wxDefaultPosition, wxSize(70, -1)
                );
                // указать размещение метки
                hbox->Add(passwordLabel, 0);
 
                // создать поле ввода имени пароля
                passwordTextBox = new wxTextCtrl(this, wxID_ANY, wxString(""),
                    wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD
                );
                // указать размещение поле ввода
                hbox->Add(passwordTextBox, 1);

                // указать привязку к верхней части диалога
                topSizer->Add(hbox, 0, wxEXPAND | wxLEFT | wxTOP | wxRIGHT, 10);
            }
            // создать кнопки диалога
            if (wxSizer* buttonSizer = CreateSeparatedButtonSizer(wxOK | wxCANCEL))
            {
                // указать размещение кнопок 
                topSizer->Add(buttonSizer, wxSizerFlags(doubleBorder).Expand());
            }
            // скорректировать размещение элементогв
            SetAutoLayout(true); SetSizer(topSizer); 

            // скорректировать размещение элементогв
            topSizer->SetSizeHints(this); topSizer->Fit(this);
        } 
        // восстановить форму курсора
        Centre(); wxEndBusyCursor();
    }
	// указать максимальный размер имени пользователя
	public: void SetMaxUserNameLength(unsigned long maxChars)
	{
	    // указать максимальный размер имени пользователя
		usernameTextBox->SetMaxLength(maxChars); 
	}
	// указать максимальный размер пароля
	public: void SetMaxPasswordLength(unsigned long maxChars)
	{
	    // указать максимальный размер пароля
		passwordTextBox->SetMaxLength(maxChars); 
	}
	// имя пользователя
	public: wxString GetUser() const { return usernameTextBox->GetValue(); }
	// введенный пароль
	public: wxString GetPassword() const { return passwordTextBox->GetValue(); }
 
    // обработчики событий
    private: void OnOK(wxCommandEvent& event) { EndModal(wxID_OK); }

    // таблица обработки сообщений
    DECLARE_EVENT_TABLE()
    wxDECLARE_DYNAMIC_CLASS(WxUserPasswordDialog);
};

// таблица обработки сообщений
BEGIN_EVENT_TABLE(WxUserPasswordDialog, wxDialog)
EVT_BUTTON(wxID_OK, WxUserPasswordDialog::OnOK)
END_EVENT_TABLE()

wxIMPLEMENT_CLASS(WxUserPasswordDialog, wxDialog);


static void OnShowUserPasswordDialog(wxCommandEvent& event)
{
    // извлечь параметры сообщения
    USER_PASSWORD_DIALOG_DATA* pData = 
        (USER_PASSWORD_DIALOG_DATA*)event.GetClientData(); 

    // создать диалог ввода пароля
	WxUserPasswordDialog dialog(pData->parent, 
        pData->caption, pData->message, pData->user
    );  
    // при указании максимального размера имени пользователя
    if (pData->maxUserNameChars != ULONG_MAX) 
    {
        // установить максимальный размер имени пользователя
        dialog.SetMaxPasswordLength(pData->maxUserNameChars); 
    }
    // при указании максимального размера пароля
    if (pData->maxPasswordChars != ULONG_MAX) 
    {
        // установить максимальный размер пароля
        dialog.SetMaxPasswordLength(pData->maxPasswordChars); 
    }
	// отобразить диалог
	int code = dialog.ShowModal(); if (code == wxID_OK)
    {
        // извлечь имя пользователя и пароль
        pData->user     = dialog.GetUser    (); 
        pData->password = dialog.GetPassword(); 
    }
    // вернуть результат отправителю
    pData->code = code; pData->condition->Signal(); 
}

int Aladdin::CAPI::OpenSSL::WxWidgets::UserPasswordDialog::ShowModal() 
{
    // создать объект синхронизации
    wxMutex mutex; wxCondition condition(mutex); 
    
    // указать объект синхронизации
    USER_PASSWORD_DIALOG_DATA data; data.condition = &condition; 

    // указать передаваемые параметры
    data.parent = parent; data.caption = caption; data.message = message; 

    // указать максимальный размер имени пользователя и пароля
    data.maxUserNameChars = maxUserNameChars; 
    data.maxPasswordChars = maxPasswordChars; 

    // инициализировать результат
    data.code = wxCANCEL; data.user = user; data.password = wxEmptyString; 

	// создать объект события 
	wxCommandEvent event(wxEVT_SHOW_USER_PASSWORD_DIALOG);

    // передать сообщение в основной цикл
	event.SetClientData(&data); wxPostEvent(wxTheApp, event);

	// дождаться обработки сообщения
    mutex.Lock(); condition.Wait(); mutex.Unlock(); 

    // вернуть результат выполнения диалога
    user = data.user; password = data.password; return data.code;
}
///////////////////////////////////////////////////////////////////////////////
// Обработка событий в отдельном потоке
///////////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp::OnInit() 
{ 
    // зарегистрировать обработчик
    Bind(wxEVT_SHOW_PASSWORD_DIALOG     , &OnShowPasswordDialog    ); 
    Bind(wxEVT_SHOW_USER_PASSWORD_DIALOG, &OnShowUserPasswordDialog); 
    
    return true; 
} 

