#include "pch.h"
#include "wxwidgets.h"
#include <wx/frame.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/button.h>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#include "TraceWindows.h"
#ifdef WPP_CONTROL_GUIDS
#include "wxwidgets.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� �����
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void _WxCreateThread(LPTHREAD_START_ROUTINE pfn, PVOID pvData)
{
    // ������� ��������� �����
    HANDLE hThread = ::CreateThread(NULL, 0, pfn, pvData, 0, NULL); 

    // ��������� ���������� ������
    AE_CHECK_WINAPI(hThread); ::CloseHandle(hThread);
}
#else 
void _WxCreateThread(void* (*pfn)(void*), void* pvData)
{
    pthread_t hThread; 

    // ������� �����
    AE_CHECK_POSIX(::pthread_create(&hThread, NULL, pfn, NULL)); 

    // ������� ��������� ���������� ������
    AE_CHECK_POSIX(::pthread_detach(hThread));
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ ����� ������
///////////////////////////////////////////////////////////////////////////////
wxDEFINE_EVENT(wxEVT_SHOW_PASSWORD_DIALOG, wxCommandEvent);

struct PASSWORD_DIALOG_DATA { wxCondition* condition; 

    // ������� ������
    wxWindow* parent; wxString caption; wxString message; 

    // ������������ ������ ������
    unsigned long maxPasswordChars;  

    // �������� ������
    int code; wxString password; 
};
static void OnShowPasswordDialog(wxCommandEvent& event)
{
    // ������� ��������� ���������
    PASSWORD_DIALOG_DATA* pData = (PASSWORD_DIALOG_DATA*)event.GetClientData(); 

    // ������� ������ ����� ������
	wxPasswordEntryDialog dialog(pData->parent, 
        pData->message, pData->caption, wxEmptyString, wxOK | wxCANCEL | wxCENTRE
    );  
    // ��� �������� ������������� ������� ������
    if (pData->maxPasswordChars != ULONG_MAX) 
    {
        // ���������� ������������ ������ ������
        dialog.SetMaxLength(pData->maxPasswordChars); 
    }
	// ���������� ������
	int code = dialog.ShowModal(); if (code == wxID_OK)
    {
        // ������� ��������� ������
        pData->password = dialog.GetValue(); 
    }
    // ������� ��������� �����������
    pData->code = code; pData->condition->Signal(); 
}

int Aladdin::CAPI::OpenSSL::WxWidgets::PasswordDialog::ShowModal() 
{
    // ������� ������ �������������
    wxMutex mutex; wxCondition condition(mutex); 
    
    // ������� ������ �������������
    PASSWORD_DIALOG_DATA data; data.condition = &condition; 

    // ������� ������������ ���������
    data.parent = parent; data.caption = caption; data.message = message; 

    // ������� ������������ ������ ������
    data.maxPasswordChars = maxPasswordChars; 

    // ���������������� ���������
    data.code = wxCANCEL; data.password = wxEmptyString; 

	// ������� ������ ������� 
	wxCommandEvent event(wxEVT_SHOW_PASSWORD_DIALOG);

    // �������� ��������� � �������� ����
	event.SetClientData(&data); wxPostEvent(wxTheApp, event);

	// ��������� ��������� ���������
    mutex.Lock(); condition.Wait(); mutex.Unlock(); 

    // ������� ��������� ���������� �������
    password = data.password; return data.code;
}

///////////////////////////////////////////////////////////////////////////////
// ������ ����� ����� ������������ � ������
///////////////////////////////////////////////////////////////////////////////
wxDEFINE_EVENT(wxEVT_SHOW_USER_PASSWORD_DIALOG, wxCommandEvent);

struct USER_PASSWORD_DIALOG_DATA { wxCondition* condition; 

    // ������� ������
    wxWindow* parent; wxString caption; wxString message; 

    // ������������ ������ ����� ������������ � ������
    unsigned long maxUserNameChars;  
    unsigned long maxPasswordChars;  

    // �������� ������
    int code; wxString user; wxString password; 
};

class WxUserPasswordDialog : public wxDialog
{
    // �������� ���������� �������
    private: wxStaticText*   messageLabel;      // ��������� �������
    private: wxStaticText*   usernameLabel;     // ����� ����� ������������
    private: wxTextCtrl*     usernameTextBox;   // ���� ����� ����� ������������
    private: wxStaticText*   passwordLabel;     // ����� ������
    private: wxTextCtrl*     passwordTextBox;   // ���� ����� ������
    private: wxButton*       buttonOK;          // ������ OK
    private: wxButton*       buttonCancel;      // ������ Cancel

    // �����������
    public: WxUserPasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message, const wxString& user)

        // ������� ��������� �������� ����
        : wxDialog(GetParentForModalDialog(parent, 0), wxID_ANY, caption, 
            wxPoint(wxID_ANY, wxID_ANY), wxSize(350, 175), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
	{
        // �������������� ����� �������
        wxBeginBusyCursor();

        // ������� ��������� �������
        wxSizerFlags doubleBorder; doubleBorder.DoubleBorder();

        // ������� ������������ ����������
        if (wxBoxSizer* topSizer = new wxBoxSizer(wxVERTICAL))
        {
            // ������� ����������� �����
            if (wxSizer* hbox = CreateTextSizer(message))
            {
                // ������� ���������� �����
                topSizer->Add(hbox, doubleBorder);
            }
            // ������� �������������� ����������
            if (wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL))
            {
                // ������� ����� ����� ������������
                usernameLabel = new wxStaticText(this, 
                    wxID_ANY, wxT("Username: "), wxDefaultPosition, wxSize(70, -1)
                );
                // ������� ���������� �����
                hbox->Add(usernameLabel, 0);
 
                // ������� ���� ����� ����� ������������
                usernameTextBox = new wxTextCtrl(this, wxID_ANY);

                // ������� ���������� ���� �����
                hbox->Add(usernameTextBox, 1);

                // ��� �������� ����� ������������
                if (!user.empty()) { usernameTextBox->SetEditable(false); 
                    
                    // ������� ��� ������������
                    usernameTextBox->SetLabelText(user); 
                }
                // ������� �������� � ������� ����� �������
                topSizer->Add(hbox, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
            }
            // ������� �������������� ����������
            if (wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL))
            {
                // ������� ����� ������
                passwordLabel = new wxStaticText(this, 
                    wxID_ANY, wxT("Password: "), wxDefaultPosition, wxSize(70, -1)
                );
                // ������� ���������� �����
                hbox->Add(passwordLabel, 0);
 
                // ������� ���� ����� ����� ������
                passwordTextBox = new wxTextCtrl(this, wxID_ANY, wxString(""),
                    wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD
                );
                // ������� ���������� ���� �����
                hbox->Add(passwordTextBox, 1);

                // ������� �������� � ������� ����� �������
                topSizer->Add(hbox, 0, wxEXPAND | wxLEFT | wxTOP | wxRIGHT, 10);
            }
            // ������� ������ �������
            if (wxSizer* buttonSizer = CreateSeparatedButtonSizer(wxOK | wxCANCEL))
            {
                // ������� ���������� ������ 
                topSizer->Add(buttonSizer, wxSizerFlags(doubleBorder).Expand());
            }
            // ��������������� ���������� ����������
            SetAutoLayout(true); SetSizer(topSizer); 

            // ��������������� ���������� ����������
            topSizer->SetSizeHints(this); topSizer->Fit(this);
        } 
        // ������������ ����� �������
        Centre(); wxEndBusyCursor();
    }
	// ������� ������������ ������ ����� ������������
	public: void SetMaxUserNameLength(unsigned long maxChars)
	{
	    // ������� ������������ ������ ����� ������������
		usernameTextBox->SetMaxLength(maxChars); 
	}
	// ������� ������������ ������ ������
	public: void SetMaxPasswordLength(unsigned long maxChars)
	{
	    // ������� ������������ ������ ������
		passwordTextBox->SetMaxLength(maxChars); 
	}
	// ��� ������������
	public: wxString GetUser() const { return usernameTextBox->GetValue(); }
	// ��������� ������
	public: wxString GetPassword() const { return passwordTextBox->GetValue(); }
 
    // ����������� �������
    private: void OnOK(wxCommandEvent& event) { EndModal(wxID_OK); }

    // ������� ��������� ���������
    DECLARE_EVENT_TABLE()
    wxDECLARE_DYNAMIC_CLASS(WxUserPasswordDialog);
};

// ������� ��������� ���������
BEGIN_EVENT_TABLE(WxUserPasswordDialog, wxDialog)
EVT_BUTTON(wxID_OK, WxUserPasswordDialog::OnOK)
END_EVENT_TABLE()

wxIMPLEMENT_CLASS(WxUserPasswordDialog, wxDialog);


static void OnShowUserPasswordDialog(wxCommandEvent& event)
{
    // ������� ��������� ���������
    USER_PASSWORD_DIALOG_DATA* pData = 
        (USER_PASSWORD_DIALOG_DATA*)event.GetClientData(); 

    // ������� ������ ����� ������
	WxUserPasswordDialog dialog(pData->parent, 
        pData->caption, pData->message, pData->user
    );  
    // ��� �������� ������������� ������� ����� ������������
    if (pData->maxUserNameChars != ULONG_MAX) 
    {
        // ���������� ������������ ������ ����� ������������
        dialog.SetMaxPasswordLength(pData->maxUserNameChars); 
    }
    // ��� �������� ������������� ������� ������
    if (pData->maxPasswordChars != ULONG_MAX) 
    {
        // ���������� ������������ ������ ������
        dialog.SetMaxPasswordLength(pData->maxPasswordChars); 
    }
	// ���������� ������
	int code = dialog.ShowModal(); if (code == wxID_OK)
    {
        // ������� ��� ������������ � ������
        pData->user     = dialog.GetUser    (); 
        pData->password = dialog.GetPassword(); 
    }
    // ������� ��������� �����������
    pData->code = code; pData->condition->Signal(); 
}

int Aladdin::CAPI::OpenSSL::WxWidgets::UserPasswordDialog::ShowModal() 
{
    // ������� ������ �������������
    wxMutex mutex; wxCondition condition(mutex); 
    
    // ������� ������ �������������
    USER_PASSWORD_DIALOG_DATA data; data.condition = &condition; 

    // ������� ������������ ���������
    data.parent = parent; data.caption = caption; data.message = message; 

    // ������� ������������ ������ ����� ������������ � ������
    data.maxUserNameChars = maxUserNameChars; 
    data.maxPasswordChars = maxPasswordChars; 

    // ���������������� ���������
    data.code = wxCANCEL; data.user = user; data.password = wxEmptyString; 

	// ������� ������ ������� 
	wxCommandEvent event(wxEVT_SHOW_USER_PASSWORD_DIALOG);

    // �������� ��������� � �������� ����
	event.SetClientData(&data); wxPostEvent(wxTheApp, event);

	// ��������� ��������� ���������
    mutex.Lock(); condition.Wait(); mutex.Unlock(); 

    // ������� ��������� ���������� �������
    user = data.user; password = data.password; return data.code;
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ������� � ��������� ������
///////////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::OpenSSL::WxWidgets::WxDllApp::OnInit() 
{ 
    // ���������������� ����������
    Bind(wxEVT_SHOW_PASSWORD_DIALOG     , &OnShowPasswordDialog    ); 
    Bind(wxEVT_SHOW_USER_PASSWORD_DIALOG, &OnShowUserPasswordDialog); 
    
    return true; 
} 

