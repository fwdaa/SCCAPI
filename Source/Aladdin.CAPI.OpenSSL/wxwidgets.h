#pragma once
#include <wx/app.h>
#include <wx/window.h>

///////////////////////////////////////////////////////////////////////////////
// ������������� � ������� ����������
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
void _WxCreateThread(LPTHREAD_START_ROUTINE pfn, PVOID pvData); 
template <class WxApp>
inline DWORD WINAPI WxThreadProc(PVOID pvData)
{
    // ������� ����� ����������
	WxApp* app = new WxApp(); wxApp::SetInstance(app);
	
	// ������ ������ �� ����� ��� ���������� ����
	app->SetExitOnFrameDelete(false); 

    // ��������� ���� ��������� ���������
    wxEntry((HMODULE)pvData, NULL, NULL, SW_HIDE); return 0; 
}
template <class WxApp>
inline void WxDllEntryStartup(HMODULE hModule)
{
    // ������� ��������� ����� ��������� �������
	_WxCreateThread(&WxThreadProc<WxApp>, (PVOID)hModule); 
}
#else 
void _WxCreateThread(void* (*pfn)(void*), void* pvData); 
template <class WxApp>
inline void* WxThreadProc(void*)
{
    // ������� ����� ����������
	WxApp* app = new WxApp(); wxApp::SetInstance(app);
	
	// ������ ������ �� ����� ��� ���������� ����
	app->SetExitOnFrameDelete(false); 
	
    // ��������� ���� ��������� ���������
	int argc = 0; wxEntry(argc, (char**)NULL); return NULL; 
}
template <class WxApp>
inline void WxDllEntryStartup()
{
    // ������� ��������� ����� ��������� �������
	_WxCreateThread(&WxThreadProc<WxApp>, NULL); 
}
#endif 

// ���������� ������������ �������
inline void WxDllEntryCleanup() 
{ 
    // �������� ����� ����������
	wxApp* app = static_cast<wxApp*>(wxApp::GetInstance()); 

	// ���������� ������������ �������
	if (app) app->Exit(); wxEntryCleanup(); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� � ��������� ������
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace OpenSSL { namespace WxWidgets
{
class WxDllApp : public wxApp 
{ 
	// ������� �������������
    public: virtual bool OnInit() override;  
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����� ������
///////////////////////////////////////////////////////////////////////////////
class PasswordDialog : public wxEvtHandler
{
	// ������������ ����, ��������� � ��������� �������
	private: wxWindow* parent; wxString caption; wxString message; 

	// ������������ ������ ������
	private: unsigned long maxPasswordChars; 

	// �����������
    public: PasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message)
	{
		// ��������� ���������� ���������
		this->parent = parent; this->caption = caption; this->message = message; 

		// ������� �������� �� ���������
		this->maxPasswordChars = ULONG_MAX; 
	}
	// ������� ������������ ������ ������
	public: void SetMaxLength(unsigned long maxChars)
	{
		// ��������� ���������� ���������
		this->maxPasswordChars = maxChars; 
	}
	// ���������� ������
	public: int ShowModal(); private: wxString password;   

	// ��������� ������
	public: const wxString& GetValue() const { return password; }
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����� ����� ������������ � ������
///////////////////////////////////////////////////////////////////////////////
class UserPasswordDialog : public wxEvtHandler
{
	// ������������ ���� � ��� ������������ 
	private: wxWindow* parent; wxString user;
	// ��������� � ��������� �������
	private: wxString caption; wxString message; 

	// ������������ ������ ����� ������������
	private: unsigned long maxUserNameChars; 
	// ������������ ������ ������
	private: unsigned long maxPasswordChars; 

	// �����������
    public: UserPasswordDialog(wxWindow* parent, 
		const wxString& caption, const wxString& message, const wxString& user)
	{
		// ��������� ���������� ���������
		this->parent = parent; this->user = user; 
		
		// ��������� ���������� ���������
		this->caption = caption; this->message = message; 

		// ������� �������� �� ���������
		this->maxUserNameChars = ULONG_MAX; 
		this->maxPasswordChars = ULONG_MAX; 
	}
	// ������� ������������ ������ ����� ������������
	public: void SetMaxUserNameLength(unsigned long maxChars)
	{
		// ��������� ���������� ���������
		this->maxUserNameChars = maxChars; 
	}
	// ������� ������������ ������ ������
	public: void SetMaxPasswordLength(unsigned long maxChars)
	{
		// ��������� ���������� ���������
		this->maxPasswordChars = maxChars; 
	}
	// ���������� ������
	public: int ShowModal(); private: wxString password;   

	// ��� ������������
	public: const wxString& GetUser() const { return user; }
	// ��������� ������
	public: const wxString& GetPassword() const { return password; }
};

}}}}

