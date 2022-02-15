#include "stdafx.h"
#include <WindowsX.h>
#include <CommCtrl.h>
#include <iostream>
#include "resource.h"
#include "Generator.h"

//////////////////////////////////////////////////////////////////////////
// ������ ����� �������� �� �������
//////////////////////////////////////////////////////////////////////////
BOOL GeneratorCUI::GenerateSeed32()
{
	// ���� �� �������� ��������� ������
	INPUT_RECORD inputEvent; for (DWORD numberEvents = 1; ; numberEvents = 1)
	{
		// ��������� ������ � �������
		if (!::ReadConsoleInputW(_hConsole, &inputEvent, numberEvents, &numberEvents)) return FALSE; 
		
		// ��������� ������� ������������� �������
		if (inputEvent.EventType != KEY_EVENT || !inputEvent.Event.KeyEvent.bKeyDown) continue; 

		// ������� ������� ������
		WCHAR ch = inputEvent.Event.KeyEvent.uChar.UnicodeChar; std::cout << ch; 

		// ��������� ������������ ������
		if (_pHandler->OnValidChar(GetMi�rosecondsSinceEpoch(), ch, _pBuffer) >= 100) break;  
	}
	return TRUE; 
}
 
//////////////////////////////////////////////////////////////////////////
// ����������� ��������
//////////////////////////////////////////////////////////////////////////
static HMODULE GetCurrentModule() { HMODULE hModule = NULL; 

	// ������� ����������� ������ ������
	DWORD dwFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT; 

	// �������� ��������� �������� ������
	return (::GetModuleHandleExW(dwFlags, (PCWSTR)&GetCurrentModule, &hModule)) ? hModule : NULL;  
}

static HRSRC FindLocaleResource(HMODULE hModule, PCWSTR szType, PCWSTR szName, LANGID langID)
{
	// ����� ������ � ��������� �����
	HRSRC hResource = ::FindResourceExW(hModule, szType, szName, langID); 

	// ����� ������ �� ����� �� ���������
	if (!hResource) hResource = ::FindResourceW(hModule, szType, szName);
	
	// ������� ������������� ����������� �����
	if (!hResource) { langID = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US); 

		// ����� ������ �� ���������� �����
		hResource = ::FindResourceExW(hModule, szType, szName, langID);
	}
	return hResource; 
}

static int LoadLocaleString(HMODULE hModule, UINT nID, LANGID langID, PWSTR szBuffer, int cchBufferMax)
{
	// ������� ������������� ����� �����
	PCWSTR szName = MAKEINTRESOURCE((nID >> 4) + 1); if (!szBuffer) return 0; 

	// ����� ������ � ��������� �����
	HRSRC hResource = FindLocaleResource(hModule, RT_STRING, szName, langID); 

	// ��������� ���������� ������
	if (!hResource) return ::LoadStringW(hModule, nID, szBuffer, cchBufferMax); 
	
	// ��������� ������
	HGLOBAL hGlobal = ::LoadResource(hModule, hResource); 
	
	// ��������� ���������� ������
	if (!hGlobal) return ::LoadStringW(hModule, nID, szBuffer, cchBufferMax); 

	// ���������� ������ ����� �����
	DWORD cbSize = ::SizeofResource(hModule, hResource); 

	// �������� ����� ������ ������ � ��������� �������� �������
	PVOID ptr = ::LockResource(hGlobal); USHORT cch = 0; 

	// ��� ���� �������������� �����
	for (UINT i = 0; i <= (nID & 0xF); i++)
	{
		// ��������� ������ ������
		if (sizeof(USHORT) > cbSize) return 0; cch = *(USHORT*)ptr;

		// ��������� ������������� �����
		if (sizeof(USHORT) + cch * sizeof(WCHAR) > cbSize) return 0; 

		// ���������� ������
		(PBYTE&)ptr += sizeof(USHORT) + cch * sizeof(WCHAR); 

		// ���������� ������
		cbSize -= sizeof(USHORT) + cch * sizeof(WCHAR); 
	} 
	// ��������� � ������ ������
	(PBYTE&)ptr -= cch * sizeof(WCHAR);

	// ������� ����� � ������ ������
	if (cchBufferMax == 0) { *(PCWSTR*)szBuffer = (PCWSTR)ptr; return cch; }

	// ��� ������������� ������
	else if (cchBufferMax > cch)
	{
		// ����������� ��� ������
		memcpy(szBuffer, ptr, cch * sizeof(WCHAR)); 
		
		// ������� ����������� ������
		szBuffer[cch] = 0; return cch;
	}
	else {
		// ����������� ����� ������
		memcpy(szBuffer, ptr, (cchBufferMax - 1) * sizeof(WCHAR)); 

		// ������� ����������� ������
		szBuffer[cchBufferMax - 1] = 0; return cchBufferMax - 1; 
	}
}

//////////////////////////////////////////////////////////////////////////
// ������ ����� �������� �� ����������� ����
//////////////////////////////////////////////////////////////////////////
static INT_PTR WINAPI Entropy_DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
{
	// ��� ������������� �������
	if (uMsg == WM_INITDIALOG)
	{
		// ��������� ������ ��� �������
		SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)lParam); 

		// ��������� �������������� ����
		GeneratorGUI* pGenerator = (GeneratorGUI*)(LONG_PTR)lParam; 

		// ������� ��������� �������
		return pGenerator->DialogProc(hwnd, uMsg, wParam, lParam); 
	}
	else {
		// �������� ����������� �������� ���������
		GeneratorGUI* pGenerator = (GeneratorGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA); 

		// ��������� ������� ���������
		if (!pGenerator) return FALSE; 

		// ������� ��������� �������
		return pGenerator->DialogProc(hwnd, uMsg, wParam, lParam); 
	}
}

LRESULT GeneratorGUI::DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:

		// ���������������� ������
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_INITDIALOG(
			hwnd, wParam, lParam, OnInitDialog
		)); 

	case WM_CLOSE:

		// ���������� ������� �������
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_CLOSE(
			hwnd, wParam, lParam, OnClose
		)); 

	case WM_DESTROY:

		// ���������� ������� �������
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_DESTROY(
			hwnd, wParam, lParam, OnDestroy
		)); 
	}
	return FALSE; 
}

BOOL GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// �������� ��������� ������
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// �������� ��������� ������������� ����
	HWND hwndOwner = (_hParent) ? _hParent : ::GetDesktopWindow(); 

	// ���������� ������
	::SendMessage(hwnd, WM_SETICON, TRUE, 
		(LPARAM)LoadIcon(hModule, MAKEINTRESOURCE(IDI_ICON))
	);
	// ���������� ������
	::SendMessage(hwnd, WM_SETICON, FALSE, 
		(LPARAM)LoadIcon(hModule, MAKEINTRESOURCE(IDI_ICON))
	);
	// �������� ���������� ������������� ����
	RECT rcOwner; ::GetWindowRect(hwndOwner, &rcOwner); 

	// �������� ���������� �������
    RECT rcDlg; ::GetWindowRect(hwnd, &rcDlg); 

	// ����������� ���������� �������
	RECT rc; ::CopyRect(&rc, &rcOwner);

	// ��������� ����� ���������� �������
    ::OffsetRect(&rcDlg, -rcDlg.left , -rcDlg.top   ); 
    ::OffsetRect(&rc   , -rc   .left , -rc   .top   ); 
    ::OffsetRect(&rc   , -rcDlg.right, -rcDlg.bottom); 

	// ���������� ����� ���������� �������
    ::SetWindowPos(hwnd, HWND_TOP, 
		rcOwner.left + (rc.right  / 2), 
        rcOwner.top  + (rc.bottom / 2), 0, 0, SWP_NOSIZE
	); 
	// ������� ������������ ������ ���� �����
	Edit_LimitText(::GetDlgItem(hwnd, IDC_CHAR), 1); return TRUE;
}

BOOL GeneratorGUI::OnChar(HWND hwnd, WCHAR ch, int)
{
	// ���������� ����������� �������
	if (ch == 0x1B || ch == 0x0D) { ::DestroyWindow(hwnd); return FALSE; }

	// ��� ����������� �������
	size_t percent = 0; if (ValidateChar(hwnd, ch)) 
	{
		// ���������� ���������� ������
		percent = OnValidChar(GetMi�rosecondsSinceEpoch(), ch); 

		// ��������� ���������� ���������
		if (percent >= 100) { ::DestroyWindow(hwnd); return TRUE; } 
	}
	// ���������� ������������ ������
	else percent = _pHandler->OnInvalidChar(ch); 
	
	// ��������� ������� ��������-����
	SIZE_T step1 = percent * 2; SIZE_T step2 = 0; 

	// ��������� ������� ��������-����
	if (percent >= 50) { step2 = step1 - 100; step1 = 100; }

	// ������� �������� ��������
	::SendMessage(::GetDlgItem(hwnd, IDC_PROGRESS1), PBM_SETPOS, step1, 0);
	::SendMessage(::GetDlgItem(hwnd, IDC_PROGRESS2), PBM_SETPOS, step2, 0); 
	
	return FALSE; 
}

#ifdef CERT_TEST
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE hModule, LPCDLGTEMPLATEW pTemplate, HWND hParent, DLGPROC pDialogFunc); 
#else
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE hModule, LPCDLGTEMPLATEW pTemplate, HWND hParent, DLGPROC pDialogFunc)
{
	// ������� ����������� ���������� ����
	HWND hwnd = ::CreateDialogIndirectParamW(hModule, pTemplate, hParent, pDialogFunc, (LPARAM)pGenerator);

	// ���������� ���������� ����
	BOOL fOK = FALSE; ::ShowWindow(hwnd, SW_SHOW); ::UpdateWindow(hwnd);

	// ��� ���� ���������
	for (MSG msg; ::IsWindow(hwnd) && ::GetMessage(&msg, NULL, 0, 0); )   
	{  
		// ������������� ��������� 
        if (::TranslateMessage(&msg)) continue; 

		// ��� ������� ������� �������
		if (msg.message == WM_CHAR)
		{
			// ���������� ������� ������� �������
			fOK = pGenerator->OnChar(hwnd, (WCHAR)(msg.wParam), (int)(short)LOWORD(msg.lParam)); 
		}
		// ���������������� ���������
		else ::DispatchMessage(&msg);
    }
	return fOK; 
}
#endif 

BOOL GeneratorGUI::GenerateSeed32()
{
	// �������� ������� ������
	HMODULE hModule = GetCurrentModule(); PCWSTR szDlgID = MAKEINTRESOURCE(IDD_ENTROPY); 

	// ���������� ���� ������� �����������
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); 

	// ����� ������ � ��������� �����
	HRSRC hResource = FindLocaleResource(hModule, RT_DIALOG, szDlgID, langID); 
	
	// ��������� ������
	if (HGLOBAL hGlobal = (hResource) ? ::LoadResource(hModule, hResource) : NULL)  
	{
		// ��������� �������������� ����
		if (LPCDLGTEMPLATEW pTemplate = (LPCDLGTEMPLATEW)::LockResource(hGlobal)) 
		{
			// ���������� ������
			return ShowGeneratorDialog(this, hModule, pTemplate, _hParent, Entropy_DlgProc); 
		} 
	}
	return FALSE; 
}

//////////////////////////////////////////////////////////////////////////
// ������ ����� ������������ ��������
//////////////////////////////////////////////////////////////////////////
BOOL AnyChar_GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// ������� ������� �������
	if (!GeneratorGUI::OnInitDialog(hwnd, hwndFocus, lParam)) return FALSE; 

	// �������� ��������� ������
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// ���������� ���� ������� �����������
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); WCHAR szText[MAX_PATH] = {0}; 

	// �������� ������ �� ��������
	if (LoadLocaleString(hModule, IDS_PRESS_ANY, langID, szText, _countof(szText)))
	{
		// ���������� ����� � �������
		::SetWindowTextW(::GetDlgItem(hwnd, IDC_LABEL), szText); 
	}
	return TRUE; 
}

BOOL AnyChar_GeneratorGUI::ValidateChar(HWND hwnd, WCHAR ch)
{
	// �������� ��������� ����
	HWND hwndEdit = ::GetDlgItem(hwnd, IDC_CHAR); WCHAR text[2] = { ch, 0 };

	// �������������� �����
	::SetWindowTextW(hwndEdit, text); return TRUE;
}

//////////////////////////////////////////////////////////////////////////
// ������ ����� ������������� �������
//////////////////////////////////////////////////////////////////////////
SpecifiedChar_GeneratorGUI::SpecifiedChar_GeneratorGUI(
	HWND hParent, void* pBuffer, UINT timeout) 
	
	// ��������� ���������� ���������
	: GeneratorGUI(hParent, pBuffer, FALSE), _timeout(timeout)
{ 
	// ������� ��������� ��� ��������� ��������� ��������
	::CryptAcquireContextW(&_hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT); 
}  

SpecifiedChar_GeneratorGUI::~SpecifiedChar_GeneratorGUI() 
{ 
	// ���������� ���������� �������
	if (_hProvider) ::CryptReleaseContext(_hProvider, 0); 
}

LRESULT SpecifiedChar_GeneratorGUI::DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// ������� ������� �������
	if (uMsg != WM_TIMER) return GeneratorGUI::DialogProc(hwnd, uMsg, wParam, lParam); 
		
	// ���������� ������� �������
	return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_TIMER(hwnd, wParam, lParam, OnTimer)); 	
}

BOOL SpecifiedChar_GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// ������� ������� �������
	if (!GeneratorGUI::OnInitDialog(hwnd, hwndFocus, lParam)) return FALSE; 

	// �������� ��������� ������
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// ���������� ���� ������� �����������
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); WCHAR szText[MAX_PATH] = {0}; 

	// �������� ������ �� ��������
	if (LoadLocaleString(hModule, IDS_PRESS_SPECIFIED, langID, szText, _countof(szText)))
	{
		// ���������� ����� � �������
		::SetWindowTextW(::GetDlgItem(hwnd, IDC_LABEL), szText); 
	}
	// ������� ������
	if (!::SetTimer(hwnd, IDC_TIMER, _timeout, NULL)) return FALSE; 

	// ������������� ����� ������
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// �������������� �����
	::SetWindowTextW(::GetDlgItem(hwnd, IDC_CHAR), expected); return TRUE;
}

void SpecifiedChar_GeneratorGUI::OnDestroy(HWND hwnd) 
{ 
	// ������� ������
	::KillTimer(hwnd, IDC_TIMER); 
}

void SpecifiedChar_GeneratorGUI::OnTimer(HWND hwnd, int)
{
	// ������������� ����� ������
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// �������������� �����
	::SetWindowTextW(::GetDlgItem(hwnd, IDC_CHAR), expected);
}

BOOL SpecifiedChar_GeneratorGUI::ValidateChar(HWND hwnd, WCHAR ch)
{
	// �������� ��������� ����
	HWND hwndEdit = ::GetDlgItem(hwnd, IDC_CHAR); 

	// �������� ��������� ������
	WCHAR old[2] = {0}; ::GetWindowTextW(hwndEdit, old, 2);

	// ������������� ����� ������
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// ���������� ����� ������
	::SetWindowTextW(hwndEdit, expected); 
	
	// �������������� ������
	::SetTimer(hwnd, IDC_TIMER, _timeout, NULL); 
	
	// ��������� ���������� �������	
	return (ch == old[0]);  
}

WCHAR SpecifiedChar_GeneratorGUI::GenerateNextChar()
{
	// ������� ���������� ��������
	static WCHAR chars[] = { 
		L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', 
		L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', 
		L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z', 
		L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', 
		L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z' 
	}; 
	// ������������� ��������� ������
	BYTE index = 0; if (!_hProvider || !::CryptGenRandom(_hProvider, 1, &index))
	{
		// �������� ������� �������
		index = (BYTE)(::rand() % _countof(chars));
	}
	// �������� ������� �������
	else { index %= _countof(chars); } return chars[index]; 
}
