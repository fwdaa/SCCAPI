#include "stdafx.h"
#include <WindowsX.h>
#include <CommCtrl.h>
#include <iostream>
#include "resource.h"
#include "Generator.h"

//////////////////////////////////////////////////////////////////////////
// Способ ввода энтропии из консоли
//////////////////////////////////////////////////////////////////////////
BOOL GeneratorCUI::GenerateSeed32()
{
	// пока не прочитан требуемый символ
	INPUT_RECORD inputEvent; for (DWORD numberEvents = 1; ; numberEvents = 1)
	{
		// прочитать символ с консоли
		if (!::ReadConsoleInputW(_hConsole, &inputEvent, numberEvents, &numberEvents)) return FALSE; 
		
		// проверить нажатие отображаемого символа
		if (inputEvent.EventType != KEY_EVENT || !inputEvent.Event.KeyEvent.bKeyDown) continue; 

		// извлечь нажатый символ
		WCHAR ch = inputEvent.Event.KeyEvent.uChar.UnicodeChar; std::cout << ch; 

		// проверить отображаемый символ
		if (_pHandler->OnValidChar(GetMiсrosecondsSinceEpoch(), ch, _pBuffer) >= 100) break;  
	}
	return TRUE; 
}
 
//////////////////////////////////////////////////////////////////////////
// Локализация ресурсов
//////////////////////////////////////////////////////////////////////////
static HMODULE GetCurrentModule() { HMODULE hModule = NULL; 

	// указать специальный способ вызова
	DWORD dwFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT; 

	// получить описатель текущего модуля
	return (::GetModuleHandleExW(dwFlags, (PCWSTR)&GetCurrentModule, &hModule)) ? hModule : NULL;  
}

static HRSRC FindLocaleResource(HMODULE hModule, PCWSTR szType, PCWSTR szName, LANGID langID)
{
	// найти ресурс в требуемом языке
	HRSRC hResource = ::FindResourceExW(hModule, szType, szName, langID); 

	// найти ресурс на языке по умолчанию
	if (!hResource) hResource = ::FindResourceW(hModule, szType, szName);
	
	// указать использование английского языка
	if (!hResource) { langID = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US); 

		// найти ресурс на английском языке
		hResource = ::FindResourceExW(hModule, szType, szName, langID);
	}
	return hResource; 
}

static int LoadLocaleString(HMODULE hModule, UINT nID, LANGID langID, PWSTR szBuffer, int cchBufferMax)
{
	// указать идентификатор блока строк
	PCWSTR szName = MAKEINTRESOURCE((nID >> 4) + 1); if (!szBuffer) return 0; 

	// найти ресурс в требуемом языке
	HRSRC hResource = FindLocaleResource(hModule, RT_STRING, szName, langID); 

	// проверить отсутствие ошибок
	if (!hResource) return ::LoadStringW(hModule, nID, szBuffer, cchBufferMax); 
	
	// загрузить ресурс
	HGLOBAL hGlobal = ::LoadResource(hModule, hResource); 
	
	// проверить отсутствие ошибок
	if (!hGlobal) return ::LoadStringW(hModule, nID, szBuffer, cchBufferMax); 

	// определить размер блока строк
	DWORD cbSize = ::SizeofResource(hModule, hResource); 

	// получить адрес первой строки с указанием префикса размера
	PVOID ptr = ::LockResource(hGlobal); USHORT cch = 0; 

	// для всех предшествующих строк
	for (UINT i = 0; i <= (nID & 0xF); i++)
	{
		// прочитать размер строки
		if (sizeof(USHORT) > cbSize) return 0; cch = *(USHORT*)ptr;

		// проверить достаточность места
		if (sizeof(USHORT) + cch * sizeof(WCHAR) > cbSize) return 0; 

		// пропустить строку
		(PBYTE&)ptr += sizeof(USHORT) + cch * sizeof(WCHAR); 

		// пропустить строку
		cbSize -= sizeof(USHORT) + cch * sizeof(WCHAR); 
	} 
	// вернуться к началу строки
	(PBYTE&)ptr -= cch * sizeof(WCHAR);

	// указать адрес и размер строки
	if (cchBufferMax == 0) { *(PCWSTR*)szBuffer = (PCWSTR)ptr; return cch; }

	// при достаточности буфера
	else if (cchBufferMax > cch)
	{
		// скопировать всю строку
		memcpy(szBuffer, ptr, cch * sizeof(WCHAR)); 
		
		// указать завершающий символ
		szBuffer[cch] = 0; return cch;
	}
	else {
		// скопировать часть строки
		memcpy(szBuffer, ptr, (cchBufferMax - 1) * sizeof(WCHAR)); 

		// указать завершающий символ
		szBuffer[cchBufferMax - 1] = 0; return cchBufferMax - 1; 
	}
}

//////////////////////////////////////////////////////////////////////////
// Способ ввода энтропии из диалогового окна
//////////////////////////////////////////////////////////////////////////
static INT_PTR WINAPI Entropy_DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
{
	// при инициализации диалога
	if (uMsg == WM_INITDIALOG)
	{
		// сохранить данные для диалога
		SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)lParam); 

		// выполнить преобразование типа
		GeneratorGUI* pGenerator = (GeneratorGUI*)(LONG_PTR)lParam; 

		// вызвать процедуру диалога
		return pGenerator->DialogProc(hwnd, uMsg, wParam, lParam); 
	}
	else {
		// получить сохраненное значение указателя
		GeneratorGUI* pGenerator = (GeneratorGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA); 

		// проверить наличие указателя
		if (!pGenerator) return FALSE; 

		// вызвать процедуру диалога
		return pGenerator->DialogProc(hwnd, uMsg, wParam, lParam); 
	}
}

LRESULT GeneratorGUI::DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:

		// инициализировать диалог
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_INITDIALOG(
			hwnd, wParam, lParam, OnInitDialog
		)); 

	case WM_CLOSE:

		// обработать команду диалога
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_CLOSE(
			hwnd, wParam, lParam, OnClose
		)); 

	case WM_DESTROY:

		// обработать команду диалога
		return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_DESTROY(
			hwnd, wParam, lParam, OnDestroy
		)); 
	}
	return FALSE; 
}

BOOL GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// получить описатель модуля
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// получить описатель родительского окна
	HWND hwndOwner = (_hParent) ? _hParent : ::GetDesktopWindow(); 

	// установить иконку
	::SendMessage(hwnd, WM_SETICON, TRUE, 
		(LPARAM)LoadIcon(hModule, MAKEINTRESOURCE(IDI_ICON))
	);
	// установить иконку
	::SendMessage(hwnd, WM_SETICON, FALSE, 
		(LPARAM)LoadIcon(hModule, MAKEINTRESOURCE(IDI_ICON))
	);
	// получить координаты родительского окна
	RECT rcOwner; ::GetWindowRect(hwndOwner, &rcOwner); 

	// получить координаты диалога
    RECT rcDlg; ::GetWindowRect(hwnd, &rcDlg); 

	// скопировать координаты диалога
	RECT rc; ::CopyRect(&rc, &rcOwner);

	// вычислить новые координаты диалога
    ::OffsetRect(&rcDlg, -rcDlg.left , -rcDlg.top   ); 
    ::OffsetRect(&rc   , -rc   .left , -rc   .top   ); 
    ::OffsetRect(&rc   , -rcDlg.right, -rcDlg.bottom); 

	// установить новые координаты диалога
    ::SetWindowPos(hwnd, HWND_TOP, 
		rcOwner.left + (rc.right  / 2), 
        rcOwner.top  + (rc.bottom / 2), 0, 0, SWP_NOSIZE
	); 
	// указать максимальный размер поля ввода
	Edit_LimitText(::GetDlgItem(hwnd, IDC_CHAR), 1); return TRUE;
}

BOOL GeneratorGUI::OnChar(HWND hwnd, WCHAR ch, int)
{
	// обработать специальные клавиши
	if (ch == 0x1B || ch == 0x0D) { ::DestroyWindow(hwnd); return FALSE; }

	// для корректного символа
	size_t percent = 0; if (ValidateChar(hwnd, ch)) 
	{
		// обработать корректный символ
		percent = OnValidChar(GetMiсrosecondsSinceEpoch(), ch); 

		// проверить завершение генерации
		if (percent >= 100) { ::DestroyWindow(hwnd); return TRUE; } 
	}
	// обработать некорректный символ
	else percent = _pHandler->OnInvalidChar(ch); 
	
	// вычислить позицию прогресс-бара
	SIZE_T step1 = percent * 2; SIZE_T step2 = 0; 

	// вычислить позицию прогресс-бара
	if (percent >= 50) { step2 = step1 - 100; step1 = 100; }

	// указать прогресс операции
	::SendMessage(::GetDlgItem(hwnd, IDC_PROGRESS1), PBM_SETPOS, step1, 0);
	::SendMessage(::GetDlgItem(hwnd, IDC_PROGRESS2), PBM_SETPOS, step2, 0); 
	
	return FALSE; 
}

#ifdef CERT_TEST
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE hModule, LPCDLGTEMPLATEW pTemplate, HWND hParent, DLGPROC pDialogFunc); 
#else
BOOL ShowGeneratorDialog(GeneratorGUI* pGenerator, HMODULE hModule, LPCDLGTEMPLATEW pTemplate, HWND hParent, DLGPROC pDialogFunc)
{
	// создать немодальное диалоговое окно
	HWND hwnd = ::CreateDialogIndirectParamW(hModule, pTemplate, hParent, pDialogFunc, (LPARAM)pGenerator);

	// отобразить диалоговое окно
	BOOL fOK = FALSE; ::ShowWindow(hwnd, SW_SHOW); ::UpdateWindow(hwnd);

	// для всех сообщений
	for (MSG msg; ::IsWindow(hwnd) && ::GetMessage(&msg, NULL, 0, 0); )   
	{  
		// преобразовать сообщение 
        if (::TranslateMessage(&msg)) continue; 

		// для события нажатия клавиши
		if (msg.message == WM_CHAR)
		{
			// обработать событие нажатия клавиши
			fOK = pGenerator->OnChar(hwnd, (WCHAR)(msg.wParam), (int)(short)LOWORD(msg.lParam)); 
		}
		// диспетчеризовать сообщение
		else ::DispatchMessage(&msg);
    }
	return fOK; 
}
#endif 

BOOL GeneratorGUI::GenerateSeed32()
{
	// получить текущий модуль
	HMODULE hModule = GetCurrentModule(); PCWSTR szDlgID = MAKEINTRESOURCE(IDD_ENTROPY); 

	// определить язык текущей локализации
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); 

	// найти ресурс в требуемом языке
	HRSRC hResource = FindLocaleResource(hModule, RT_DIALOG, szDlgID, langID); 
	
	// загрузить ресурс
	if (HGLOBAL hGlobal = (hResource) ? ::LoadResource(hModule, hResource) : NULL)  
	{
		// выполнить преобразование типа
		if (LPCDLGTEMPLATEW pTemplate = (LPCDLGTEMPLATEW)::LockResource(hGlobal)) 
		{
			// отобпазить диалог
			return ShowGeneratorDialog(this, hModule, pTemplate, _hParent, Entropy_DlgProc); 
		} 
	}
	return FALSE; 
}

//////////////////////////////////////////////////////////////////////////
// Способ ввода произвольных символов
//////////////////////////////////////////////////////////////////////////
BOOL AnyChar_GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// вызвать базовую функцию
	if (!GeneratorGUI::OnInitDialog(hwnd, hwndFocus, lParam)) return FALSE; 

	// получить описатель модуля
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// определить язык текущей локализации
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); WCHAR szText[MAX_PATH] = {0}; 

	// получить строку из ресурсов
	if (LoadLocaleString(hModule, IDS_PRESS_ANY, langID, szText, _countof(szText)))
	{
		// установить текст в диалоге
		::SetWindowTextW(::GetDlgItem(hwnd, IDC_LABEL), szText); 
	}
	return TRUE; 
}

BOOL AnyChar_GeneratorGUI::ValidateChar(HWND hwnd, WCHAR ch)
{
	// получить описатель окна
	HWND hwndEdit = ::GetDlgItem(hwnd, IDC_CHAR); WCHAR text[2] = { ch, 0 };

	// переустановить текст
	::SetWindowTextW(hwndEdit, text); return TRUE;
}

//////////////////////////////////////////////////////////////////////////
// Способ ввода предлагаемого символа
//////////////////////////////////////////////////////////////////////////
SpecifiedChar_GeneratorGUI::SpecifiedChar_GeneratorGUI(
	HWND hParent, void* pBuffer, UINT timeout) 
	
	// сохранить переданные параметры
	: GeneratorGUI(hParent, pBuffer, FALSE), _timeout(timeout)
{ 
	// открыть провайдер для генерации случайных символов
	::CryptAcquireContextW(&_hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT); 
}  

SpecifiedChar_GeneratorGUI::~SpecifiedChar_GeneratorGUI() 
{ 
	// освободить выделенные ресурсы
	if (_hProvider) ::CryptReleaseContext(_hProvider, 0); 
}

LRESULT SpecifiedChar_GeneratorGUI::DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// вызвать базовую функцию
	if (uMsg != WM_TIMER) return GeneratorGUI::DialogProc(hwnd, uMsg, wParam, lParam); 
		
	// обработать событие таймера
	return SetDlgMsgResult(hwnd, uMsg, HANDLE_WM_TIMER(hwnd, wParam, lParam, OnTimer)); 	
}

BOOL SpecifiedChar_GeneratorGUI::OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	// вызвать базовую функцию
	if (!GeneratorGUI::OnInitDialog(hwnd, hwndFocus, lParam)) return FALSE; 

	// получить описатель модуля
	HMODULE hModule = (HMODULE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE); 

	// определить язык текущей локализации
	LANGID langID = LANGIDFROMLCID(::GetThreadLocale()); WCHAR szText[MAX_PATH] = {0}; 

	// получить строку из ресурсов
	if (LoadLocaleString(hModule, IDS_PRESS_SPECIFIED, langID, szText, _countof(szText)))
	{
		// установить текст в диалоге
		::SetWindowTextW(::GetDlgItem(hwnd, IDC_LABEL), szText); 
	}
	// создать таймер
	if (!::SetTimer(hwnd, IDC_TIMER, _timeout, NULL)) return FALSE; 

	// сгенерировать новый символ
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// переустановить текст
	::SetWindowTextW(::GetDlgItem(hwnd, IDC_CHAR), expected); return TRUE;
}

void SpecifiedChar_GeneratorGUI::OnDestroy(HWND hwnd) 
{ 
	// удалить таймер
	::KillTimer(hwnd, IDC_TIMER); 
}

void SpecifiedChar_GeneratorGUI::OnTimer(HWND hwnd, int)
{
	// сгенерировать новый символ
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// переустановить текст
	::SetWindowTextW(::GetDlgItem(hwnd, IDC_CHAR), expected);
}

BOOL SpecifiedChar_GeneratorGUI::ValidateChar(HWND hwnd, WCHAR ch)
{
	// получить описатель окна
	HWND hwndEdit = ::GetDlgItem(hwnd, IDC_CHAR); 

	// получить ожидаемый символ
	WCHAR old[2] = {0}; ::GetWindowTextW(hwndEdit, old, 2);

	// сгенерировать новый символ
	WCHAR expected[2] = { GenerateNextChar(), 0 }; 

	// установить новый символ
	::SetWindowTextW(hwndEdit, expected); 
	
	// переустановить таймер
	::SetTimer(hwnd, IDC_TIMER, _timeout, NULL); 
	
	// проверить совпадение символа	
	return (ch == old[0]);  
}

WCHAR SpecifiedChar_GeneratorGUI::GenerateNextChar()
{
	// таблица допустимых символов
	static WCHAR chars[] = { 
		L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', 
		L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', 
		L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z', 
		L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', 
		L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z' 
	}; 
	// сгенерировать случайные данные
	BYTE index = 0; if (!_hProvider || !::CryptGenRandom(_hProvider, 1, &index))
	{
		// получить позицию символа
		index = (BYTE)(::rand() % _countof(chars));
	}
	// получить позицию символа
	else { index %= _countof(chars); } return chars[index]; 
}
