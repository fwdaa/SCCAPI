#pragma once
#include <vector>
#include <memory>

//////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
//////////////////////////////////////////////////////////////////////////
struct Generator 
{ 
	// ����� ������� ����������� �������
	private: FARPROC _pfnGetSystemTimeAsFileTime; 

	// �����������/����������
	public: Generator(); virtual ~Generator() {}

	// �������� ������� �����
	public: long long GetMi�rosecondsSinceEpoch() const; 

	// ������������� 32-�����
	public: virtual BOOL GenerateSeed32() = 0; 
}; 
 
//////////////////////////////////////////////////////////////////////////
// ���������� ������� ������
//////////////////////////////////////////////////////////////////////////
struct ICharHandler { virtual ~ICharHandler() {}

	// ���������� ���������� ������
	virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer) = 0;  
	// ���������� ������������ ������
	virtual size_t OnInvalidChar(WCHAR ch) = 0;  
};

class LegacyCharHandler : public ICharHandler
{
	// ������� ������� � ������ ��� ��������
	private: std::vector<long long> _occurences; std::wstring _str; 

	// ���������� ���������� ������
	public: virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer);  
	// ���������� ������������ ������
	public: virtual size_t OnInvalidChar(WCHAR ch);  
};

class CertCharHandler : public ICharHandler
{ 
	// ������� ������� � ������ ��� ��������
	private: std::vector<long long> _occurences; size_t _v[8]; 

	// �����������
	public: CertCharHandler() { memset(_v, 0, sizeof(_v)); }

	// ���������� ���������� ������
	public: virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer);  
	// ���������� ������������ ������
	public: virtual size_t OnInvalidChar(WCHAR ch);  
};

//////////////////////////////////////////////////////////////////////////
// ������ ����� �������� �� �������
//////////////////////////////////////////////////////////////////////////
class GeneratorCUI : public Generator
{
	// ��������� ������� � ����� ������
	private: HANDLE _hConsole; void* _pBuffer;  
	// ���������� �������
	private: ICharHandler* _pHandler; 

	// �����������
	public: GeneratorCUI(HANDLE hConsole, void* pBuffer, BOOL legacy) 
		
		// ��������� ���������� ���������
		: _hConsole(hConsole), _pBuffer(pBuffer) 
	{
		// ������� ������������ ���������� ������� ������
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// ������� ������������ ���������� ������� ������
		else _pHandler = new CertCharHandler(); 
	} 
	// �����������
	public: GeneratorCUI(void* pBuffer, BOOL legacy) : _pBuffer(pBuffer)
	{
		// �������� ��������� �������
		_hConsole = ::GetStdHandle(STD_INPUT_HANDLE); 

		// ������� ������������ ���������� ������� ������
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// ������� ������������ ���������� ������� ������
		else _pHandler = new CertCharHandler(); 
	}
	// ����������
	public: virtual ~GeneratorCUI() { delete _pHandler; }

	// ������������� 32-�����
	public: virtual BOOL GenerateSeed32(); 
}; 

//////////////////////////////////////////////////////////////////////////
// ������ ����� �������� �� ����������� ����
//////////////////////////////////////////////////////////////////////////
class GeneratorGUI : public Generator
{
	// ������������ ���� � ����� ����������
	private: HWND _hParent; void* _pBuffer; 
	// ���������� �������
	private: ICharHandler* _pHandler; 

	// �����������
	public: GeneratorGUI(HWND hParent, void* pBuffer, BOOL legacy)
		
		// ��������� ���������� ���������
		: _hParent(hParent), _pBuffer(pBuffer) 
	{
		// ������� ������������ ���������� ������� ������
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// ������� ������������ ���������� ������� ������
		else _pHandler = new CertCharHandler(); 
	} 
	// ����������
	public: virtual ~GeneratorGUI() { delete _pHandler; }

	// ������������� ��������� ������������������
	public: virtual BOOL GenerateSeed32(); 

	// ��������� ����
	public: virtual LRESULT DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);  

	// ���������������� ������
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// ������� ������
	protected: virtual void OnClose(HWND hwnd) { ::DestroyWindow(hwnd); }
	// ���������� �������			 
	protected: virtual void OnDestroy(HWND hwnd) {}

	// ��������� ������� �������
	public: virtual BOOL OnChar(HWND hwnd, WCHAR ch, int);

	// ���������� ���������� ������
	public: size_t OnValidChar(long long timer, WCHAR ch) 
	{ 
		// ���������� ���������� ������
		return _pHandler->OnValidChar(timer, ch, _pBuffer); 
	}
	// �������� ������������ �������
	protected: virtual BOOL ValidateChar(HWND, WCHAR) { return TRUE; }
};

//////////////////////////////////////////////////////////////////////////
// ������ ����� ������������ ��������
//////////////////////////////////////////////////////////////////////////
class AnyChar_GeneratorGUI : public GeneratorGUI
{
	// �����������
	public: AnyChar_GeneratorGUI(HWND hParent, void* pBuffer, BOOL legacy) 
		
		// ��������� ���������� ���������
		: GeneratorGUI(hParent, pBuffer, legacy) {}

	// ���������������� ������
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// �������� ������������ �������
	protected: virtual BOOL ValidateChar(HWND, WCHAR); 
};

//////////////////////////////////////////////////////////////////////////
// ������ ����� ������������� �������
//////////////////////////////////////////////////////////////////////////
class SpecifiedChar_GeneratorGUI : public GeneratorGUI
{
	// ����-��� �������� ����� � ��������� ���������������� 
	private: UINT _timeout; HCRYPTPROV _hProvider; 

	// �����������
	public: SpecifiedChar_GeneratorGUI(HWND hParent, void* pBuffer, UINT timeout);
	// ����������
	public: virtual ~SpecifiedChar_GeneratorGUI();

	// ��������� ����
	public: virtual LRESULT DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);  

	// ���������������� ������
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// ���������� �������			 
	protected: virtual void OnDestroy(HWND hwnd); 

	// ���������� ������� �������
	protected: virtual void OnTimer(HWND hwnd, int); 

	// �������� ������������ �������
	protected: virtual BOOL ValidateChar(HWND hwnd, WCHAR ch); 
	// ������������� ����� ������
	protected: WCHAR GenerateNextChar();  
};
