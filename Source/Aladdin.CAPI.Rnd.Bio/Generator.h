#pragma once
#include <vector>
#include <memory>

//////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
//////////////////////////////////////////////////////////////////////////
struct Generator 
{ 
	// адрес функции определения времени
	private: FARPROC _pfnGetSystemTimeAsFileTime; 

	// конструктор/деструктор
	public: Generator(); virtual ~Generator() {}

	// получить текущее время
	public: long long GetMiсrosecondsSinceEpoch() const; 

	// сгенерировать 32-байта
	public: virtual BOOL GenerateSeed32() = 0; 
}; 
 
//////////////////////////////////////////////////////////////////////////
// Обработчик нажатий клавиш
//////////////////////////////////////////////////////////////////////////
struct ICharHandler { virtual ~ICharHandler() {}

	// обработать корректный символ
	virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer) = 0;  
	// обработать некорректный символ
	virtual size_t OnInvalidChar(WCHAR ch) = 0;  
};

class LegacyCharHandler : public ICharHandler
{
	// моменты времени и данные для энтропии
	private: std::vector<long long> _occurences; std::wstring _str; 

	// обработать корректный символ
	public: virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer);  
	// обработать некорректный символ
	public: virtual size_t OnInvalidChar(WCHAR ch);  
};

class CertCharHandler : public ICharHandler
{ 
	// моменты времени и данные для энтропии
	private: std::vector<long long> _occurences; size_t _v[8]; 

	// конструктор
	public: CertCharHandler() { memset(_v, 0, sizeof(_v)); }

	// обработать корректный символ
	public: virtual size_t OnValidChar(long long timer, WCHAR ch, void* pBuffer);  
	// обработать некорректный символ
	public: virtual size_t OnInvalidChar(WCHAR ch);  
};

//////////////////////////////////////////////////////////////////////////
// Способ ввода энтропии из консоли
//////////////////////////////////////////////////////////////////////////
class GeneratorCUI : public Generator
{
	// описатель консоли и адрес буфера
	private: HANDLE _hConsole; void* _pBuffer;  
	// обработчик нажатий
	private: ICharHandler* _pHandler; 

	// конструктор
	public: GeneratorCUI(HANDLE hConsole, void* pBuffer, BOOL legacy) 
		
		// сохранить переданные параметры
		: _hConsole(hConsole), _pBuffer(pBuffer) 
	{
		// указать используемый обработчик нажатий клавиш
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// указать используемый обработчик нажатий клавиш
		else _pHandler = new CertCharHandler(); 
	} 
	// конструктор
	public: GeneratorCUI(void* pBuffer, BOOL legacy) : _pBuffer(pBuffer)
	{
		// получить описатель консоли
		_hConsole = ::GetStdHandle(STD_INPUT_HANDLE); 

		// указать используемый обработчик нажатий клавиш
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// указать используемый обработчик нажатий клавиш
		else _pHandler = new CertCharHandler(); 
	}
	// деструктор
	public: virtual ~GeneratorCUI() { delete _pHandler; }

	// сгенерировать 32-байта
	public: virtual BOOL GenerateSeed32(); 
}; 

//////////////////////////////////////////////////////////////////////////
// Способ ввода энтропии из диалогового окна
//////////////////////////////////////////////////////////////////////////
class GeneratorGUI : public Generator
{
	// родительское окно и буфер результата
	private: HWND _hParent; void* _pBuffer; 
	// обработчик нажатий
	private: ICharHandler* _pHandler; 

	// конструктор
	public: GeneratorGUI(HWND hParent, void* pBuffer, BOOL legacy)
		
		// сохранить переданные параметры
		: _hParent(hParent), _pBuffer(pBuffer) 
	{
		// указать используемый обработчик нажатий клавиш
		if (legacy) _pHandler = new LegacyCharHandler(); 

		// указать используемый обработчик нажатий клавиш
		else _pHandler = new CertCharHandler(); 
	} 
	// деструктор
	public: virtual ~GeneratorGUI() { delete _pHandler; }

	// сгенерировать случайную последовательность
	public: virtual BOOL GenerateSeed32(); 

	// процедура окна
	public: virtual LRESULT DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);  

	// инициализировать диалог
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// закрыть диалог
	protected: virtual void OnClose(HWND hwnd) { ::DestroyWindow(hwnd); }
	// освободить ресурсы			 
	protected: virtual void OnDestroy(HWND hwnd) {}

	// обработка нажатия клавиши
	public: virtual BOOL OnChar(HWND hwnd, WCHAR ch, int);

	// обработать корректный символ
	public: size_t OnValidChar(long long timer, WCHAR ch) 
	{ 
		// обработать корректный символ
		return _pHandler->OnValidChar(timer, ch, _pBuffer); 
	}
	// проверка корректности символа
	protected: virtual BOOL ValidateChar(HWND, WCHAR) { return TRUE; }
};

//////////////////////////////////////////////////////////////////////////
// Способ ввода произвольных символов
//////////////////////////////////////////////////////////////////////////
class AnyChar_GeneratorGUI : public GeneratorGUI
{
	// конструктор
	public: AnyChar_GeneratorGUI(HWND hParent, void* pBuffer, BOOL legacy) 
		
		// сохранить переданные параметры
		: GeneratorGUI(hParent, pBuffer, legacy) {}

	// инициализировать диалог
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// проверка корректности символа
	protected: virtual BOOL ValidateChar(HWND, WCHAR); 
};

//////////////////////////////////////////////////////////////////////////
// Способ ввода предлагаемого символа
//////////////////////////////////////////////////////////////////////////
class SpecifiedChar_GeneratorGUI : public GeneratorGUI
{
	// тайм-аут ожидания ввода и описатель криптопровайдера 
	private: UINT _timeout; HCRYPTPROV _hProvider; 

	// конструктор
	public: SpecifiedChar_GeneratorGUI(HWND hParent, void* pBuffer, UINT timeout);
	// деструктор
	public: virtual ~SpecifiedChar_GeneratorGUI();

	// процедура окна
	public: virtual LRESULT DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);  

	// инициализировать диалог
	protected: virtual BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam); 
	// освободить ресурсы			 
	protected: virtual void OnDestroy(HWND hwnd); 

	// обработать команду таймера
	protected: virtual void OnTimer(HWND hwnd, int); 

	// проверка корректности символа
	protected: virtual BOOL ValidateChar(HWND hwnd, WCHAR ch); 
	// сгенерировать новый символ
	protected: WCHAR GenerateNextChar();  
};
