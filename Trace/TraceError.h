#pragma once
#include <stdexcept>

///////////////////////////////////////////////////////////////////////////////
// Заголовочный файл, поддерживаемый с Visual Studio 2010
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#include <system_error>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (0CEACA83, 9CF5, 4D89, A342, 6C3E7FAC62E5)
#include "TraceError.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Категория ошибки
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::error_category _error_category;   // категория ошибки
#else 
class _error_category 
{
    // деструктор
    public: virtual ~_error_category() {} 

    // получить сообщение об ошибке
    public: virtual std::string message(int code) const = 0; 
};
#endif 

namespace trace {
template <typename T> class error_category 
{
    // деструктор
    public: virtual ~error_category() {} 

    // получить сообщение об ошибке
    public: virtual std::string message(T code) const = 0; 
};
}
///////////////////////////////////////////////////////////////////////////////
// Описание ошибки 
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::error_code     _error_code;       // описание ошибки
#else 
class _error_code 
{
    // категория и код ошибки
    private: const _error_category* _category; int _value; 

    // конструктор
    public: _error_code(int value, const _error_category& category) 
        
        // сохранить переданные параметры
        : _category(&category), _value(value) {}

    // категория ошибки
    public: const _error_category& category() const { return *_category; }
    // код ошибки
    public: int value() const { return _value;  }

    // сообщение об ошибке
    public: std::string message() const { return category().message(value()); }
};
#endif 
namespace trace {
template <typename T> class error_code 
{
    // категория и код ошибки
    private: const error_category<T>* _category; T _value; 

    // конструктор
    public: error_code(T value, const error_category<T>& category) 
        
        // сохранить переданные параметры
        : _category(&category), _value(value) {}

    // категория ошибки
    public: const error_category<T>& category() const { return *_category; }
    // код ошибки
    public: T value() const { return _value;  }

    // сообщение об ошибке
    public: std::string message() const { return category().message(value()); }
}; 
}

///////////////////////////////////////////////////////////////////////////////
// Исключение операционной системы
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::system_error   _system_error;     // исключение при ошибке
#else 
class _system_error : public std::runtime_error
{
    // возникшая ошибка и ее описание
    private: _error_code _code; std::string _what; 

    // конструктор
    public: _system_error(int value, const _error_category& category) 
        
        // сохранить переданные параметры
        : std::runtime_error(""), _code(value, category), _what(category.message(value)) {}

    // конструктор
    public: _system_error(const _error_code& code) 
        
        // сохранить переданные параметры
        : std::runtime_error(""), _code(code), _what(code.message()) {}

    // возникшая ошибка
    public: const _error_code& code() const { return _code; }

    // описание ошибки
    public: virtual const char* what() const { return _what.c_str(); }
}; 
#endif 

class system_exception : public _system_error
{
    // имя файла и номер строки
    private: std::string _file; private: int _line; 

    // конструктор
    public: system_exception(const _error_category& category, int value, const char* szFile, int line)

        // сохранить переданные параметры
        : _system_error(value, category), _file(szFile), _line(line) {} 

    // конструктор
    public: system_exception(const _error_code& code, const char* szFile, int line)

        // сохранить переданные параметры
        : _system_error(code), _file(szFile), _line(line) {} 

	// идентификатор ошибки
	public: int value() const { return code().value(); }	

    // имя файла
    public: const char* file() const { return _file.c_str(); }
    // номер строки
    public: int line() const { return _line; }

    // сохранить код последней ошибки
    public: virtual void SetLastError() const = 0; 

	// вывести дополнительные данные ошибки
	public: virtual WPP_NOINLINE void trace() const 
    {
		// вывести дополнительные данные ошибки
		ATRACE(TRACE_LEVEL_ERROR, "Message = %hs", what()); 	
	} 	
};

///////////////////////////////////////////////////////////////////////////////
// Исключение времени выполнения
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T>
class exception : public std::runtime_error
{
    // возникшая ошибка и ее описание
    private: error_code<T> _code; std::string _what; 
    // имя файла и номер строки
    private: std::string _file; private: int _line;

    // конструктор
    public: exception(const error_category<T>& category, T value, const char* szFile, int line)

        // сохранить переданные параметры
        : std::runtime_error(""), _code(value, category), _what(category.message(value)), _file(szFile), _line(line) {} 

    // конструктор
    public: exception(const error_code<T>& code, const char* szFile, int line)

        // сохранить переданные параметры
        : std::runtime_error(""), _code(code), _what(code.message()), _file(szFile), _line(line) {} 

    // возникшая ошибка
    public: const error_code<T>& code() const { return _code; }
	// идентификатор ошибки
	public: T value() const { return code().value(); }	

    // описание ошибки
    public: virtual const char* what() const throw() { return _what.c_str(); }

    // имя файла
    public: const char* file() const { return _file.c_str(); }
    // номер строки
    public: int line() const { return _line; }

	// вывести дополнительные данные ошибки
	public: virtual WPP_NOINLINE void trace() const 
    {
		// вывести дополнительные данные ошибки
		ATRACE(TRACE_LEVEL_ERROR, "Message = %hs", what()); 	
	} 	
	// выбросить исключение
	public: virtual void raise() const { trace(); throw *this; }
};
}

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
