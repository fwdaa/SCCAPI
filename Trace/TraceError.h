#pragma once
#if !defined _NTDDK_
#include <stdexcept>

///////////////////////////////////////////////////////////////////////////////
// Заголовочный файл, поддерживаемый с Visual Studio 2010
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#include <system_error>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Запрет встраивания функций
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define _NOINLINE      __attribute__((noinline)) 
#elif defined _MSC_VER
#define _NOINLINE      __declspec(noinline)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение используемых имен 
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#define _ERROR_CATEGORY _error_category 
#define _ERROR_CODE     _error_code
#else 
#define _ERROR_CATEGORY error_category 
#define _ERROR_CODE     error_code
#endif 

///////////////////////////////////////////////////////////////////////////////
// Категория ошибки
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int> class _ERROR_CATEGORY 
{
    // деструктор
    public: virtual ~_ERROR_CATEGORY() {} 

    // получить сообщение об ошибке
    public: virtual std::string message(T code) const = 0; 
};
}

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <typename T> struct _error_category_traits
{
    // указать тип 
    typedef typename _ERROR_CATEGORY<T> type; 
}; 
template <> struct _error_category_traits<int>
{
    // указать тип 
    typedef std::error_category type; 
}; 
template <typename T>
using error_category = typename _error_category_traits<T>::type; 
}
#else 
namespace std {
typedef trace::_ERROR_CATEGORY<> error_category; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int> class _ERROR_CODE 
{
    // категория и код ошибки (порядок расположения важен для va_list)
    private: const error_category<T>* _category; T _value; 

    // конструктор по умолчанию
    public: _ERROR_CODE() : _value(0), _category(std::system_category()) {}

    // конструктор
    public: _ERROR_CODE(T value, const error_category<T>& category) 
        
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

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <typename T> struct _error_code_traits
{
    // указать тип 
    typedef typename _ERROR_CODE<T> type; 
}; 
template <> struct _error_code_traits<int>
{
    // указать тип 
    typedef std::error_code type; 
}; 
template <typename T>
using error_code = typename _error_code_traits<T>::type; 
}
#else 
namespace std {
typedef trace::_ERROR_CODE<> error_code; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Исключение времени выполнения 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int>
class _system_error : public std::runtime_error
{
    // возникшая ошибка
    private: error_code<T> _code; 

    // конструктор
    public: _system_error(T value, const error_category<T>& category) 
        
        // сохранить переданные параметры
        : std::runtime_error(category.message(value)), _code(value, category) {}

    // конструктор
    public: _system_error(const error_code<T>& code) 
        
        // сохранить переданные параметры
        : std::runtime_error(code.message()), _code(code) {}

    // возникшая ошибка
    public: const error_code<T>& code() const { return _code; }
}; 

template <typename T> struct _system_error_traits
{
    // указать тип 
    typedef typename _system_error<T> type; 
}; 
}

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <> struct _system_error_traits<int>
{
    // указать тип 
    typedef std::system_error type; 
}; 
}
#else 
namespace std {
typedef trace::_system_error<> system_error; 
}
#endif 

namespace trace {
template <typename T = int>
class system_error : public _system_error_traits<T>::type
{
    // указать тип базового класса
    private: typedef typename _system_error_traits<T>::type base_type; 

    // конструктор
    public: system_error(T value, const error_category<T>& category) 
        
        // сохранить переданные параметры
        : base_type(value, category) {}

    // конструктор
    public: system_error(const error_code<T>& code) : base_type(code) {} 
        
	// вывести дополнительные данные ошибки
	public: virtual _NOINLINE void trace(const char*, int) const 
    {
		// вывести дополнительные данные ошибки
		trace_format("Message = %hs", base_type::what()); 	
	}
	// вывести дополнительную строку
	protected: _NOINLINE void trace_format(const char* szFormat, ...) const 
    {
        // перейти на переданные аргументы
        va_list args; va_start(args, szFormat);

		// отформатировать ошибку
		std::string message = trace::vsprintf(szFormat, args); 

		// вывести дополнительные данные ошибки
		ATRACESTR(TRACE_LEVEL_ERROR, message.c_str()); va_end(args);
	}
}; 
}

///////////////////////////////////////////////////////////////////////////////
// Отмена действия макросов
///////////////////////////////////////////////////////////////////////////////
#undef _ERROR_CATEGORY
#undef _ERROR_CODE    
#undef _NOINLINE
#endif 
