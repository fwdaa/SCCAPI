#pragma once
#if !defined _NTDDK_
#include <stdexcept>

///////////////////////////////////////////////////////////////////////////////
// ������������ ����, �������������� � Visual Studio 2010
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#include <system_error>
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ ����������� �������
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define _NOINLINE      __attribute__((noinline)) 
#elif defined _MSC_VER
#define _NOINLINE      __declspec(noinline)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ ���� 
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#define _ERROR_CATEGORY _error_category 
#define _ERROR_CODE     _error_code
#else 
#define _ERROR_CATEGORY error_category 
#define _ERROR_CODE     error_code
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int> class _ERROR_CATEGORY 
{
    // ����������
    public: virtual ~_ERROR_CATEGORY() {} 

    // �������� ��������� �� ������
    public: virtual std::string message(T code) const = 0; 
};
}

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <typename T> struct _error_category_traits
{
    // ������� ��� 
    typedef typename _ERROR_CATEGORY<T> type; 
}; 
template <> struct _error_category_traits<int>
{
    // ������� ��� 
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
// �������� ������ 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int> class _ERROR_CODE 
{
    // ��������� � ��� ������ (������� ������������ ����� ��� va_list)
    private: const error_category<T>* _category; T _value; 

    // ����������� �� ���������
    public: _ERROR_CODE() : _value(0), _category(std::system_category()) {}

    // �����������
    public: _ERROR_CODE(T value, const error_category<T>& category) 
        
        // ��������� ���������� ���������
        : _category(&category), _value(value) {}

    // ��������� ������
    public: const error_category<T>& category() const { return *_category; }
    // ��� ������
    public: T value() const { return _value;  }

    // ��������� �� ������
    public: std::string message() const { return category().message(value()); }
}; 
}

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <typename T> struct _error_code_traits
{
    // ������� ��� 
    typedef typename _ERROR_CODE<T> type; 
}; 
template <> struct _error_code_traits<int>
{
    // ������� ��� 
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
// ���������� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T = int>
class _system_error : public std::runtime_error
{
    // ��������� ������
    private: error_code<T> _code; 

    // �����������
    public: _system_error(T value, const error_category<T>& category) 
        
        // ��������� ���������� ���������
        : std::runtime_error(category.message(value)), _code(value, category) {}

    // �����������
    public: _system_error(const error_code<T>& code) 
        
        // ��������� ���������� ���������
        : std::runtime_error(code.message()), _code(code) {}

    // ��������� ������
    public: const error_code<T>& code() const { return _code; }
}; 

template <typename T> struct _system_error_traits
{
    // ������� ��� 
    typedef typename _system_error<T> type; 
}; 
}

#if !defined _MSC_VER || _MSC_VER >= 1600
namespace trace {
template <> struct _system_error_traits<int>
{
    // ������� ��� 
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
    // ������� ��� �������� ������
    private: typedef typename _system_error_traits<T>::type base_type; 

    // �����������
    public: system_error(T value, const error_category<T>& category) 
        
        // ��������� ���������� ���������
        : base_type(value, category) {}

    // �����������
    public: system_error(const error_code<T>& code) : base_type(code) {} 
        
	// ������� �������������� ������ ������
	public: virtual _NOINLINE void trace(const char*, int) const 
    {
		// ������� �������������� ������ ������
		trace_format("Message = %hs", base_type::what()); 	
	}
	// ������� �������������� ������
	protected: _NOINLINE void trace_format(const char* szFormat, ...) const 
    {
        // ������� �� ���������� ���������
        va_list args; va_start(args, szFormat);

		// ��������������� ������
		std::string message = trace::vsprintf(szFormat, args); 

		// ������� �������������� ������ ������
		ATRACESTR(TRACE_LEVEL_ERROR, message.c_str()); va_end(args);
	}
}; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������
///////////////////////////////////////////////////////////////////////////////
#undef _ERROR_CATEGORY
#undef _ERROR_CODE    
#undef _NOINLINE
#endif 
