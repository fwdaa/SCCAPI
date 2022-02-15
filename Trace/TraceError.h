#pragma once
#include <stdexcept>

///////////////////////////////////////////////////////////////////////////////
// ������������ ����, �������������� � Visual Studio 2010
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
#include <system_error>
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (0CEACA83, 9CF5, 4D89, A342, 6C3E7FAC62E5)
#include "TraceError.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::error_category _error_category;   // ��������� ������
#else 
class _error_category 
{
    // ����������
    public: virtual ~_error_category() {} 

    // �������� ��������� �� ������
    public: virtual std::string message(int code) const = 0; 
};
#endif 

namespace trace {
template <typename T> class error_category 
{
    // ����������
    public: virtual ~error_category() {} 

    // �������� ��������� �� ������
    public: virtual std::string message(T code) const = 0; 
};
}
///////////////////////////////////////////////////////////////////////////////
// �������� ������ 
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::error_code     _error_code;       // �������� ������
#else 
class _error_code 
{
    // ��������� � ��� ������
    private: const _error_category* _category; int _value; 

    // �����������
    public: _error_code(int value, const _error_category& category) 
        
        // ��������� ���������� ���������
        : _category(&category), _value(value) {}

    // ��������� ������
    public: const _error_category& category() const { return *_category; }
    // ��� ������
    public: int value() const { return _value;  }

    // ��������� �� ������
    public: std::string message() const { return category().message(value()); }
};
#endif 
namespace trace {
template <typename T> class error_code 
{
    // ��������� � ��� ������
    private: const error_category<T>* _category; T _value; 

    // �����������
    public: error_code(T value, const error_category<T>& category) 
        
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

///////////////////////////////////////////////////////////////////////////////
// ���������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
#if !defined _MSC_VER || _MSC_VER >= 1600
typedef std::system_error   _system_error;     // ���������� ��� ������
#else 
class _system_error : public std::runtime_error
{
    // ��������� ������ � �� ��������
    private: _error_code _code; std::string _what; 

    // �����������
    public: _system_error(int value, const _error_category& category) 
        
        // ��������� ���������� ���������
        : std::runtime_error(""), _code(value, category), _what(category.message(value)) {}

    // �����������
    public: _system_error(const _error_code& code) 
        
        // ��������� ���������� ���������
        : std::runtime_error(""), _code(code), _what(code.message()) {}

    // ��������� ������
    public: const _error_code& code() const { return _code; }

    // �������� ������
    public: virtual const char* what() const { return _what.c_str(); }
}; 
#endif 

class system_exception : public _system_error
{
    // ��� ����� � ����� ������
    private: std::string _file; private: int _line; 

    // �����������
    public: system_exception(const _error_category& category, int value, const char* szFile, int line)

        // ��������� ���������� ���������
        : _system_error(value, category), _file(szFile), _line(line) {} 

    // �����������
    public: system_exception(const _error_code& code, const char* szFile, int line)

        // ��������� ���������� ���������
        : _system_error(code), _file(szFile), _line(line) {} 

	// ������������� ������
	public: int value() const { return code().value(); }	

    // ��� �����
    public: const char* file() const { return _file.c_str(); }
    // ����� ������
    public: int line() const { return _line; }

    // ��������� ��� ��������� ������
    public: virtual void SetLastError() const = 0; 

	// ������� �������������� ������ ������
	public: virtual WPP_NOINLINE void trace() const 
    {
		// ������� �������������� ������ ������
		ATRACE(TRACE_LEVEL_ERROR, "Message = %hs", what()); 	
	} 	
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
namespace trace {
template <typename T>
class exception : public std::runtime_error
{
    // ��������� ������ � �� ��������
    private: error_code<T> _code; std::string _what; 
    // ��� ����� � ����� ������
    private: std::string _file; private: int _line;

    // �����������
    public: exception(const error_category<T>& category, T value, const char* szFile, int line)

        // ��������� ���������� ���������
        : std::runtime_error(""), _code(value, category), _what(category.message(value)), _file(szFile), _line(line) {} 

    // �����������
    public: exception(const error_code<T>& code, const char* szFile, int line)

        // ��������� ���������� ���������
        : std::runtime_error(""), _code(code), _what(code.message()), _file(szFile), _line(line) {} 

    // ��������� ������
    public: const error_code<T>& code() const { return _code; }
	// ������������� ������
	public: T value() const { return code().value(); }	

    // �������� ������
    public: virtual const char* what() const throw() { return _what.c_str(); }

    // ��� �����
    public: const char* file() const { return _file.c_str(); }
    // ����� ������
    public: int line() const { return _line; }

	// ������� �������������� ������ ������
	public: virtual WPP_NOINLINE void trace() const 
    {
		// ������� �������������� ������ ������
		ATRACE(TRACE_LEVEL_ERROR, "Message = %hs", what()); 	
	} 	
	// ��������� ����������
	public: virtual void raise() const { trace(); throw *this; }
};
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
