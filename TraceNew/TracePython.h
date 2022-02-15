#pragma once

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ Python
///////////////////////////////////////////////////////////////////////////////
class python_error_category : public trace::error_category<PyObject*>
{
	// ������� ������� ������
	private: PyObject* (*pfn_PyErr_Occurred)(); 

	// ������� ���������� ������������
	private: void (*pfn_PyErr_Fetch  )(PyObject**, PyObject**, PyObject**);
	private: void (*pfn_PyErr_Restore)(PyObject* , PyObject* , PyObject* );

	// ������ ����� Python
	private: Py_ssize_t (*pfn_PyString_Size        )(PyObject* obj); 
	private: Py_ssize_t (*pfn_PyUnicodeUCS2_GetSize)(PyObject* obj); 

	// ��������� ������������� ����� Python 
	private: int        (*pfn_PyString_AsStringAndSize)(PyObject*, char**, Py_ssize_t*);
	private: Py_ssize_t (*pfn_PyUnicodeUCS2_AsWideChar)(PyObject*, wchar_t*, Py_ssize_t); 

	// �������������� ��������� ������
	private: PyObject* (*pfn_PyUnicodeUCS2_AsUTF8String)(PyObject*); 

	// ��������� ������������� �������
	private: PyObject* (*pfn_PyObject_Unicode)(PyObject*); 

	// �����������
	public: python_error_category(HMODULE hModule) 
	{
		(FARPROC&)pfn_PyErr_Occurred			 		= GetProcAddress(hModule, "PyErr_Occurred"					); 
		(FARPROC&)pfn_PyErr_Fetch				 		= GetProcAddress(hModule, "PyErr_Fetch"	 					); 
		(FARPROC&)pfn_PyErr_Restore				 		= GetProcAddress(hModule, "PyErr_Restore"					); 
		(FARPROC&)pfn_PyString_Size						= GetProcAddress(hModule, "PyString_Size"					); 
		(FARPROC&)pfn_PyUnicodeUCS2_GetSize				= GetProcAddress(hModule, "PyUnicodeUCS2_GetSize"			); 
		(FARPROC&)pfn_PyString_AsStringAndSize			= GetProcAddress(hModule, "PyString_AsStringAndSize"		); 
		(FARPROC&)pfn_PyUnicodeUCS2_AsWideChar	 		= GetProcAddress(hModule, "PyUnicodeUCS2_AsWideChar"		); 
		(FARPROC&)pfn_PyUnicodeUCS2_AsUTF8String		= GetProcAddress(hModule, "PyUnicodeUCS2_AsUTF8String"		); 
		(FARPROC&)pfn_PyObject_Unicode			 		= GetProcAddress(hModule, "PyObject_Unicode"				); 
	}
    // �������� ��������� �� ������
    public: virtual std::string message(PyObject* status) const; 

    // �������� �������������� ������ ������
    public: void trace(PyObject* type, PyObject* value, PyObject* traceback) const; 

	///////////////////////////////////////////////////////////////////////////////
	// ���������� �������� 
	///////////////////////////////////////////////////////////////////////////////

	// ������� ������� ������
	public: PyObject* PyErr_Occurred() const { return (*pfn_PyErr_Occurred)(); }

    // �������� ��������� ������
    public: void PyErr_Fetch(PyObject** ptype, PyObject** pvalue, PyObject** ptraceback) const
	{
		// �������� ��������� ������
		(*pfn_PyErr_Fetch)(ptype, pvalue, ptraceback); 
	} 
    // ���������� ��������� ������
    public: void PyErr_Restore(PyObject* type, PyObject* value, PyObject* traceback) const
	{
		// ���������� ��������� ������
		(*pfn_PyErr_Restore)(type, value, traceback); 
	} 
	///////////////////////////////////////////////////////////////////////////////
	// ���������� ��������
	///////////////////////////////////////////////////////////////////////////////
	public: Py_ssize_t PyString_Size (PyObject* obj) const; 
	public: Py_ssize_t PyUnicode_Size(PyObject* obj) const; 

	public: std::string  PyString_AsString     (PyObject* obj) const; 
	public: std::string  PyUnicode_AsUTF8String(PyObject* obj) const; 
	public: std::wstring PyUnicode_AsWideString(PyObject* obj) const; 

	////////////////////////////////////////////////////////////////
	// ��������� ������������� �������
	////////////////////////////////////////////////////////////////
	public: std::string PyObject_AsUTF8String (PyObject* obj) const; 
	public: std::wstring PyObject_AsWideString(PyObject* obj) const;
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������ Python
///////////////////////////////////////////////////////////////////////////////
class python_error : public trace::error_code<PyObject*>
{
    // �����������
    public: python_error(const python_error_category& category, PyObject* status) 
        
        // ��������� ���������� ���������
        : trace::error_code<PyObject*>(status, category) {}

    // �����������
    public: python_error(const python_error_category& category) 
        
        // ��������� ���������� ���������
        : trace::error_code<PyObject*>(category.PyErr_Occurred(), category) {}

	// ������� ������� ������
	public: operator const void* () const 
	{ 
		// ������� ������� ������
		return (value() != 0) ? this : (const void*)0; 
	}
    // ������������� �������� ������
    public: std::string name() const
    {	
        // ��������������� ��� ������
        char str[32]; sprintf_s(str, sizeof(str), "%p", value()); return str; 
	}
}; 
// �������� ��������� �� ������
inline std::string python_error_category::message(PyObject* status) const
{
	// ��������������� ��� ������
    char str[32]; sprintf_s(str, sizeof(str), "%p", status); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� Python
///////////////////////////////////////////////////////////////////////////////
class python_exception : public trace::exception<PyObject*>
{	
    // ��� �������� ������
    private: typedef trace::exception<PyObject*> base_type; 

	// �������� ���������� Python
	private: PyObject* _type; PyObject* _value; PyObject* _traceback; 

    // �����������
    public: python_exception(const python_error& error,	const char* szFile, int line)

        // ��������� ���������� ���������
        : base_type(error, szFile, line), _type(nullptr), _value(nullptr), _traceback(nullptr)
	{
		// ��������� �������������� ����
		const python_error_category& category = 
			(const python_error_category&)error.category(); 

		// �������� �������� ����������
		if (value()) category.PyErr_Fetch(&_type, &_value, &_traceback);
	}
	// ����������� �����������
	public: python_exception(const python_exception& e) : base_type(code(), e.file(), e.line()) 
	{
		// ��������� �������� ������
		_type      = e._type     ; if (_type     ) Py_XINCREF(_type     ); 
		_value     = e._value    ; if (_value    ) Py_XINCREF(_value    ); 
		_traceback = e._traceback; if (_traceback) Py_XINCREF(_traceback);
	}
	// ����������
	public: virtual ~python_exception() 
	{
		// ��������� �������� ������
		if (_type     ) Py_XDECREF(_type     ); 
		if (_value    ) Py_XDECREF(_value    ); 
		if (_traceback) Py_XDECREF(_traceback);
	}
    // �������� �������������� ���������� �� ������
    public: virtual void trace() const { if (value()) return; 

		// �������� �������������� ���������� �� ������
		((const python_error_category&)code().category()).trace(_type, _value, _traceback); 
	} 
    // ��������� ����������
    public: virtual __noreturn void raise() const { trace(); 

		// ��������� �������������� ����
		const python_error_category& category = 
			(const python_error_category&)code().category(); 

		// ���������� ���������� Python
		category.PyErr_Restore(_type, _value, _traceback); throw *this;  
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (1A453A5C, 07A1, 4652, 88A2, BA51F837D2E4)
#include "TracePython.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� Python
///////////////////////////////////////////////////////////////////////////////
inline Py_ssize_t python_error_category::PyString_Size(PyObject* obj) const
{
	// ���������� ������ ������
	Py_ssize_t length = (*pfn_PyString_Size)(obj); 

	// ��������� ������������ ������
	if (length < 0) { AE_CHECK_PYTHON(*this); } return length; 
} 

inline Py_ssize_t python_error_category::PyUnicode_Size(PyObject* obj) const
{
	// ���������� ������ ������
	Py_ssize_t length = (*pfn_PyUnicodeUCS2_GetSize)(obj); 

	// ��������� ������������ ������
	if (length < 0) { AE_CHECK_PYTHON(*this); } return length; 
} 

inline std::string python_error_category::PyString_AsString(PyObject* obj) const
{
	char* buffer; Py_ssize_t length; 
		
	// ������� ������
	if ((*pfn_PyString_AsStringAndSize)(obj, &buffer, &length) < 0) 
	{ 
		// ��� ������ ��������� ����������
		AE_CHECK_PYTHON(*this); 
	}
	// ������� ������
	return std::string(buffer, length); 
} 

inline std::string python_error_category::PyUnicode_AsUTF8String(PyObject* obj) const
{
	// ��������� �������������� ���������
	PyObject* str = (*pfn_PyUnicodeUCS2_AsUTF8String)(obj); 
	
	// ��������� ���������� ������
	if (!str) { AE_CHECK_PYTHON(*this); } 

	// ������� ��������� ����������
	std::string value = PyString_AsString(str); 

	// ��������� ������� ������ �������
	Py_DECREF(str); return value; 
} 

inline std::wstring python_error_category::PyUnicode_AsWideString(PyObject* obj) const
{
	// ���������� ������ ������
	Py_ssize_t length = PyUnicode_Size(obj); std::wstring buffer(length, 0);

	// ������� ������
	length = (*pfn_PyUnicodeUCS2_AsWideChar)(obj, &buffer[0], length); 

	// ��������� ���������� ������
	if (length < 0) { AE_CHECK_PYTHON(*this); } 

	// ������� ������
	buffer.resize(length); return buffer; 
} 

////////////////////////////////////////////////////////////////
// ��������� ������������� ������� Python
////////////////////////////////////////////////////////////////
inline std::string python_error_category::PyObject_AsUTF8String(PyObject* obj) const
{
	// �������� ��������� ����������
	PyObject* unicodeObj = (*pfn_PyObject_Unicode)(obj); 
	
	// ��������� ���������� ������
	if (!unicodeObj) { AE_CHECK_PYTHON(*this); } 

	// ������� ��������� ����������
	std::string value = PyUnicode_AsUTF8String(unicodeObj); 

	// ��������� ������� ������ �������
	Py_DECREF(unicodeObj); return value; 
}

inline std::wstring python_error_category::PyObject_AsWideString(PyObject* obj) const
{
	// �������� ��������� ����������
	PyObject* unicodeObj = (*pfn_PyObject_Unicode)(obj); 
	
	// ��������� ���������� ������
	if (!unicodeObj) { AE_CHECK_PYTHON(*this); } 

	// ������� ��������� ����������
	std::wstring value = PyUnicode_AsWideString(unicodeObj); 

	// ��������� ������� ������ �������
	Py_DECREF(unicodeObj); return value; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� �� ������
///////////////////////////////////////////////////////////////////////////////
inline void python_error_category::trace(PyObject* type, PyObject* value, PyObject*) const
{
	// �������� �������� ����
	std::wstring message; if (type) try { message = PyObject_AsWideString(type); }

	// ��������� ���������� ������
	catch (const std::exception&) {} if (value) 
	try { 
		// �������� �������� �������
		std::wstring wstr = PyObject_AsWideString(value); 

		// �������� �������� �������
		if (!message.empty()) message += L" : "; message += wstr;
	}
	// ��������� ���������� ������
	catch (const std::exception&) {} 
		
	// ������� �������� ������
	ATRACE(TRACE_LEVEL_ERROR, "%ls", message.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_python(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// ������� ��� ������
	const python_error& error = va_arg(args, python_error); 
#else 
	// ������� ��������� ������
	const python_error_category* category = 
		(const python_error_category*)va_arg(args, const void*); 
	
	// ������� ��� ������
	python_error error(*category, va_arg(args, PyObject*));
#endif 
	// ���������� ��� ������
	std::string name = error.name(); 

	// ������� ��� ������
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(PYTHON, format_python);

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
