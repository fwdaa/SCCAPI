#pragma once
#include "patchlevel.h"

///////////////////////////////////////////////////////////////////////////////
// ������������ ������� 
///////////////////////////////////////////////////////////////////////////////
class PyDecrementor
{
	// ������� ������������ ������� 
	private: void (*pfn__Py_Dealloc)(PyObject*); 

	// �����������
	public: PyDecrementor(void (*pfn__Py_Dealloc)(PyObject*))
	{
		// ��������� ���������� ��������� 
		this->pfn__Py_Dealloc = pfn__Py_Dealloc; 
	}
	// �������� ������ 
	public: void operator()(PyObject* op) const
	{
#if (PY_MAJOR_VERSION >= 3)
		// ��������� ������� ������ ������� 
		if (--op->ob_refcnt == 0) (*pfn__Py_Dealloc)(op);
#else 
		Py_DECREF(op);
#endif 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ Python
///////////////////////////////////////////////////////////////////////////////
class python_error_category : public trace::error_category<PyObject*>
{
	// �����������
	public: python_error_category(HMODULE hModule) : pfn__Py_Dealloc(nullptr) 
	{
		// ���������������� ���������� 
		pfn_PyUnicode_AsUTF8AndSize = nullptr; pfn_PyString_AsStringAndSize = nullptr;
		pfn_PyUnicode_AsUTF8String  = nullptr; 

		// ���������� ������ ������� 
		(FARPROC&)pfn_PyErr_Occurred			 = GetProcAddress(hModule, "PyErr_Occurred"				); 
		(FARPROC&)pfn_PyErr_Fetch				 = GetProcAddress(hModule, "PyErr_Fetch"	 			); 
		(FARPROC&)pfn_PyErr_Restore				 = GetProcAddress(hModule, "PyErr_Restore"				); 
#if (PY_MAJOR_VERSION >= 3)
		(FARPROC&)pfn__Py_Dealloc				= GetProcAddress(hModule, "_Py_Dealloc"					); 
		(FARPROC&)pfn_PyUnicode_GetSize			= GetProcAddress(hModule, "PyUnicode_GetSize"			); 
		(FARPROC&)pfn_PyUnicode_AsWideChar	 	= GetProcAddress(hModule, "PyUnicode_AsWideChar"		); 
		(FARPROC&)pfn_PyUnicode_AsUTF8AndSize	= GetProcAddress(hModule, "PyUnicode_AsUTF8AndSize"		); 
		(FARPROC&)pfn_PyObject_Unicode			= GetProcAddress(hModule, "PyObject_Str"				); 
#else
		(FARPROC&)pfn_PyString_AsStringAndSize	= GetProcAddress(hModule, "PyString_AsStringAndSize"	); 
		(FARPROC&)pfn_PyUnicode_GetSize			= GetProcAddress(hModule, "PyUnicodeUCS2_GetSize"		); 
		(FARPROC&)pfn_PyUnicode_AsWideChar	 	= GetProcAddress(hModule, "PyUnicodeUCS2_AsWideChar"	); 
		(FARPROC&)pfn_PyUnicode_AsUTF8String	= GetProcAddress(hModule, "PyUnicodeUCS2_AsUTF8String"	); 
		(FARPROC&)pfn_PyObject_Unicode			= GetProcAddress(hModule, "PyObject_Unicode"			); 
#endif 
	}
    // �������� ��������� �� ������
    public: virtual std::string message(PyObject* status) const; 

    // �������� �������������� ������ ������
    public: void trace(PyObject* type, PyObject* value, PyObject* traceback) const; 

	///////////////////////////////////////////////////////////////////////////////
	// ������ ������������� ������� 
	///////////////////////////////////////////////////////////////////////////////
	private: void (*pfn__Py_Dealloc)(PyObject* obj); 
	public: class PyDecrementor PyDecrementor() const 
	{
		// ������ ������������� ������� 
		return class PyDecrementor(pfn__Py_Dealloc); 
	}
	///////////////////////////////////////////////////////////////////////////////
	// ���������� �������� 
	///////////////////////////////////////////////////////////////////////////////

	// ������� ������� ������
	private: PyObject* (*pfn_PyErr_Occurred)(); 
	public: PyObject* PyErr_Occurred() const { return (*pfn_PyErr_Occurred)(); }

    // �������� ��������� ������
	private: void (*pfn_PyErr_Fetch)(PyObject**, PyObject**, PyObject**);
    public: void PyErr_Fetch(PyObject** ptype, PyObject** pvalue, PyObject** ptraceback) const
	{
		// �������� ��������� ������
		(*pfn_PyErr_Fetch)(ptype, pvalue, ptraceback); 
	} 
    // ���������� ��������� ������
	private: void (*pfn_PyErr_Restore)(PyObject*, PyObject*, PyObject*);
    public: void PyErr_Restore(PyObject* type, PyObject* value, PyObject* traceback) const
	{
		// ���������� ��������� ������
		(*pfn_PyErr_Restore)(type, value, traceback); 
	} 
	///////////////////////////////////////////////////////////////////////////////
	// ���������� �������� (����� String - ��� String ��� Python2 � Unicode ��� Python3)
	///////////////////////////////////////////////////////////////////////////////
	private: int (*pfn_PyString_AsStringAndSize)(PyObject*, char**, Py_ssize_t*);
	public: std::string PyString_AsUTF8String(PyObject* obj) const; 

	private: const char* (*pfn_PyUnicode_AsUTF8AndSize)(PyObject*, Py_ssize_t*); 
	private: PyObject*   (*pfn_PyUnicode_AsUTF8String )(PyObject*); 
	public: std::string PyUnicode_AsUTF8String(PyObject* obj) const; 

	private: Py_ssize_t (*pfn_PyUnicode_GetSize   )(PyObject*); 
	private: Py_ssize_t (*pfn_PyUnicode_AsWideChar)(PyObject*, wchar_t*, Py_ssize_t); 
	public: std::wstring PyUnicode_AsWideString(PyObject* obj) const; 

	////////////////////////////////////////////////////////////////
	// ��������� ������������� �������
	////////////////////////////////////////////////////////////////
	private: PyObject* (*pfn_PyObject_Unicode)(PyObject*); 
	public: std::string  PyObject_AsUTF8String(PyObject* obj) const; 
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
// ������� ������� ������
inline bool is_python_error(const python_error& error) { return error.value() != 0; }

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
    // �������� �������������� ���������� �� ������
    public: virtual void trace() const { if (value()) return; 

		// ��������� �������������� ����
		const python_error_category& category = 
			(const python_error_category&)code().category(); 

		// �������� �������������� ���������� �� ������
		category.trace(_type, _value, _traceback); 
	} 
    // ��������� ����������
    public: virtual void raise() const { trace(); 

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
inline std::string python_error_category::PyString_AsUTF8String(PyObject* obj) const
{
#if (PY_MAJOR_VERSION >= 3)
	// ������� ��������� ����������
	return PyUnicode_AsUTF8String(obj); 
#else 
	// ���������������� ���������� 
	char* buffer = nullptr; Py_ssize_t length = 0; 
		
	// ������� ������
	if ((*pfn_PyString_AsStringAndSize)(obj, &buffer, &length) < 0) 
	{ 
		// ��� ������ ��������� ����������
		AE_CHECK_PYTHON(*this); 
	}
	// ������� ������
	return std::string(buffer, length); 
#endif 
} 

inline std::string python_error_category::PyUnicode_AsUTF8String(PyObject* obj) const
{
#if (PY_MAJOR_VERSION >= 3)
	// ���������������� ���������� 
	const char* buffer = nullptr; Py_ssize_t length = 0; 
		
	// ������� ������
	buffer = (*pfn_PyUnicode_AsUTF8AndSize)(obj, &length); 

	// ��� ������ ��������� ����������
	if (!buffer) AE_CHECK_PYTHON(*this); 

	// ������� ������
	return std::string(buffer, length); 
#else 
	// ��������� �������������� ���������
	PyObject* str = (*pfn_PyUnicode_AsUTF8String)(obj); 
	
	// ��������� ���������� ������
	if (!str) { AE_CHECK_PYTHON(*this); } 

	// ������� ��������� ����������
	std::string value = PyString_AsUTF8String(str); 

	// ��������� ������� ������ �������
	PyDecrementor().operator()(str); return value; 
#endif 
} 

inline std::wstring python_error_category::PyUnicode_AsWideString(PyObject* obj) const
{
	// ���������� ������ ������
	Py_ssize_t length = (*pfn_PyUnicode_GetSize)(obj); 

	// ��������� ������������ ������
	if (length < 0) { AE_CHECK_PYTHON(*this); } std::wstring buffer(length, 0);

	// ������� ������
	length = (*pfn_PyUnicode_AsWideChar)(obj, &buffer[0], length); 

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
	PyDecrementor().operator()(unicodeObj); return value; 
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
	PyDecrementor().operator()(unicodeObj); return value; 
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
