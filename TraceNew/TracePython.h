#pragma once

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок Python
///////////////////////////////////////////////////////////////////////////////
class python_error_category : public trace::error_category<PyObject*>
{
	// признак наличия ошибки
	private: PyObject* (*pfn_PyErr_Occurred)(); 

	// функции управления исключениями
	private: void (*pfn_PyErr_Fetch  )(PyObject**, PyObject**, PyObject**);
	private: void (*pfn_PyErr_Restore)(PyObject* , PyObject* , PyObject* );

	// размер строк Python
	private: Py_ssize_t (*pfn_PyString_Size        )(PyObject* obj); 
	private: Py_ssize_t (*pfn_PyUnicodeUCS2_GetSize)(PyObject* obj); 

	// строковое представление строк Python 
	private: int        (*pfn_PyString_AsStringAndSize)(PyObject*, char**, Py_ssize_t*);
	private: Py_ssize_t (*pfn_PyUnicodeUCS2_AsWideChar)(PyObject*, wchar_t*, Py_ssize_t); 

	// преобразование кодировки строки
	private: PyObject* (*pfn_PyUnicodeUCS2_AsUTF8String)(PyObject*); 

	// строковое представление объекта
	private: PyObject* (*pfn_PyObject_Unicode)(PyObject*); 

	// конструктор
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
    // получить сообщение об ошибке
    public: virtual std::string message(PyObject* status) const; 

    // получить дополнительное данные ошибки
    public: void trace(PyObject* type, PyObject* value, PyObject* traceback) const; 

	///////////////////////////////////////////////////////////////////////////////
	// Управление ошибками 
	///////////////////////////////////////////////////////////////////////////////

	// признак наличия ошибки
	public: PyObject* PyErr_Occurred() const { return (*pfn_PyErr_Occurred)(); }

    // получить состояние ошибки
    public: void PyErr_Fetch(PyObject** ptype, PyObject** pvalue, PyObject** ptraceback) const
	{
		// пулучить состояние ошибки
		(*pfn_PyErr_Fetch)(ptype, pvalue, ptraceback); 
	} 
    // установить состояние ошибки
    public: void PyErr_Restore(PyObject* type, PyObject* value, PyObject* traceback) const
	{
		// установить состояние ошибки
		(*pfn_PyErr_Restore)(type, value, traceback); 
	} 
	///////////////////////////////////////////////////////////////////////////////
	// Управление строками
	///////////////////////////////////////////////////////////////////////////////
	public: Py_ssize_t PyString_Size (PyObject* obj) const; 
	public: Py_ssize_t PyUnicode_Size(PyObject* obj) const; 

	public: std::string  PyString_AsString     (PyObject* obj) const; 
	public: std::string  PyUnicode_AsUTF8String(PyObject* obj) const; 
	public: std::wstring PyUnicode_AsWideString(PyObject* obj) const; 

	////////////////////////////////////////////////////////////////
	// Строковое представление объекта
	////////////////////////////////////////////////////////////////
	public: std::string PyObject_AsUTF8String (PyObject* obj) const; 
	public: std::wstring PyObject_AsWideString(PyObject* obj) const;
};

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки Python
///////////////////////////////////////////////////////////////////////////////
class python_error : public trace::error_code<PyObject*>
{
    // конструктор
    public: python_error(const python_error_category& category, PyObject* status) 
        
        // сохранить переданные параметры
        : trace::error_code<PyObject*>(status, category) {}

    // конструктор
    public: python_error(const python_error_category& category) 
        
        // сохранить переданные параметры
        : trace::error_code<PyObject*>(category.PyErr_Occurred(), category) {}

	// признак наличия ошибки
	public: operator const void* () const 
	{ 
		// признак наличия ошибки
		return (value() != 0) ? this : (const void*)0; 
	}
    // символическое описание ошибки
    public: std::string name() const
    {	
        // отформатировать код ошибки
        char str[32]; sprintf_s(str, sizeof(str), "%p", value()); return str; 
	}
}; 
// получить сообщение об ошибке
inline std::string python_error_category::message(PyObject* status) const
{
	// отформатировать код ошибки
    char str[32]; sprintf_s(str, sizeof(str), "%p", status); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// Исключение Python
///////////////////////////////////////////////////////////////////////////////
class python_exception : public trace::exception<PyObject*>
{	
    // тип базового класса
    private: typedef trace::exception<PyObject*> base_type; 

	// описание исключения Python
	private: PyObject* _type; PyObject* _value; PyObject* _traceback; 

    // конструктор
    public: python_exception(const python_error& error,	const char* szFile, int line)

        // сохранить переданные параметры
        : base_type(error, szFile, line), _type(nullptr), _value(nullptr), _traceback(nullptr)
	{
		// выполнить преобразование типа
		const python_error_category& category = 
			(const python_error_category&)error.category(); 

		// получить описание исключения
		if (value()) category.PyErr_Fetch(&_type, &_value, &_traceback);
	}
	// конструктор копирования
	public: python_exception(const python_exception& e) : base_type(code(), e.file(), e.line()) 
	{
		// увеличить счетчики ссылок
		_type      = e._type     ; if (_type     ) Py_XINCREF(_type     ); 
		_value     = e._value    ; if (_value    ) Py_XINCREF(_value    ); 
		_traceback = e._traceback; if (_traceback) Py_XINCREF(_traceback);
	}
	// деструктор
	public: virtual ~python_exception() 
	{
		// уменьшить счетчики ссылок
		if (_type     ) Py_XDECREF(_type     ); 
		if (_value    ) Py_XDECREF(_value    ); 
		if (_traceback) Py_XDECREF(_traceback);
	}
    // получить дополнительную информацию об ошибке
    public: virtual void trace() const { if (value()) return; 

		// получить дополнительную информацию об ошибке
		((const python_error_category&)code().category()).trace(_type, _value, _traceback); 
	} 
    // выбросить исключение
    public: virtual __noreturn void raise() const { trace(); 

		// выполнить преобразование типа
		const python_error_category& category = 
			(const python_error_category&)code().category(); 

		// установить исключение Python
		category.PyErr_Restore(_type, _value, _traceback); throw *this;  
	}
};

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#define WPP_USER_MSG_GUID (1A453A5C, 07A1, 4652, 88A2, BA51F837D2E4)
#include "TracePython.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Управление строками Python
///////////////////////////////////////////////////////////////////////////////
inline Py_ssize_t python_error_category::PyString_Size(PyObject* obj) const
{
	// определить размер строки
	Py_ssize_t length = (*pfn_PyString_Size)(obj); 

	// проверить корректность вызова
	if (length < 0) { AE_CHECK_PYTHON(*this); } return length; 
} 

inline Py_ssize_t python_error_category::PyUnicode_Size(PyObject* obj) const
{
	// определить размер строки
	Py_ssize_t length = (*pfn_PyUnicodeUCS2_GetSize)(obj); 

	// проверить корректность вызова
	if (length < 0) { AE_CHECK_PYTHON(*this); } return length; 
} 

inline std::string python_error_category::PyString_AsString(PyObject* obj) const
{
	char* buffer; Py_ssize_t length; 
		
	// извлечь строку
	if ((*pfn_PyString_AsStringAndSize)(obj, &buffer, &length) < 0) 
	{ 
		// при ошибке выбросить исключение
		AE_CHECK_PYTHON(*this); 
	}
	// вернуть строку
	return std::string(buffer, length); 
} 

inline std::string python_error_category::PyUnicode_AsUTF8String(PyObject* obj) const
{
	// выполнить преобразование кодировки
	PyObject* str = (*pfn_PyUnicodeUCS2_AsUTF8String)(obj); 
	
	// проверить отсутствие ошибок
	if (!str) { AE_CHECK_PYTHON(*this); } 

	// извлечь строковое содержимое
	std::string value = PyString_AsString(str); 

	// уменьшить счетчик ссылок объекта
	Py_DECREF(str); return value; 
} 

inline std::wstring python_error_category::PyUnicode_AsWideString(PyObject* obj) const
{
	// определить размер строки
	Py_ssize_t length = PyUnicode_Size(obj); std::wstring buffer(length, 0);

	// извлечь строку
	length = (*pfn_PyUnicodeUCS2_AsWideChar)(obj, &buffer[0], length); 

	// проверить отсутствие ошибок
	if (length < 0) { AE_CHECK_PYTHON(*this); } 

	// вернуть строку
	buffer.resize(length); return buffer; 
} 

////////////////////////////////////////////////////////////////
// Строковое представление объекта Python
////////////////////////////////////////////////////////////////
inline std::string python_error_category::PyObject_AsUTF8String(PyObject* obj) const
{
	// получить строковое содержимое
	PyObject* unicodeObj = (*pfn_PyObject_Unicode)(obj); 
	
	// проверить отсутствие ошибок
	if (!unicodeObj) { AE_CHECK_PYTHON(*this); } 

	// извлечь строковое содержимое
	std::string value = PyUnicode_AsUTF8String(unicodeObj); 

	// уменьшить счетчик ссылок объекта
	Py_DECREF(unicodeObj); return value; 
}

inline std::wstring python_error_category::PyObject_AsWideString(PyObject* obj) const
{
	// получить строковое содержимое
	PyObject* unicodeObj = (*pfn_PyObject_Unicode)(obj); 
	
	// проверить отсутствие ошибок
	if (!unicodeObj) { AE_CHECK_PYTHON(*this); } 

	// извлечь строковое содержимое
	std::wstring value = PyUnicode_AsWideString(unicodeObj); 

	// уменьшить счетчик ссылок объекта
	Py_DECREF(unicodeObj); return value; 
}

///////////////////////////////////////////////////////////////////////////////
// Дополнительная информация об ошибке
///////////////////////////////////////////////////////////////////////////////
inline void python_error_category::trace(PyObject* type, PyObject* value, PyObject*) const
{
	// добавить описание типа
	std::wstring message; if (type) try { message = PyObject_AsWideString(type); }

	// проверить отсутствие ошибок
	catch (const std::exception&) {} if (value) 
	try { 
		// получить описание объекта
		std::wstring wstr = PyObject_AsWideString(value); 

		// добавить описание объекта
		if (!message.empty()) message += L" : "; message += wstr;
	}
	// проверить отсутствие ошибок
	catch (const std::exception&) {} 
		
	// вывести описание ошибки
	ATRACE(TRACE_LEVEL_ERROR, "%ls", message.c_str()); 
}

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_python(trace::pprintf print, void* context, int level, va_list& args)
{
#if defined _MSC_VER && _MSC_VER >= 1600 

	// извлечь код ошибки
	const python_error& error = va_arg(args, python_error); 
#else 
	// извлечь категорию ошибки
	const python_error_category* category = 
		(const python_error_category*)va_arg(args, const void*); 
	
	// создать код ошибки
	python_error error(*category, va_arg(args, PyObject*));
#endif 
	// определить имя ошибки
	std::string name = error.name(); 

	// вывести имя ошибки
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(PYTHON, format_python);

///////////////////////////////////////////////////////////////////////////////
// Сбросить идентификатор служебных сообщений
///////////////////////////////////////////////////////////////////////////////
#if defined WPP_CONTROL_GUIDS
#undef WPP_USER_MSG_GUID
#endif 
