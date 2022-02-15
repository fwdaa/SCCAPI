#pragma once

///////////////////////////////////////////////////////////////////////////////
// Категория ошибок LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_category : public trace::error_category<PGresult*>
{
    // получить сообщение об ошибке
    public: virtual std::string message(PGresult* result) const 
    {
		// получить сообщение об ошибке 
		std::string message = ::PQresultErrorMessage(result); 
		try { 
			// выполнить преобразование кодировки
			std::wstring wmessage = from_utf8(message.c_str()); 

			// выполнить преобразование кодировки
			return from_unicode(wmessage.c_str()); 
		}
		// при возникновении ошибки
		catch (const std::exception&) { return message; }
    }
};
inline const class libpq_category& libpq_category() 
{
    // категория ошибок LIBPQ
    static class libpq_category libpq_category; return libpq_category; 
}

///////////////////////////////////////////////////////////////////////////////
// Описание ошибки LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_error : public trace::error_code<PGresult*>
{
    // конструктор
    public: libpq_error(PGresult* result) 

		// сохранить переданные параметры
		: trace::error_code<PGresult*>(result, libpq_category()) {}

    // символическое описание ошибки
    public: std::string name() const
    {
		// получить код состояния
		ExecStatusType status = ::PQresultStatus(value());

		// получить код состояния
		switch (status)
		{
		case PGRES_EMPTY_QUERY		: return "PGRES_EMPTY_QUERY";
		case PGRES_COMMAND_OK		: return "PGRES_COMMAND_OK";
		case PGRES_TUPLES_OK		: return "PGRES_TUPLES_OK";
		case PGRES_COPY_OUT			: return "PGRES_COPY_OUT";
		case PGRES_COPY_IN			: return "PGRES_COPY_IN";
		case PGRES_BAD_RESPONSE		: return "PGRES_BAD_RESPONSE"; 
		case PGRES_NONFATAL_ERROR	: return "PGRES_NONFATAL_ERROR";
		case PGRES_FATAL_ERROR		: return "PGRES_FATAL_ERROR";
		case PGRES_COPY_BOTH		: return "PGRES_COPY_BOTH";
		case PGRES_SINGLE_TUPLE		: return "PGRES_SINGLE_TUPLE";
		}
        // отформатировать код ошибки
        char str[16]; trace::snprintf(str, sizeof(str), "%u", status); return str; 
	}
}; 
// признак наличия ошибки
inline bool is_libpq_error(PGresult* result) 
{ 
	// получить код состояния
	ExecStatusType status = ::PQresultStatus(result);

	// проверить отсутствие ошибок
	if (status == PGRES_BAD_RESPONSE) return true; 

	// проверить наличие ошибок
	return (status == PGRES_NONFATAL_ERROR || status == PGRES_FATAL_ERROR);
}

///////////////////////////////////////////////////////////////////////////////
// Исключение LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_exception : public trace::exception<PGresult*>
{
    // конструктор
    public: libpq_exception(PGresult* result, const char* szFile, int line)

        // сохранить переданные параметры
        : trace::exception<PGresult*>(libpq_error(result), szFile, line) {}

    // выбросить исключение
    public: void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// Добавление способа форматирования
///////////////////////////////////////////////////////////////////////////////
inline void format_libpq(trace::pprintf print, void* context, int level, va_list& args)
{
	// извлечь код ошибки
	libpq_error error(va_arg(args, PGresult*)); 

	// определить имя ошибки
	std::string name = error.name(); 

	// вывести имя ошибки
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(LIBPQ, format_libpq);

