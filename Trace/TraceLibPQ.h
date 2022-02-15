#pragma once

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_category : public trace::error_category<PGresult*>
{
    // �������� ��������� �� ������
    public: virtual std::string message(PGresult* result) const 
    {
		// �������� ��������� �� ������ 
		std::string message = ::PQresultErrorMessage(result); 
		try { 
			// ��������� �������������� ���������
			std::wstring wmessage = from_utf8(message.c_str()); 

			// ��������� �������������� ���������
			return from_unicode(wmessage.c_str()); 
		}
		// ��� ������������� ������
		catch (const std::exception&) { return message; }
    }
};
inline const class libpq_category& libpq_category() 
{
    // ��������� ������ LIBPQ
    static class libpq_category libpq_category; return libpq_category; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������ LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_error : public trace::error_code<PGresult*>
{
    // �����������
    public: libpq_error(PGresult* result) 

		// ��������� ���������� ���������
		: trace::error_code<PGresult*>(result, libpq_category()) {}

    // ������������� �������� ������
    public: std::string name() const
    {
		// �������� ��� ���������
		ExecStatusType status = ::PQresultStatus(value());

		// �������� ��� ���������
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
        // ��������������� ��� ������
        char str[16]; trace::snprintf(str, sizeof(str), "%u", status); return str; 
	}
}; 
// ������� ������� ������
inline bool is_libpq_error(PGresult* result) 
{ 
	// �������� ��� ���������
	ExecStatusType status = ::PQresultStatus(result);

	// ��������� ���������� ������
	if (status == PGRES_BAD_RESPONSE) return true; 

	// ��������� ������� ������
	return (status == PGRES_NONFATAL_ERROR || status == PGRES_FATAL_ERROR);
}

///////////////////////////////////////////////////////////////////////////////
// ���������� LIBPQ
///////////////////////////////////////////////////////////////////////////////
class libpq_exception : public trace::exception<PGresult*>
{
    // �����������
    public: libpq_exception(PGresult* result, const char* szFile, int line)

        // ��������� ���������� ���������
        : trace::exception<PGresult*>(libpq_error(result), szFile, line) {}

    // ��������� ����������
    public: void raise() const { trace(); throw *this; }
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
inline void format_libpq(trace::pprintf print, void* context, int level, va_list& args)
{
	// ������� ��� ������
	libpq_error error(va_arg(args, PGresult*)); 

	// ���������� ��� ������
	std::string name = error.name(); 

	// ������� ��� ������
	(*print)(context, level, "%hs", name.c_str()); 
}
WPP_FORMAT_TABLE_EXTENSION(LIBPQ, format_libpq);

