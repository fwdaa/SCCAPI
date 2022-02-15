#pragma once
#include <locale>
#include <iterator>

////////////////////////////////////////////////////////////////
// �������������� Unicode
////////////////////////////////////////////////////////////////
inline std::wstring to_unicode(const char* message, size_t cch = -1)
{
    // ���������� ������ ������
	if (cch == (size_t)-1) { cch = strlen(message); } std::locale locale(""); 

	// ������� ������ �������������� �����
	typedef std::codecvt<wchar_t, char, mbstate_t> facet;

	// ������� ����������� ������������ �������
	const facet& codecvt = std::use_facet<facet>(locale); 

    // ������� ������������ �����
    std::wstring buffer(8, 0); const char* first = message; std::wstring str;

    // ��� ���� ������ ���������
    for (mbstate_t state = mbstate_t(); first != message + cch; ) 
    {
        // ������� ����� ������
        wchar_t* dest = &buffer[0]; wchar_t* next = dest;

        // ������������� ����� ������
        switch (codecvt.in(state, first, message + cch, first, dest, dest + buffer.size(), next)) 
        {
        // ��� ������������� ��������������
        case std::codecvt_base::noconv:
        {
            // ��� ���� ������ ���������
            for (; first != message + cch; ++first) 
            {
                // ��������� ������������ ����������� �����
                str.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*first)));
            }
            break;
        }
        // ��� ��������� ��������������
        case std::codecvt_base::partial: case std::codecvt_base::ok:
        {
            // ��� ���������� �������������� � ������������ ������
            if (dest == next && buffer.size() == 16) 
            {
                // ��������� ����������
                throw std::range_error("bad conversion");
            }
            // ��������� ������ ������
            if (dest == next) buffer.append(8, 0);
            else {
                // ��������� ��������������� �������
                str.append(dest, static_cast<size_t>(next - dest));
            }
            break;
        }
        // ���������� ����������� ������
        default: throw std::range_error("bad conversion");
        }
    }
    return str;
}

inline std::string from_unicode(const wchar_t* message, size_t cch = -1)
{
    // ���������� ������ ������
	if (cch == (size_t)-1) { cch = wcslen(message); } std::locale locale("");

	// ������� ������ �������������� �����
	typedef std::codecvt<wchar_t, char, mbstate_t> facet;

	// ������� ����������� ������������ �������
	const facet& codecvt = std::use_facet<facet>(locale); 

    // ������� ������������ �����
    std::string buffer(8, 0); const wchar_t* first = message; std::string str;

    // ��� ���� ��������
    for (mbstate_t state = mbstate_t(); first != message + cch; ) 
    {
        // ������� ����� ������
        char* dest = &buffer[0]; char* next = dest;

        // ������������ ����� ������
        switch (codecvt.out(state, first, message + cch, first, dest, dest + buffer.size(), next)) 
        {
        // ��� ������������� ��������������
        case std::codecvt_base::noconv:
        {
            // ��� ���� ��������
            for (; first != message + cch; ++first) 
            {
                // ��������� ���������� ��������������
                str.push_back(static_cast<char>(static_cast<unsigned char>(*first)));
            }
            break;
        }
        // ��� ��������� ��������������
        case std::codecvt_base::partial: case std::codecvt_base::ok:
        {
            // ��� ���������� �������������� � ������������ ������
            if (dest == next && buffer.size() == 16) 
            {
                // ��������� ����������
                throw std::range_error("bad conversion");
            }
            // ��������� ������ ������
            if (dest == next) buffer.append(8, 0);
            else {
                // ��������� �������������� �����
                str.append(dest, static_cast<size_t>(next - dest));
            }
			break; 
        }
        // ���������� ����������� ������
        default: throw std::range_error("bad conversion");
        }
    }
    return str;
}

////////////////////////////////////////////////////////////////
// �������������� UTF-8
////////////////////////////////////////////////////////////////
#if defined _WIN32
inline std::string to_utf8(const wchar_t* wsz, size_t cch = -1) 
{
	// ���������� ������ ������
	if (cch == (size_t)(-1)) cch = wcslen(wsz); 
	
	// ��������� ������� ������
	if (cch == 0) return std::string(); 

	// ���������� ��������� ������ ������
	int cb = ::WideCharToMultiByte(
		CP_UTF8, 0, wsz, (int)cch, nullptr, 0, nullptr, nullptr
	); 
	// ��������� ���������� ������
	if (cb == 0) throw std::range_error("bad conversion");

	// �������� ����� ���������� �������
	std::string str(cb, 0); 

	// ��������� �������������� ���������
	cb = ::WideCharToMultiByte(
		CP_UTF8, 0, wsz, (int)cch, &str[0], cb, nullptr, nullptr
	); 
	// ��������� ���������� ������
	if (cb == 0) throw std::range_error("bad conversion");

	// ��������������� ������ ������
	str.resize(cb); return str; 
}

inline std::wstring from_utf8(const char* sz, size_t cb = -1)
{
	// ���������� ������ ������
	if (cb == (size_t)(-1)) cb = strlen(sz); 
	
	// ��������� ������� ������
	if (cb == 0) return std::wstring(); 

	// ���������� ��������� ������ ������
	int cch = ::MultiByteToWideChar(CP_UTF8, 0, sz, (int)cb, 0, 0); 

	// ��������� ���������� ������
	if (cch == 0) throw std::range_error("bad conversion");

	// �������� ����� ���������� �������
	std::wstring wstr(cch, 0); 

	// ��������� �������������� ���������
	cch = ::MultiByteToWideChar(CP_UTF8, 0, sz, (int)cb, &wstr[0], cch); 

	// ��������� ���������� ������
	if (cch == 0) throw std::range_error("bad conversion");

	// ��������������� ������ ������
	wstr.resize(cch); return wstr; 
}
#else
#include <codecvt>

inline std::string to_utf8(const wchar_t* wsz, size_t cch = -1) 
{
	// ���������� ������ ������
	if (cch == (size_t)(-1)) cch = wcslen(wsz); 
	
	// ��������� ������� ������
	if (cch == 0) return std::string(); 

	// ������� ������ �������������� �����
	typedef std::codecvt_utf8<wchar_t> codecvt_type;

	// ������� ������ �������������� �����
	codecvt_type codecvt(1);

	// ������� ������ �������������
	std::wstring_convert<codecvt_type> converter(&codecvt);

	// ��������� ��������������
	return converter.to_bytes(wsz, wsz + cch);
}

inline std::wstring from_utf8(const char* sz, size_t cb = -1)
{
	// ���������� ������ ������
	if (cb == (size_t)(-1)) cb = strlen(sz); 
	
	// ��������� ������� ������
	if (cb == 0) return std::wstring(); 

	// ������� ������ �������������� �����
	typedef std::codecvt_utf8<wchar_t> codecvt_type;

	// ������� ������ �������������� �����
	codecvt_type codecvt(1);

	// ������� ������ �������������
	std::wstring_convert<codecvt_type> converter(&codecvt);

	// ��������� ��������������
	return converter.from_bytes(sz, sz + cb);
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������� �������� ��� ������������� ��������� UTF16-BE
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER || WCHAR_MAX == 0xFFFF
inline std::string to_utf16be(const wchar_t* wstr, size_t length = -1)
{
	// �������� ������������ �����
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // ��� ���� �������� ������
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// ��������� ���������� ������
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// ������������� ��������� �������
		*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
		*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF);
	}		
	return str; 
}
inline std::wstring from_utf16be(const char* str, size_t length = -1)
{
	// �������� ������������ �����
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// ��� ���� �������� ������
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// ������� ��������� ����� �������
		wchar_t code = (str[i] << 8) | str[i + 1];

		// ��������� ���������� ������
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// ���������� ������ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// ���������� ������������ ������
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// ���������� ������������ ������
			*p++ = 0xFFFD; if (0xDC00 <= code && code < 0xE000) i += 2;  
		}
	}
	// ������� ��������������� ������
	if ((length % 2) != 0) *p++ = 0xFFFD; return wstr; 	
}
inline std::string to_utf16le(const wchar_t* wstr, size_t length = -1)
{
	// �������� ������������ �����
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // ��� ���� �������� ������
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// ��������� ���������� ������
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// ������������� ��������� �������
		*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
		*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF);
	}		
	return str; 
}
inline std::wstring from_utf16le(const char* str, size_t length = -1)
{
	// �������� ������������ �����
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// ��� ���� �������� ������
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// ������� ��������� ����� �������
		wchar_t code = (str[i + 1] << 8) | str[i];

		// ��������� ���������� ������
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// ���������� ������ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// ���������� ������������ ������
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// ���������� ������������ ������
			*p++ = 0xFFFD; if (0xDC00 <= code && code < 0xE000) i += 2;  
		}
	}
	// ������� ��������������� ������
	if ((length % 2) != 0) *p++ = 0xFFFD; return wstr; 	
}
#else 
inline std::string to_utf16be(const wchar_t* wstr, std::size_t length = -1)
{
	// �������� ������������ �����
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // ��� ���� �������� ������
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// ��������� ���������� ������
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// ��� ������� BMP
		if (wstr[i] < 0x10000) 
		{ 
			// ������������ ������ BMP
			*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
			*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
		}
		else { 
			// ������� ��������� ����� �������
			wchar_t code = 0xD800 + ((wstr[i] - 0x10000) >>   10); 
			wchar_t next = 0xDC00 + ((wstr[i] - 0x10000) & 0x3FF); 

			// ��������� ��������� ����� �������
			*p++ = (char)(unsigned char)((code >> 8) & 0xFF); 
			*p++ = (char)(unsigned char)((code >> 0) & 0xFF); 
			*p++ = (char)(unsigned char)((next >> 8) & 0xFF); 
			*p++ = (char)(unsigned char)((next >> 0) & 0xFF);
		}
	}		
	return str; 
}
inline std::wstring from_utf16be(const char* str, size_t length = -1)
{
	// �������� ������������ �����
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// ��� ���� �������� ������
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// ������� ��������� ����� �������
		wchar_t code = (str[i] << 8) | str[i + 1];

		// ��������� ���������� ������
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// ���������� ������ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// ���������� ������������ ������
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// ������� ������ ����� �������
			wchar_t next = (str[i + 2] << 8) | str[i + 3];

			// ���������� ������������ ������
			if (next < 0xDC00 || 0xE000 <= next) *p++ = 0xFFFD; 
				
			// ���������� ������ ��� BMP
			else { *p++ = 0x10000 + (code - 0xD800) * 0x0400 + (next - 0xDC00); i += 2; }
		}
	}
	// ������� ��������������� ������
	if ((length % 2) != 0) { *p++ = 0xFFFD; } return wstr; 	
}
inline std::string to_utf16le(const wchar_t* wstr, size_t length = -1)
{
	// �������� ������������ �����
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // ��� ���� �������� ������
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// ��������� ���������� ������
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// ��� ������� BMP
		if (wstr[i] < 0x10000) 
		{ 
			// ������������ ������ BMP
			*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
			*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
		}
		else { 
			// ������� ��������� ����� �������
			wchar_t code = 0xD800 + ((wstr[i] - 0x10000) >>   10); 
			wchar_t next = 0xDC00 + ((wstr[i] - 0x10000) & 0x3FF); 

			// ��������� ��������� ����� �������
			*p++ = (char)(unsigned char)((code >> 0) & 0xFF); 
			*p++ = (char)(unsigned char)((code >> 8) & 0xFF); 
			*p++ = (char)(unsigned char)((next >> 0) & 0xFF); 
			*p++ = (char)(unsigned char)((next >> 8) & 0xFF);
		}
	}		
	return str; 
}
inline std::wstring from_utf16le(const char* str, size_t length = -1)
{
	// �������� ������������ �����
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// ��� ���� �������� ������
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// ������� ��������� ����� �������
		wchar_t code = (str[i + 1] << 8) | str[i];

		// ��������� ���������� ������
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// ���������� ������ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// ���������� ������������ ������
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// ������� ������ ����� �������
			wchar_t next = (str[i + 3] << 8) | str[i + 2];

			// ���������� ������������ ������
			if (next < 0xDC00 || 0xE000 <= next) *p++ = 0xFFFD; 
				
			// ���������� ������ ��� BMP
			else { *p++ = 0x10000 + (code - 0xD800) * 0x0400 + (next - 0xDC00); i += 2; }
		}
	}
	// ������� ��������������� ������
	if ((length % 2) != 0) { *p++ = 0xFFFD; } return wstr; 	
}
#endif 
