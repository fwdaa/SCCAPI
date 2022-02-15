#pragma once
#include <locale>
#include <iterator>

////////////////////////////////////////////////////////////////
// Преобразования Unicode
////////////////////////////////////////////////////////////////
inline std::wstring to_unicode(const char* message, size_t cch = -1)
{
    // определить размер строки
	if (cch == (size_t)-1) { cch = strlen(message); } std::locale locale(""); 

	// указать способ преобразования строк
	typedef std::codecvt<wchar_t, char, mbstate_t> facet;

	// указать локализацию операционной системы
	const facet& codecvt = std::use_facet<facet>(locale); 

    // создать динамический буфер
    std::wstring buffer(8, 0); const char* first = message; std::wstring str;

    // для всех байтов кодировки
    for (mbstate_t state = mbstate_t(); first != message + cch; ) 
    {
        // указать адрес буфера
        wchar_t* dest = &buffer[0]; wchar_t* next = dest;

        // раскодировать часть данных
        switch (codecvt.in(state, first, message + cch, first, dest, dest + buffer.size(), next)) 
        {
        // при тождественном преобразовании
        case std::codecvt_base::noconv:
        {
            // для всех байтов кодировки
            for (; first != message + cch; ++first) 
            {
                // выполнить интегральное продвижение байта
                str.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*first)));
            }
            break;
        }
        // при возможном преобразовании
        case std::codecvt_base::partial: case std::codecvt_base::ok:
        {
            // при отсутствии преобразования и максимальном буфере
            if (dest == next && buffer.size() == 16) 
            {
                // выбросить исключение
                throw std::range_error("bad conversion");
            }
            // увеличить размер буфера
            if (dest == next) buffer.append(8, 0);
            else {
                // сохранить преобразованные символы
                str.append(dest, static_cast<size_t>(next - dest));
            }
            break;
        }
        // обработать неожидаемую ошибку
        default: throw std::range_error("bad conversion");
        }
    }
    return str;
}

inline std::string from_unicode(const wchar_t* message, size_t cch = -1)
{
    // определить размер строки
	if (cch == (size_t)-1) { cch = wcslen(message); } std::locale locale("");

	// указать способ преобразования строк
	typedef std::codecvt<wchar_t, char, mbstate_t> facet;

	// указать локализацию операционной системы
	const facet& codecvt = std::use_facet<facet>(locale); 

    // создать динамический буфер
    std::string buffer(8, 0); const wchar_t* first = message; std::string str;

    // для всех символов
    for (mbstate_t state = mbstate_t(); first != message + cch; ) 
    {
        // указать адрес буфера
        char* dest = &buffer[0]; char* next = dest;

        // закодировать часть строки
        switch (codecvt.out(state, first, message + cch, first, dest, dest + buffer.size(), next)) 
        {
        // при тождественном преобразовании
        case std::codecvt_base::noconv:
        {
            // для всех символов
            for (; first != message + cch; ++first) 
            {
                // выполнить понижающее преобразование
                str.push_back(static_cast<char>(static_cast<unsigned char>(*first)));
            }
            break;
        }
        // при возможном преобразовании
        case std::codecvt_base::partial: case std::codecvt_base::ok:
        {
            // при отсутствии преобразования и максимальном буфере
            if (dest == next && buffer.size() == 16) 
            {
                // выбросить исключение
                throw std::range_error("bad conversion");
            }
            // увеличить размер буфера
            if (dest == next) buffer.append(8, 0);
            else {
                // сохранить закодированные байты
                str.append(dest, static_cast<size_t>(next - dest));
            }
			break; 
        }
        // обработать неожидаемую ошибку
        default: throw std::range_error("bad conversion");
        }
    }
    return str;
}

////////////////////////////////////////////////////////////////
// Преобразования UTF-8
////////////////////////////////////////////////////////////////
#if defined _WIN32
inline std::string to_utf8(const wchar_t* wsz, size_t cch = -1) 
{
	// определить размер строки
	if (cch == (size_t)(-1)) cch = wcslen(wsz); 
	
	// проверить наличие строки
	if (cch == 0) return std::string(); 

	// определить требуемый размер буфера
	int cb = ::WideCharToMultiByte(
		CP_UTF8, 0, wsz, (int)cch, nullptr, 0, nullptr, nullptr
	); 
	// проверить отсутствие ошибок
	if (cb == 0) throw std::range_error("bad conversion");

	// выделить буфер требуемого размера
	std::string str(cb, 0); 

	// выполнить преобразование кодировки
	cb = ::WideCharToMultiByte(
		CP_UTF8, 0, wsz, (int)cch, &str[0], cb, nullptr, nullptr
	); 
	// проверить отсутствие ошибок
	if (cb == 0) throw std::range_error("bad conversion");

	// скорректировать размер буфера
	str.resize(cb); return str; 
}

inline std::wstring from_utf8(const char* sz, size_t cb = -1)
{
	// определить размер строки
	if (cb == (size_t)(-1)) cb = strlen(sz); 
	
	// проверить наличие строки
	if (cb == 0) return std::wstring(); 

	// определить требуемый размер буфера
	int cch = ::MultiByteToWideChar(CP_UTF8, 0, sz, (int)cb, 0, 0); 

	// проверить отсутствие ошибок
	if (cch == 0) throw std::range_error("bad conversion");

	// выделить буфер требуемого размера
	std::wstring wstr(cch, 0); 

	// выполнить преобразование кодировки
	cch = ::MultiByteToWideChar(CP_UTF8, 0, sz, (int)cb, &wstr[0], cch); 

	// проверить отсутствие ошибок
	if (cch == 0) throw std::range_error("bad conversion");

	// скорректировать размер буфера
	wstr.resize(cch); return wstr; 
}
#else
#include <codecvt>

inline std::string to_utf8(const wchar_t* wsz, size_t cch = -1) 
{
	// определить размер строки
	if (cch == (size_t)(-1)) cch = wcslen(wsz); 
	
	// проверить наличие строки
	if (cch == 0) return std::string(); 

	// указать способ преобразования строк
	typedef std::codecvt_utf8<wchar_t> codecvt_type;

	// указать способ преобразования строк
	codecvt_type codecvt(1);

	// создать способ преобразовния
	std::wstring_convert<codecvt_type> converter(&codecvt);

	// выполнить преобразование
	return converter.to_bytes(wsz, wsz + cch);
}

inline std::wstring from_utf8(const char* sz, size_t cb = -1)
{
	// определить размер строки
	if (cb == (size_t)(-1)) cb = strlen(sz); 
	
	// проверить наличие строки
	if (cb == 0) return std::wstring(); 

	// указать способ преобразования строк
	typedef std::codecvt_utf8<wchar_t> codecvt_type;

	// указать способ преобразования строк
	codecvt_type codecvt(1);

	// создать способ преобразовния
	std::wstring_convert<codecvt_type> converter(&codecvt);

	// выполнить преобразование
	return converter.from_bytes(sz, sz + cb);
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Преобразования наборов символов при использовании кодировки UTF16-BE
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER || WCHAR_MAX == 0xFFFF
inline std::string to_utf16be(const wchar_t* wstr, size_t length = -1)
{
	// выделить динамический буфер
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // для всех символов строки
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// проверить завершение строки
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// преобразовать кодировку символа
		*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
		*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF);
	}		
	return str; 
}
inline std::wstring from_utf16be(const char* str, size_t length = -1)
{
	// выделить динамический буфер
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// для всех символов строки
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// извлечь отдельную часть символа
		wchar_t code = (str[i] << 8) | str[i + 1];

		// проверить завершение строки
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// обработать символ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// обработать некорректный символ
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// обработать некорректный символ
			*p++ = 0xFFFD; if (0xDC00 <= code && code < 0xE000) i += 2;  
		}
	}
	// вернуть раскодированную строку
	if ((length % 2) != 0) *p++ = 0xFFFD; return wstr; 	
}
inline std::string to_utf16le(const wchar_t* wstr, size_t length = -1)
{
	// выделить динамический буфер
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // для всех символов строки
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// проверить завершение строки
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// преобразовать кодировку символа
		*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
		*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF);
	}		
	return str; 
}
inline std::wstring from_utf16le(const char* str, size_t length = -1)
{
	// выделить динамический буфер
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// для всех символов строки
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// извлечь отдельную часть символа
		wchar_t code = (str[i + 1] << 8) | str[i];

		// проверить завершение строки
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// обработать символ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// обработать некорректный символ
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// обработать некорректный символ
			*p++ = 0xFFFD; if (0xDC00 <= code && code < 0xE000) i += 2;  
		}
	}
	// вернуть раскодированную строку
	if ((length % 2) != 0) *p++ = 0xFFFD; return wstr; 	
}
#else 
inline std::string to_utf16be(const wchar_t* wstr, std::size_t length = -1)
{
	// выделить динамический буфер
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // для всех символов строки
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// проверить завершение строки
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// для символа BMP
		if (wstr[i] < 0x10000) 
		{ 
			// закодировать символ BMP
			*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
			*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
		}
		else { 
			// извлечь отдельные части символа
			wchar_t code = 0xD800 + ((wstr[i] - 0x10000) >>   10); 
			wchar_t next = 0xDC00 + ((wstr[i] - 0x10000) & 0x3FF); 

			// сохранить отдельные части символа
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
	// выделить динамический буфер
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// для всех символов строки
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// извлечь отдельную часть символа
		wchar_t code = (str[i] << 8) | str[i + 1];

		// проверить завершение строки
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// обработать символ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// обработать некорректный символ
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// извлечь вторую часть символа
			wchar_t next = (str[i + 2] << 8) | str[i + 3];

			// обработать некорректный символ
			if (next < 0xDC00 || 0xE000 <= next) *p++ = 0xFFFD; 
				
			// обработать символ вне BMP
			else { *p++ = 0x10000 + (code - 0xD800) * 0x0400 + (next - 0xDC00); i += 2; }
		}
	}
	// вернуть раскодированную строку
	if ((length % 2) != 0) { *p++ = 0xFFFD; } return wstr; 	
}
inline std::string to_utf16le(const wchar_t* wstr, size_t length = -1)
{
	// выделить динамический буфер
	std::string str; std::back_insert_iterator<std::string> p(str);  

    // для всех символов строки
    for (size_t i = 0; length == (size_t)(-1) || i < length; i++)
	{
		// проверить завершение строки
		if (wstr[i] == 0 && length == (size_t)(-1)) break;  

		// для символа BMP
		if (wstr[i] < 0x10000) 
		{ 
			// закодировать символ BMP
			*p++ = (char)(unsigned char)((wstr[i] >> 0) & 0xFF); 
			*p++ = (char)(unsigned char)((wstr[i] >> 8) & 0xFF); 
		}
		else { 
			// извлечь отдельные части символа
			wchar_t code = 0xD800 + ((wstr[i] - 0x10000) >>   10); 
			wchar_t next = 0xDC00 + ((wstr[i] - 0x10000) & 0x3FF); 

			// сохранить отдельные части символа
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
	// выделить динамический буфер
	std::wstring wstr; std::back_insert_iterator<std::wstring> p(wstr);  

	// для всех символов строки
	for (size_t i = 0; length == (size_t)(-1) || i + 1 < length; i += 2)
	{
		// извлечь отдельную часть символа
		wchar_t code = (str[i + 1] << 8) | str[i];

		// проверить завершение строки
		if (code == 0 && length == (size_t)(-1)) { length = i; break; } 

		// обработать символ BMP
		if (code < 0xD800 || 0xE000 <= code) *p++ = code; 

		// обработать некорректный символ
		else if ((0xDC00 <= code && code < 0xE000) || length < i + 4) *p++ = 0xFFFD; 
		else {
			// извлечь вторую часть символа
			wchar_t next = (str[i + 3] << 8) | str[i + 2];

			// обработать некорректный символ
			if (next < 0xDC00 || 0xE000 <= next) *p++ = 0xFFFD; 
				
			// обработать символ вне BMP
			else { *p++ = 0x10000 + (code - 0xD800) * 0x0400 + (next - 0xDC00); i += 2; }
		}
	}
	// вернуть раскодированную строку
	if ((length % 2) != 0) { *p++ = 0xFFFD; } return wstr; 	
}
#endif 
