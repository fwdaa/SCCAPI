#include "pch.h"
#include "registry.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "registry.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Получение и установка параметров в реестре
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::RegistryValueImpl::GetUInt32() const
{
	// проверить тип параметра
	DWORD type = GetType(); switch (type)
	{
	case REG_DWORD: { DWORD ulValue = 0; 

		// получить значение параметра
		GetValue(&ulValue, sizeof(ulValue)); return ulValue; 
	}
	case REG_DWORD_BIG_ENDIAN: { DWORD ulValue = 0; 

		// получить значение параметра
		GetValue(&ulValue, sizeof(ulValue)); 

		// изменить порядок байтов
		return ((((ulValue >> 24) & 0xFF) <<  0) | 
			    (((ulValue >> 16) & 0xFF) <<  8) |
			    (((ulValue >>  8) & 0xFF) << 16) | 
			    (((ulValue >>  0) & 0xFF) << 24)); 
	}}
	// при ошибке выбросить исключение
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return 0; 
}

DWORD64 Windows::RegistryValueImpl::GetUInt64() const
{
	// проверить тип параметра
	DWORD type = GetType(); switch (type)
	{
	case REG_QWORD: { DWORD64 ullValue = 0; 

		// получить значение параметра
		GetValue(&ullValue, sizeof(ullValue)); return ullValue; 
	}}
	// при ошибке выбросить исключение
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return 0; 
}

std::vector<BYTE> Windows::RegistryValueImpl::GetBinary() const
{
	// получить тип параметра и требуемый размер буфера
	DWORD cb = 0; switch (GetType(&cb))
	{
	// выделить буфер требуемого размера
	case REG_BINARY: { std::vector<BYTE> buffer(cb, 0); 
		
		// получить значение параметра
		if (cb > 0) GetValue(&buffer[0], cb); return buffer; 
	}}
	// при ошибке выбросить исключение
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return std::vector<BYTE>(); 
}

std::wstring Windows::RegistryValueImpl::GetString(BOOL expand) const
{
	// получить тип параметра и требуемый размер буфера
	DWORD cb = 0; switch (GetType(&cb))
	{
	case REG_SZ: 
	{
		// выделить буфер требуемого размера 
		std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// получить значение параметра
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// установить общий размер
		buffer.resize(wcslen(buffer.c_str())); return buffer; 
	}
	case REG_EXPAND_SZ: 
	{
		// выделить буфер требуемого размера 
		std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// получить значение параметра
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// при необходимости подстановок
		if (expand) { std::wstring str = buffer; 

			// определить требуемый размер буфера
			DWORD cch = ::ExpandEnvironmentStringsW(str.c_str(), nullptr, 0); 

			// выделить буфер требуемого размера
			if (!cch) AE_CHECK_WINAPI(FALSE); buffer.resize(cch, 0); 

			// подставить переменные окружения
			cch = ::ExpandEnvironmentStringsW(str.c_str(), &buffer[0], cch); 

			// вернуть строку с выполненными подстановками 
			if (!cch) AE_CHECK_WINAPI(FALSE); buffer.resize(cch - 1); 
		}
		return buffer; 
	}
	case REG_MULTI_SZ:
	{
		// выделить буфер требуемого размера 
		std::wstring buffer(cb / sizeof(WCHAR), 0); size_t cch = 0; 

		// получить значение параметра
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// для всех полученных строк
		for (PCWSTR sz = buffer.c_str(); *sz; ) 
		{
			// определить общий размер 
			size_t len = wcslen(sz) + 1; cch += len; sz += len; 
		}
		// установить общий размер
		buffer.resize(cch); return buffer; 
	}}
	// при ошибке выбросить исключение
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return std::wstring(); 
}

std::vector<std::wstring> Windows::RegistryValueImpl::GetStrings() const
{
	// инициализировать паременные
	std::vector<std::wstring> values; 

	// получить тип параметра и требуемый размер буфера
	DWORD cb = 0; switch (GetType(&cb))
	{
	case REG_SZ: case REG_EXPAND_SZ:
	{
		// выделить буфер требуемого размера 
		if (cb == 0) return values; std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// получить значение параметра
		GetValue(&buffer[0], cb); 
		
		// вернуть строку
		values.push_back(buffer.c_str()); return values; 
	}
	case REG_MULTI_SZ:
	{
		// выделить буфер требуемого размера 
		if (cb == 0) return values; std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// получить значение параметра
		GetValue(&buffer[0], cb); 
		
		// для всех полученных строк
		for (PCWSTR sz = buffer.c_str(); *sz; ) 
		{
			// добавить строку в список
			values.push_back(sz); sz += wcslen(sz) + 1; 
		}
		return values; 
	}}
	// при ошибке выбросить исключение
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return values; 
}

void Windows::RegistryValueImpl::SetStrings(PCWSTR* szValues, DWORD cValues)  
{
	// для всех строк 
	size_t cbValue = sizeof(WCHAR); for (DWORD i = 0; i < cValues; i++)
	{
		// добавить размер строки
		cbValue += (wcslen(szValues[i]) + 1) * sizeof(WCHAR); 
	}
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cbValue, 0); PBYTE pbBuffer = &buffer[0]; 

	// для всех строк 
	for (DWORD i = 0; i < cValues; i++)
	{
		// определить размер строки
		size_t cb = (wcslen(szValues[i]) + 1) * sizeof(WCHAR); 

		// скопировать строку
		memcpy(pbBuffer, szValues[i], cb); pbBuffer += cb;
	}
	// установить значение параметра
	SetValue(&buffer[0], (DWORD)cbValue, REG_MULTI_SZ); 
}

///////////////////////////////////////////////////////////////////////////////
// Значение в разделе реестра 
///////////////////////////////////////////////////////////////////////////////
	// получить тип и размер параметра 
DWORD Windows::RegistryValue::GetType(DWORD* pcbBuffer) const
{
	DWORD type = 0; DWORD cb = 0; 

	// получить тип параметра
	AE_CHECK_WINERROR(::RegQueryValueExW(_hKey, 
		_strValue.c_str(), nullptr, &type, nullptr, &cb
	)); 
	// вернуть тип и размер данных
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}
// получить значение параметра
DWORD Windows::RegistryValue::GetValue(PVOID pvBuffer, DWORD cbBuffer) const
{
	// получить значение параметра
	AE_CHECK_WINERROR(::RegQueryValueExW(_hKey, 
		_strValue.c_str(), nullptr, nullptr, (PBYTE)pvBuffer, &cbBuffer
	)); 
	// проверить отсутствие ошибок
	return cbBuffer;  
}
// установить значение параметра
void Windows::RegistryValue::SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type)
{
	// установить значение параметра
	AE_CHECK_WINERROR(::RegSetKeyValueW(
		_hKey, NULL, _strValue.c_str(),  type, pvBuffer, cbBuffer
	)); 
}
