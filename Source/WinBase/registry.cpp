#include "pch.h"
#include "registry.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "registry.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� � ��������� ���������� � �������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::RegistryValueImpl::GetUInt32() const
{
	// ��������� ��� ���������
	DWORD type = GetType(); switch (type)
	{
	case REG_DWORD: { DWORD ulValue = 0; 

		// �������� �������� ���������
		GetValue(&ulValue, sizeof(ulValue)); return ulValue; 
	}
	case REG_DWORD_BIG_ENDIAN: { DWORD ulValue = 0; 

		// �������� �������� ���������
		GetValue(&ulValue, sizeof(ulValue)); 

		// �������� ������� ������
		return ((((ulValue >> 24) & 0xFF) <<  0) | 
			    (((ulValue >> 16) & 0xFF) <<  8) |
			    (((ulValue >>  8) & 0xFF) << 16) | 
			    (((ulValue >>  0) & 0xFF) << 24)); 
	}}
	// ��� ������ ��������� ����������
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return 0; 
}

DWORD64 Windows::RegistryValueImpl::GetUInt64() const
{
	// ��������� ��� ���������
	DWORD type = GetType(); switch (type)
	{
	case REG_QWORD: { DWORD64 ullValue = 0; 

		// �������� �������� ���������
		GetValue(&ullValue, sizeof(ullValue)); return ullValue; 
	}}
	// ��� ������ ��������� ����������
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return 0; 
}

std::vector<BYTE> Windows::RegistryValueImpl::GetBinary() const
{
	// �������� ��� ��������� � ��������� ������ ������
	DWORD cb = 0; switch (GetType(&cb))
	{
	// �������� ����� ���������� �������
	case REG_BINARY: { std::vector<BYTE> buffer(cb, 0); 
		
		// �������� �������� ���������
		if (cb > 0) GetValue(&buffer[0], cb); return buffer; 
	}}
	// ��� ������ ��������� ����������
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return std::vector<BYTE>(); 
}

std::wstring Windows::RegistryValueImpl::GetString(BOOL expand) const
{
	// �������� ��� ��������� � ��������� ������ ������
	DWORD cb = 0; switch (GetType(&cb))
	{
	case REG_SZ: 
	{
		// �������� ����� ���������� ������� 
		std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// �������� �������� ���������
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// ���������� ����� ������
		buffer.resize(wcslen(buffer.c_str())); return buffer; 
	}
	case REG_EXPAND_SZ: 
	{
		// �������� ����� ���������� ������� 
		std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// �������� �������� ���������
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// ��� ������������� �����������
		if (expand) { std::wstring str = buffer; 

			// ���������� ��������� ������ ������
			DWORD cch = ::ExpandEnvironmentStringsW(str.c_str(), nullptr, 0); 

			// �������� ����� ���������� �������
			if (!cch) AE_CHECK_WINAPI(FALSE); buffer.resize(cch, 0); 

			// ���������� ���������� ���������
			cch = ::ExpandEnvironmentStringsW(str.c_str(), &buffer[0], cch); 

			// ������� ������ � ������������ ������������� 
			if (!cch) AE_CHECK_WINAPI(FALSE); buffer.resize(cch - 1); 
		}
		return buffer; 
	}
	case REG_MULTI_SZ:
	{
		// �������� ����� ���������� ������� 
		std::wstring buffer(cb / sizeof(WCHAR), 0); size_t cch = 0; 

		// �������� �������� ���������
		if (cb == 0) return buffer; GetValue(&buffer[0], cb); 
		
		// ��� ���� ���������� �����
		for (PCWSTR sz = buffer.c_str(); *sz; ) 
		{
			// ���������� ����� ������ 
			size_t len = wcslen(sz) + 1; cch += len; sz += len; 
		}
		// ���������� ����� ������
		buffer.resize(cch); return buffer; 
	}}
	// ��� ������ ��������� ����������
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return std::wstring(); 
}

std::vector<std::wstring> Windows::RegistryValueImpl::GetStrings() const
{
	// ���������������� ����������
	std::vector<std::wstring> values; 

	// �������� ��� ��������� � ��������� ������ ������
	DWORD cb = 0; switch (GetType(&cb))
	{
	case REG_SZ: case REG_EXPAND_SZ:
	{
		// �������� ����� ���������� ������� 
		if (cb == 0) return values; std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// �������� �������� ���������
		GetValue(&buffer[0], cb); 
		
		// ������� ������
		values.push_back(buffer.c_str()); return values; 
	}
	case REG_MULTI_SZ:
	{
		// �������� ����� ���������� ������� 
		if (cb == 0) return values; std::wstring buffer(cb / sizeof(WCHAR), 0); 

		// �������� �������� ���������
		GetValue(&buffer[0], cb); 
		
		// ��� ���� ���������� �����
		for (PCWSTR sz = buffer.c_str(); *sz; ) 
		{
			// �������� ������ � ������
			values.push_back(sz); sz += wcslen(sz) + 1; 
		}
		return values; 
	}}
	// ��� ������ ��������� ����������
	AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); return values; 
}

void Windows::RegistryValueImpl::SetStrings(PCWSTR* szValues, DWORD cValues)  
{
	// ��� ���� ����� 
	size_t cbValue = sizeof(WCHAR); for (DWORD i = 0; i < cValues; i++)
	{
		// �������� ������ ������
		cbValue += (wcslen(szValues[i]) + 1) * sizeof(WCHAR); 
	}
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cbValue, 0); PBYTE pbBuffer = &buffer[0]; 

	// ��� ���� ����� 
	for (DWORD i = 0; i < cValues; i++)
	{
		// ���������� ������ ������
		size_t cb = (wcslen(szValues[i]) + 1) * sizeof(WCHAR); 

		// ����������� ������
		memcpy(pbBuffer, szValues[i], cb); pbBuffer += cb;
	}
	// ���������� �������� ���������
	SetValue(&buffer[0], (DWORD)cbValue, REG_MULTI_SZ); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ������� 
///////////////////////////////////////////////////////////////////////////////
	// �������� ��� � ������ ��������� 
DWORD Windows::RegistryValue::GetType(DWORD* pcbBuffer) const
{
	DWORD type = 0; DWORD cb = 0; 

	// �������� ��� ���������
	AE_CHECK_WINERROR(::RegQueryValueExW(_hKey, 
		_strValue.c_str(), nullptr, &type, nullptr, &cb
	)); 
	// ������� ��� � ������ ������
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}
// �������� �������� ���������
DWORD Windows::RegistryValue::GetValue(PVOID pvBuffer, DWORD cbBuffer) const
{
	// �������� �������� ���������
	AE_CHECK_WINERROR(::RegQueryValueExW(_hKey, 
		_strValue.c_str(), nullptr, nullptr, (PBYTE)pvBuffer, &cbBuffer
	)); 
	// ��������� ���������� ������
	return cbBuffer;  
}
// ���������� �������� ���������
void Windows::RegistryValue::SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type)
{
	// ���������� �������� ���������
	AE_CHECK_WINERROR(::RegSetKeyValueW(
		_hKey, NULL, _strValue.c_str(),  type, pvBuffer, cbBuffer
	)); 
}
