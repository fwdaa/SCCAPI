#pragma once
#include <vector>
#include <string>

///////////////////////////////////////////////////////////////////////////////
// ����������� �������������� �������
///////////////////////////////////////////////////////////////////////////////
#ifdef WINBASE_EXPORTS
#define WINBASE_CALL __declspec(dllexport)
#else 
#define WINBASE_CALL __declspec(dllimport)
#endif 

namespace Windows {

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ������� 
///////////////////////////////////////////////////////////////////////////////
struct IRegistryValue { virtual ~IRegistryValue() {}

	// �������� ��� �������� 
	virtual DWORD GetType() const = 0; 

	// �������� ������������� ��������
	virtual DWORD   GetUInt32() const = 0; 
	virtual DWORD64 GetUInt64() const = 0; 

	// �������� �������� �������� 
	virtual std::vector<BYTE> GetBinary() const = 0; 
	// �������� ��������� �������� 
	virtual std::wstring GetString(BOOL expand) const = 0; 
	// �������� ��������� �������� 
	virtual std::vector<std::wstring> GetStrings() const = 0; 

	// ���������� ������������� �������� 
	virtual void SetUInt32(DWORD   ulValue ) = 0; 
	virtual void SetUInt64(DWORD64 ullValue) = 0; 

	// ���������� �������� ��������
	virtual void SetBinary(LPCVOID pvValue, DWORD cbValue) = 0; 

	// ���������� ��������� ��������
	virtual void SetString (PCWSTR  szValue,  DWORD type   ) = 0; 
	virtual void SetStrings(PCWSTR* szValues, DWORD cValues) = 0; 
}; 

class RegistryValueImpl : public IRegistryValue 
{
	// �������� ��� ��������
	public: virtual DWORD GetType() const override { return GetType(nullptr); }

	// �������� ������������� �������� 
	public: WINBASE_CALL virtual DWORD   GetUInt32() const override; 
	public: WINBASE_CALL virtual DWORD64 GetUInt64() const override; 

	// �������� �������� �������� 
	public: WINBASE_CALL virtual std::vector<BYTE> GetBinary() const override; 
	// �������� ��������� �������� 
	public: WINBASE_CALL virtual std::wstring GetString(BOOL expand) const override; 
	// �������� ��������� �������� 
	public: WINBASE_CALL virtual std::vector<std::wstring> GetStrings() const override; 

	// ���������� ������������� �������� 
	public: virtual void SetUInt32(DWORD ulValue) override
	{
		// ���������� ������������� ��������
		SetValue(&ulValue, sizeof(ulValue), REG_DWORD); 
	}
	public: virtual void SetUInt64(DWORD64 ullValue) override
	{
		// ���������� ������������� �������� 
		SetValue(&ullValue, sizeof(ullValue), REG_QWORD); 
	}
	// ���������� �������� ��������
	public: virtual void SetBinary(LPCVOID pvValue, DWORD cbValue) override
	{
		// ���������� �������� ��������
		SetValue(pvValue, cbValue, REG_BINARY); 
	}
	// ���������� ��������� ��������
	public: virtual void SetString(PCWSTR szValue, DWORD type) override
	{
		// ���������� ������ ������ � ������
		size_t cbValue = (wcslen(szValue) + 1) * sizeof(WCHAR); 

		// ���������� ��������� ��������
		SetValue(szValue, (DWORD)cbValue, type); 
	}
	// ���������� ��������� ��������
	public: WINBASE_CALL virtual void SetStrings(PCWSTR* szValues, DWORD cValues) override; 

	// �������� ��� � ������ ��������� 
	protected: virtual DWORD GetType(DWORD* pcbBuffer) const = 0; 
	// �������� �������� ���������
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD) const = 0; 
	// ���������� �������� ���������
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) = 0; 
}; 

class RegistryValue : public RegistryValueImpl
{
	// ������ � �������� � �������
	private: HKEY _hKey; std::wstring _strValue; 

	// �����������
	public: RegistryValue(HKEY hKey, PCWSTR szValue) : _hKey(hKey), _strValue(szValue) {}

	// �������� ��� � ������ ��������� 
	protected: WINBASE_CALL virtual DWORD GetType(DWORD* pcbBuffer) const override; 
	// �������� �������� ���������
	protected: WINBASE_CALL virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 
	// ���������� �������� ���������
	protected: WINBASE_CALL virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
}; 

}
