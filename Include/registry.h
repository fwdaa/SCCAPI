#pragma once
#include <vector>
#include <string>

///////////////////////////////////////////////////////////////////////////////
// Определение экспортируемых функций
///////////////////////////////////////////////////////////////////////////////
#ifdef WINBASE_EXPORTS
#define WINBASE_CALL __declspec(dllexport)
#else 
#define WINBASE_CALL __declspec(dllimport)
#endif 

namespace Windows {

///////////////////////////////////////////////////////////////////////////////
// Значение в разделе реестра 
///////////////////////////////////////////////////////////////////////////////
struct IRegistryValue { virtual ~IRegistryValue() {}

	// получить тип значения 
	virtual DWORD GetType() const = 0; 

	// получить целочисленное значение
	virtual DWORD   GetUInt32() const = 0; 
	virtual DWORD64 GetUInt64() const = 0; 

	// получить бинарное значение 
	virtual std::vector<BYTE> GetBinary() const = 0; 
	// получить строковое значение 
	virtual std::wstring GetString(BOOL expand) const = 0; 
	// получить строковые значения 
	virtual std::vector<std::wstring> GetStrings() const = 0; 

	// установить целочисленное значение 
	virtual void SetUInt32(DWORD   ulValue ) = 0; 
	virtual void SetUInt64(DWORD64 ullValue) = 0; 

	// установить бинарное значение
	virtual void SetBinary(LPCVOID pvValue, DWORD cbValue) = 0; 

	// установить строковое значение
	virtual void SetString (PCWSTR  szValue,  DWORD type   ) = 0; 
	virtual void SetStrings(PCWSTR* szValues, DWORD cValues) = 0; 
}; 

class RegistryValueImpl : public IRegistryValue 
{
	// получить тип значения
	public: virtual DWORD GetType() const override { return GetType(nullptr); }

	// получить целочисленное значение 
	public: WINBASE_CALL virtual DWORD   GetUInt32() const override; 
	public: WINBASE_CALL virtual DWORD64 GetUInt64() const override; 

	// получить бинарное значение 
	public: WINBASE_CALL virtual std::vector<BYTE> GetBinary() const override; 
	// получить строковое значение 
	public: WINBASE_CALL virtual std::wstring GetString(BOOL expand) const override; 
	// получить строковые значения 
	public: WINBASE_CALL virtual std::vector<std::wstring> GetStrings() const override; 

	// установить целочисленное значение 
	public: virtual void SetUInt32(DWORD ulValue) override
	{
		// установить целочисленное значение
		SetValue(&ulValue, sizeof(ulValue), REG_DWORD); 
	}
	public: virtual void SetUInt64(DWORD64 ullValue) override
	{
		// установить целочисленное значение 
		SetValue(&ullValue, sizeof(ullValue), REG_QWORD); 
	}
	// установить бинарное значение
	public: virtual void SetBinary(LPCVOID pvValue, DWORD cbValue) override
	{
		// установить бинарное значение
		SetValue(pvValue, cbValue, REG_BINARY); 
	}
	// установить строковое значение
	public: virtual void SetString(PCWSTR szValue, DWORD type) override
	{
		// определить размер строки в байтах
		size_t cbValue = (wcslen(szValue) + 1) * sizeof(WCHAR); 

		// установить строковое значение
		SetValue(szValue, (DWORD)cbValue, type); 
	}
	// установить строковые значения
	public: WINBASE_CALL virtual void SetStrings(PCWSTR* szValues, DWORD cValues) override; 

	// получить тип и размер параметра 
	protected: virtual DWORD GetType(DWORD* pcbBuffer) const = 0; 
	// получить значение параметра
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD) const = 0; 
	// установить значение параметра
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) = 0; 
}; 

class RegistryValue : public RegistryValueImpl
{
	// раздел и значение в разделе
	private: HKEY _hKey; std::wstring _strValue; 

	// конструктор
	public: RegistryValue(HKEY hKey, PCWSTR szValue) : _hKey(hKey), _strValue(szValue) {}

	// получить тип и размер параметра 
	protected: WINBASE_CALL virtual DWORD GetType(DWORD* pcbBuffer) const override; 
	// получить значение параметра
	protected: WINBASE_CALL virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 
	// установить значение параметра
	protected: WINBASE_CALL virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
}; 

}
