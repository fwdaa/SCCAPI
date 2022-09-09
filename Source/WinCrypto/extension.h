#pragma once
#include "crypto.h"

namespace Windows { namespace Crypto { namespace Extension { 

///////////////////////////////////////////////////////////////////////////////
// Значение в реестре для функций расширения
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionRegistryValue : public RegistryValueImpl
{
	// имя функции и идентификатор OID
	private: std::string _strFuncName; std::string _strOID; PCSTR _szOID; 

	// тип кодирования и имя значения  
	private: DWORD _dwEncodingType; std::wstring _szValue; 

	// тип и содержимое значения 
	private: DWORD _type; std::vector<BYTE> _value; 

	// конструктор
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, 
		PCWSTR szValue, DWORD type, LPCVOID pvValue, DWORD cbValue)

		// сохранить переданные параметры
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), 

		// сохранить переданные параметры
		_type(type), _value((CONST BYTE*)pvValue, (CONST BYTE*)pvValue + cbValue) 
	{
		// скопировать строковое представление OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// конструктор
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, PCWSTR szValue)

		// сохранить переданные параметры
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), _type(REG_NONE) 
	{
		// скопировать строковое представление OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// получить тип и размер параметра 
	protected: virtual DWORD GetType(PDWORD pcb) const override; 

	// получить значение параметра
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 

	// установить значение параметра
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Вызываемая функция расширения
///////////////////////////////////////////////////////////////////////////////
class FunctionExtension : public IFunctionExtension
{
	// описатель функции и ее адрес
	private: HCRYPTOIDFUNCADDR _hFuncAddr; PVOID _pvFuncAddr; BOOL _fClose; 

	// конструктор
	public: FunctionExtension(HCRYPTOIDFUNCADDR hFuncAddr, PVOID pvFuncAddr, BOOL fClose = FALSE)

		// сохранить переданные параметры
		: _hFuncAddr(hFuncAddr), _pvFuncAddr(pvFuncAddr), _fClose(fClose) {}

	// деструктор 
	public: virtual ~FunctionExtension() 
	{
		// уменьшить счетчик ссылок функции 
		if (_fClose && _hFuncAddr) ::CryptFreeOIDFunctionAddress(_hFuncAddr, 0); 
	}
	// адрес вызываемой функции расширения 
	public: virtual PVOID Address() const override { return _pvFuncAddr; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения для OID
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionOID : public IFunctionExtensionOID
{
	// описатель набора и имя функции
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 
	// тип кодирования и идентификатор OID
	private: DWORD _dwEncodingType; std::string _strOID; PCSTR _szOID;

	// конструктор
	public: FunctionExtensionOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)

		// сохранить ипереданные параметры 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID) 
	{
		// скопировать строковое представление
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// конструктор
	public: FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID); 

	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// тип кодирования 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID функции расширения 
	public: virtual PCSTR OID         () const override { return _szOID;               } 

	// перечислить параметры регистрации
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 
	// получить параметр регистрации
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// получить параметр регистрации
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// перечислить установленные функции
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override;
	// установить функцию расширения 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения по умолчанию
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionDefaultOID : public IFunctionExtensionDefaultOID
{
	// описатель набора, имя функции и тип кодирования
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; DWORD _dwEncodingType;

	// конструктор
	public: FunctionExtensionDefaultOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType)

		// сохранить ипереданные параметры 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType) {}

	// конструктор
	public: FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType); 

	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// тип кодирования 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID функции расширения 
	public: virtual PCSTR OID         () const override { return CRYPT_DEFAULT_OID;    } 

	// перечислить параметры регистрации
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 

	// получить параметр регистрации
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// получить параметр регистрации
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// получить список зарегистрированных модулей 
	public: virtual std::vector<std::wstring> EnumModules() const override; 
	// зарегистрировать модуль 
	public: virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const override; 
	// отменить регистрацию модуля 
	public: virtual void RemoveModule(PCWSTR szModule) const override; 

	// перечислить установленные функции
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override; 
	// установить функцию расширения 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const override; 
	// найти вызываемую функцию расширения
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения 
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionSet : public IFunctionExtensionSet
{
	// описатель набора и имя функции
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 

	// конструктор
	public: FunctionExtensionSet(PCSTR szFuncName); 
	
	// имя функции расширения 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 

	// получить набор функций расширения по умолчанию
	public: virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const override 
	{
		// получить набор функций расширения по умолчанию
		return std::shared_ptr<IFunctionExtensionDefaultOID>(
			new FunctionExtensionDefaultOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType)
		); 
	}
	// перечислить наборы функций расширения для OID
	public: virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const override; 

	// зарегистрировать функцию расширения для OID
	public: virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const override; 
	// отменить регистрацию функции расширения для OID
	public: virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const override; 
 
	// получить набор функций расширения для OID
	public: virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const override
	{
		// получить набор функций расширения для OID
		return std::shared_ptr<IFunctionExtensionOID>(
			new FunctionExtensionOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType, szOID)
		); 
	}
};

}}}

