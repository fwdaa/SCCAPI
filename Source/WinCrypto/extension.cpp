#include "pch.h"
#include "extension.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "extension.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Значение в реестре для функций расширения
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::FunctionExtensionRegistryValue::GetType(PDWORD pcbBuffer) const 
{ 
	// инициализировать переменные 
	DWORD type = _type; DWORD cb = (DWORD)_value.size(); 

	// при отсутствии данных
	if (type == REG_NONE) 
	{
		// получить тип параметра
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			&type, nullptr, &cb
		)); 
	}
	// вернуть тип и размер данных
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}

DWORD Windows::Crypto::FunctionExtensionRegistryValue::GetValue(
	PVOID pvBuffer, DWORD cbBuffer) const 
{
	// проверить наличие данных
	if (_type != REG_NONE) { DWORD cb = (DWORD)_value.size(); 
	
		// проверить достаточность буфера
		if (cbBuffer < cb) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

		// скопировать данные
		if (cb > 0) memcpy(pvBuffer, &_value[0], cb); 
	}
	else {
		// получить значение параметра
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			nullptr, (PBYTE)pvBuffer, &cbBuffer
		)); 
	}
	return cbBuffer;  
}

void Windows::Crypto::FunctionExtensionRegistryValue::SetValue(
	LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) 
{
	// установить значение параметра
	AE_CHECK_WINAPI(::CryptSetOIDFunctionValue(_dwEncodingType, 
		_strFuncName.c_str(), _szOID, _szValue.c_str(), 
		type, (CONST BYTE*)pvBuffer, cbBuffer
	)); 
 	// выделить буфер требуемого размера 
 	_type = type; _value.resize(cbBuffer); 
 
 	// сохранить значение
 	if (cbBuffer > 0) memcpy(&_value[0], pvBuffer, cbBuffer); 	
};

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения для OID
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionOID::FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)
	
	// сохранить переданные параметры
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID)
{
	// скопировать строковое представление
	if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }

	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionOIDCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR pszOID, DWORD cValue, 
	CONST DWORD* rgdwValueType, LPCWSTR CONST* rgpwszValueName, 
	CONST BYTE* CONST* rgpbValueData, CONST DWORD* rgcbValueData, PVOID pvArg
){
	// указать тип параметра
	typedef std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > arg_type; 

	// выполнить преобразование типа
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// для всех значений
	for (DWORD i = 0; i < cValue; i++)
	{
		// добавить значение в список
		values[rgpwszValueName[i]] = std::shared_ptr<Windows::IRegistryValue>(
			new Windows::Crypto::FunctionExtensionRegistryValue(
				pszFuncName, pszOID, dwEncodingType, rgpwszValueName[i], 
				rgdwValueType[i], rgpbValueData[i], rgcbValueData[i]
		)); 
	}
	return FALSE; 
}

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::FunctionExtensionOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// перечислить параметры регистрации
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

BOOL Windows::Crypto::FunctionExtensionOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить функцию обработки отдельного OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, 
		OID(), CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr)) return TRUE; 
		 
	// создать объект отдельной функции расширения 
	FunctionExtension extension(hFuncAddr, pvFuncAddr, TRUE); 

	// вызвать функцию обратного вызова
	return pCallback->Invoke(&extension); 
}

// установить функцию обработки
void Windows::Crypto::FunctionExtensionOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// указать OID и адрес функции
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// установить функцию
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionOID::GetFunction(DWORD flags) const
{
	// инициализировать переменные 
    HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;

	// получить функцию обработки отдельного OID
	AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, OID(), flags, &pvFuncAddr, &hFuncAddr
	)); 
	// вернуть функцию обработки отдельного OID
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения по умолчанию
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionDefaultOID::FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType)
	
	// сохранить переданные параметры
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType)
{
	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// перечислить параметры регистрации
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

std::vector<std::wstring> Windows::Crypto::FunctionExtensionDefaultOID::EnumModules() const
{
	// создать пустой список модулей
	std::vector<std::wstring> modules; DWORD cchDllList = 0; 

	// получить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, nullptr, &cchDllList));

	// выделить буфер требуемого размера
	if (cchDllList == 0) return modules; std::wstring buffer(cchDllList, 0); 

	// получить список модулей для обработки по умолчанию
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, &buffer[0], &cchDllList));

	// для всех полученных модулей
	for (PCWSTR szModule = buffer.c_str(); *szModule; ) 
	{
		// добавить модуль в список
		modules.push_back(szModule); szModule += wcslen(szModule) + 1; 
	}
	return modules; 
}

void Windows::Crypto::FunctionExtensionDefaultOID::AddModule(PCWSTR szModule, DWORD dwIndex) const 
{
	// установить модуль для обработки по умолчанию
	AE_CHECK_WINAPI(::CryptRegisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), dwIndex, szModule)); 
}

void Windows::Crypto::FunctionExtensionDefaultOID::RemoveModule(PCWSTR szModule) const 
{
	// удалить модуль для обработки по умолчанию
	::CryptUnregisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), szModule); 
}

BOOL Windows::Crypto::FunctionExtensionDefaultOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить адрес следующей функции 
	while (::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
	{
		// создать объект отдельной функции расширения 
		FunctionExtension extension(hFuncAddr, pvFuncAddr, FALSE); 

		// вызвать функцию обратного вызова
		if (!pCallback->Invoke(&extension)) return FALSE; 
	}
	return TRUE; 
}

void Windows::Crypto::FunctionExtensionDefaultOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// указать OID и адрес функции
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// установить функцию
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionDefaultOID::GetFunction(PCWSTR szModule) const
{
	// функция CryptGetDefaultOIDFunctionAddress загружает модуль при помощи 
	// LoadLibrary, поэтому во избежание излишних загрузок модулей мы требуем,
	// чтобы модуль уже находился в адресном пространстве до вызова функции 

	// проверить наличие модуля в адресном пространстве
	HMODULE hModule = ::GetModuleHandleW(szModule); if (!hModule)
	{
		// при ошибке выбросить исключение
		AE_CHECK_WINERROR(ERROR_MOD_NOT_FOUND); 
	}
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить функцию обработки по умолчанию
	BOOL fOK = ::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, szModule, 0, &pvFuncAddr, &hFuncAddr
	); 
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(fOK); ::FreeLibrary(hModule); 

	// вернуть функцию расширения 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionDefaultOID::GetFunction(DWORD flags) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr; 

	// проверить корректность флагов
	if (flags & CRYPT_GET_INSTALLED_OID_FUNC_FLAG)
	{
		// получить адрес установленной функции 
		if (::CryptGetDefaultOIDFunctionAddress(
			_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
		{
			// вернуть функцию расширения 
			return std::shared_ptr<IFunctionExtension>(
				new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
			); 
		}
	}
	// перечислить модули
	std::vector<std::wstring> modules = EnumModules(); 

	// проверить наличие модулей
	if (modules.size() == 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 

	// получить адрес следующей функции 
	AE_CHECK_WINAPI(::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, modules[0].c_str(), 0, &pvFuncAddr, &hFuncAddr
	)); 
	// вернуть функцию расширения 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionSet::FunctionExtensionSet(PCSTR szFuncName) : _strFuncName(szFuncName) 
{
	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionSetEnumOIDsCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR szOID, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// указать тип параметра
	typedef std::vector<std::shared_ptr<Windows::Crypto::IFunctionExtensionOID> > arg_type; 

	// указать тип итератора
	typedef arg_type::const_iterator const_iterator; 

	// выполнить преобразование типа
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// при указании имени функции
	if (((UINT_PTR)szOID >> 16) != 0)
	{
		// пропустить функции по умолчанию
		if (::lstrcmpiA(szOID, CRYPT_DEFAULT_OID) == 0) return TRUE; 
	}
	// добавить OID в список
	names.push_back(std::shared_ptr<Windows::Crypto::IFunctionExtensionOID>(
		new Windows::Crypto::FunctionExtensionOID(pszFuncName, dwEncodingType, szOID)
	)); 
	return TRUE; 
}

std::vector<std::shared_ptr<Windows::Crypto::IFunctionExtensionOID> > 
Windows::Crypto::FunctionExtensionSet::EnumOIDs(DWORD dwEncodingType) const
{
	// создать список поддерживаемых OID
	std::vector<std::shared_ptr<IFunctionExtensionOID> > oidSets; 

	// перечислить поддерживаемые OID
	::CryptEnumOIDFunction(dwEncodingType, _strFuncName.c_str(), 
		nullptr, 0, &oidSets, ::FunctionExtensionSetEnumOIDsCallback
	); 
	return oidSets; 
}

void Windows::Crypto::FunctionExtensionSet::RegisterOID(
	DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const 
{
	// добавить поддержку OID
	AE_CHECK_WINAPI(::CryptRegisterOIDFunction(
		dwEncodingType, _strFuncName.c_str(), szOID, szModule, szFunction
	)); 
	// проверить указание флагов
	if (dwFlags == 0) return; 
	
	// установить дополнительный параметр в реестре
	BOOL fOK = ::CryptSetOIDFunctionValue(dwEncodingType, 
		_strFuncName.c_str(), szOID, CRYPT_OID_REG_FLAGS_VALUE_NAME, 
		REG_DWORD, (CONST BYTE*)&dwFlags, sizeof(dwFlags)
	); 
	// проверить отсутствие ошибок
	if (!fOK) { DWORD code = ::GetLastError(); 

		// удалить поддержку OID
		::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 

		// выбросить исключение
		AE_CHECK_WINERROR(code); 
	}
}

void Windows::Crypto::FunctionExtensionSet::UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const 
{
	// удалить поддержку OID
	::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 
}

static BOOL CALLBACK EnumFunctionExtensionSetCallback(
    DWORD, PCSTR pszFuncName, PCSTR, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// указать тип параметра
	typedef std::vector<std::string> arg_type; 

	// выполнить преобразование типа
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// указать имя функции расширения 
	std::string name(pszFuncName); 

	// при отсутствие имени
	if (std::find(names.begin(), names.end(), name) == names.end())
	{
		// добавить имя в список
		names.push_back(name); 
	}
	return TRUE; 
}

std::vector<std::string> Windows::Crypto::EnumFunctionExtensionSets()
{
	// создать список имен функций расширения 
	std::vector<std::string> names; 

	// перечислить имена функций расширения 
	::CryptEnumOIDFunction(CRYPT_MATCH_ANY_ENCODING_TYPE, 
		nullptr, nullptr, 0, &names, ::EnumFunctionExtensionSetCallback
	); 
	return names; 
}

std::shared_ptr<Windows::Crypto::IFunctionExtensionSet> Windows::Crypto::GetFunctionExtensionSet(PCSTR szFuncName)
{
	// вернуть набор функций расширения 
	return std::shared_ptr<IFunctionExtensionSet>(new FunctionExtensionSet(szFuncName)); 
}
