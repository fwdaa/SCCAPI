#include "pch.h"
#include "extension.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "extension.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::FunctionExtensionRegistryValue::GetType(PDWORD pcbBuffer) const 
{ 
	// ���������������� ���������� 
	DWORD type = _type; DWORD cb = (DWORD)_value.size(); 

	// ��� ���������� ������
	if (type == REG_NONE) 
	{
		// �������� ��� ���������
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			&type, nullptr, &cb
		)); 
	}
	// ������� ��� � ������ ������
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}

DWORD Windows::Crypto::FunctionExtensionRegistryValue::GetValue(
	PVOID pvBuffer, DWORD cbBuffer) const 
{
	// ��������� ������� ������
	if (_type != REG_NONE) { DWORD cb = (DWORD)_value.size(); 
	
		// ��������� ������������� ������
		if (cbBuffer < cb) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

		// ����������� ������
		if (cb > 0) memcpy(pvBuffer, &_value[0], cb); 
	}
	else {
		// �������� �������� ���������
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
	// ���������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetOIDFunctionValue(_dwEncodingType, 
		_strFuncName.c_str(), _szOID, _szValue.c_str(), 
		type, (CONST BYTE*)pvBuffer, cbBuffer
	)); 
 	// �������� ����� ���������� ������� 
 	_type = type; _value.resize(cbBuffer); 
 
 	// ��������� ��������
 	if (cbBuffer > 0) memcpy(&_value[0], pvBuffer, cbBuffer); 	
};

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionOID::FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)
	
	// ��������� ���������� ���������
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID)
{
	// ����������� ��������� �������������
	if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }

	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionOIDCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR pszOID, DWORD cValue, 
	CONST DWORD* rgdwValueType, LPCWSTR CONST* rgpwszValueName, 
	CONST BYTE* CONST* rgpbValueData, CONST DWORD* rgcbValueData, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > arg_type; 

	// ��������� �������������� ����
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// ��� ���� ��������
	for (DWORD i = 0; i < cValue; i++)
	{
		// �������� �������� � ������
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
	// ������� ������ ���������� �����������
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// ����������� ��������� �����������
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

BOOL Windows::Crypto::FunctionExtensionOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ������� ��������� ���������� OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, 
		OID(), CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr)) return TRUE; 
		 
	// ������� ������ ��������� ������� ���������� 
	FunctionExtension extension(hFuncAddr, pvFuncAddr, TRUE); 

	// ������� ������� ��������� ������
	return pCallback->Invoke(&extension); 
}

// ���������� ������� ���������
void Windows::Crypto::FunctionExtensionOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// ������� OID � ����� �������
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// ���������� �������
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionOID::GetFunction(DWORD flags) const
{
	// ���������������� ���������� 
    HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;

	// �������� ������� ��������� ���������� OID
	AE_CHECK_WINAPI(::CryptGetOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, OID(), flags, &pvFuncAddr, &hFuncAddr
	)); 
	// ������� ������� ��������� ���������� OID
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionDefaultOID::FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType)
	
	// ��������� ���������� ���������
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType)
{
	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// ������� ������ ���������� �����������
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// ����������� ��������� �����������
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

std::vector<std::wstring> Windows::Crypto::FunctionExtensionDefaultOID::EnumModules() const
{
	// ������� ������ ������ �������
	std::vector<std::wstring> modules; DWORD cchDllList = 0; 

	// �������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, nullptr, &cchDllList));

	// �������� ����� ���������� �������
	if (cchDllList == 0) return modules; std::wstring buffer(cchDllList, 0); 

	// �������� ������ ������� ��� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, &buffer[0], &cchDllList));

	// ��� ���� ���������� �������
	for (PCWSTR szModule = buffer.c_str(); *szModule; ) 
	{
		// �������� ������ � ������
		modules.push_back(szModule); szModule += wcslen(szModule) + 1; 
	}
	return modules; 
}

void Windows::Crypto::FunctionExtensionDefaultOID::AddModule(PCWSTR szModule, DWORD dwIndex) const 
{
	// ���������� ������ ��� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptRegisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), dwIndex, szModule)); 
}

void Windows::Crypto::FunctionExtensionDefaultOID::RemoveModule(PCWSTR szModule) const 
{
	// ������� ������ ��� ��������� �� ���������
	::CryptUnregisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), szModule); 
}

BOOL Windows::Crypto::FunctionExtensionDefaultOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ����� ��������� ������� 
	while (::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
	{
		// ������� ������ ��������� ������� ���������� 
		FunctionExtension extension(hFuncAddr, pvFuncAddr, FALSE); 

		// ������� ������� ��������� ������
		if (!pCallback->Invoke(&extension)) return FALSE; 
	}
	return TRUE; 
}

void Windows::Crypto::FunctionExtensionDefaultOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// ������� OID � ����� �������
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// ���������� �������
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionDefaultOID::GetFunction(PCWSTR szModule) const
{
	// ������� CryptGetDefaultOIDFunctionAddress ��������� ������ ��� ������ 
	// LoadLibrary, ������� �� ��������� �������� �������� ������� �� �������,
	// ����� ������ ��� ��������� � �������� ������������ �� ������ ������� 

	// ��������� ������� ������ � �������� ������������
	HMODULE hModule = ::GetModuleHandleW(szModule); if (!hModule)
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_MOD_NOT_FOUND); 
	}
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ������� ��������� �� ���������
	BOOL fOK = ::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, szModule, 0, &pvFuncAddr, &hFuncAddr
	); 
	// ��������� ���������� ������
	AE_CHECK_WINAPI(fOK); ::FreeLibrary(hModule); 

	// ������� ������� ���������� 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
}

std::shared_ptr<Windows::Crypto::IFunctionExtension> 
Windows::Crypto::FunctionExtensionDefaultOID::GetFunction(DWORD flags) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr; 

	// ��������� ������������ ������
	if (flags & CRYPT_GET_INSTALLED_OID_FUNC_FLAG)
	{
		// �������� ����� ������������� ������� 
		if (::CryptGetDefaultOIDFunctionAddress(
			_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
		{
			// ������� ������� ���������� 
			return std::shared_ptr<IFunctionExtension>(
				new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
			); 
		}
	}
	// ����������� ������
	std::vector<std::wstring> modules = EnumModules(); 

	// ��������� ������� �������
	if (modules.size() == 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 

	// �������� ����� ��������� ������� 
	AE_CHECK_WINAPI(::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, modules[0].c_str(), 0, &pvFuncAddr, &hFuncAddr
	)); 
	// ������� ������� ���������� 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::FunctionExtensionSet::FunctionExtensionSet(PCSTR szFuncName) : _strFuncName(szFuncName) 
{
	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionSetEnumOIDsCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR szOID, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::vector<std::shared_ptr<Windows::Crypto::IFunctionExtensionOID> > arg_type; 

	// ������� ��� ���������
	typedef arg_type::const_iterator const_iterator; 

	// ��������� �������������� ����
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// ��� �������� ����� �������
	if (((UINT_PTR)szOID >> 16) != 0)
	{
		// ���������� ������� �� ���������
		if (::lstrcmpiA(szOID, CRYPT_DEFAULT_OID) == 0) return TRUE; 
	}
	// �������� OID � ������
	names.push_back(std::shared_ptr<Windows::Crypto::IFunctionExtensionOID>(
		new Windows::Crypto::FunctionExtensionOID(pszFuncName, dwEncodingType, szOID)
	)); 
	return TRUE; 
}

std::vector<std::shared_ptr<Windows::Crypto::IFunctionExtensionOID> > 
Windows::Crypto::FunctionExtensionSet::EnumOIDs(DWORD dwEncodingType) const
{
	// ������� ������ �������������� OID
	std::vector<std::shared_ptr<IFunctionExtensionOID> > oidSets; 

	// ����������� �������������� OID
	::CryptEnumOIDFunction(dwEncodingType, _strFuncName.c_str(), 
		nullptr, 0, &oidSets, ::FunctionExtensionSetEnumOIDsCallback
	); 
	return oidSets; 
}

void Windows::Crypto::FunctionExtensionSet::RegisterOID(
	DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const 
{
	// �������� ��������� OID
	AE_CHECK_WINAPI(::CryptRegisterOIDFunction(
		dwEncodingType, _strFuncName.c_str(), szOID, szModule, szFunction
	)); 
	// ��������� �������� ������
	if (dwFlags == 0) return; 
	
	// ���������� �������������� �������� � �������
	BOOL fOK = ::CryptSetOIDFunctionValue(dwEncodingType, 
		_strFuncName.c_str(), szOID, CRYPT_OID_REG_FLAGS_VALUE_NAME, 
		REG_DWORD, (CONST BYTE*)&dwFlags, sizeof(dwFlags)
	); 
	// ��������� ���������� ������
	if (!fOK) { DWORD code = ::GetLastError(); 

		// ������� ��������� OID
		::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 

		// ��������� ����������
		AE_CHECK_WINERROR(code); 
	}
}

void Windows::Crypto::FunctionExtensionSet::UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const 
{
	// ������� ��������� OID
	::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 
}

static BOOL CALLBACK EnumFunctionExtensionSetCallback(
    DWORD, PCSTR pszFuncName, PCSTR, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::vector<std::string> arg_type; 

	// ��������� �������������� ����
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// ������� ��� ������� ���������� 
	std::string name(pszFuncName); 

	// ��� ���������� �����
	if (std::find(names.begin(), names.end(), name) == names.end())
	{
		// �������� ��� � ������
		names.push_back(name); 
	}
	return TRUE; 
}

std::vector<std::string> Windows::Crypto::EnumFunctionExtensionSets()
{
	// ������� ������ ���� ������� ���������� 
	std::vector<std::string> names; 

	// ����������� ����� ������� ���������� 
	::CryptEnumOIDFunction(CRYPT_MATCH_ANY_ENCODING_TYPE, 
		nullptr, nullptr, 0, &names, ::EnumFunctionExtensionSetCallback
	); 
	return names; 
}

std::shared_ptr<Windows::Crypto::IFunctionExtensionSet> Windows::Crypto::GetFunctionExtensionSet(PCSTR szFuncName)
{
	// ������� ����� ������� ���������� 
	return std::shared_ptr<IFunctionExtensionSet>(new FunctionExtensionSet(szFuncName)); 
}
