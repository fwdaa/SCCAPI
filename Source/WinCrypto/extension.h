#pragma once
#include "crypto.h"

namespace Windows { namespace Crypto { namespace Extension { 

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionRegistryValue : public RegistryValueImpl
{
	// ��� ������� � ������������� OID
	private: std::string _strFuncName; std::string _strOID; PCSTR _szOID; 

	// ��� ����������� � ��� ��������  
	private: DWORD _dwEncodingType; std::wstring _szValue; 

	// ��� � ���������� �������� 
	private: DWORD _type; std::vector<BYTE> _value; 

	// �����������
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, 
		PCWSTR szValue, DWORD type, LPCVOID pvValue, DWORD cbValue)

		// ��������� ���������� ���������
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), 

		// ��������� ���������� ���������
		_type(type), _value((CONST BYTE*)pvValue, (CONST BYTE*)pvValue + cbValue) 
	{
		// ����������� ��������� ������������� OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �����������
	public: FunctionExtensionRegistryValue(PCSTR szFuncName, PCSTR szOID, DWORD dwEncodingType, PCWSTR szValue)

		// ��������� ���������� ���������
		: _strFuncName(szFuncName), _szOID(szOID), _dwEncodingType(dwEncodingType), _szValue(szValue), _type(REG_NONE) 
	{
		// ����������� ��������� ������������� OID
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �������� ��� � ������ ��������� 
	protected: virtual DWORD GetType(PDWORD pcb) const override; 

	// �������� �������� ���������
	protected: virtual DWORD GetValue(PVOID pvBuffer, DWORD cbBuffer) const override; 

	// ���������� �������� ���������
	protected: virtual void SetValue(LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtension : public IFunctionExtension
{
	// ��������� ������� � �� �����
	private: HCRYPTOIDFUNCADDR _hFuncAddr; PVOID _pvFuncAddr; BOOL _fClose; 

	// �����������
	public: FunctionExtension(HCRYPTOIDFUNCADDR hFuncAddr, PVOID pvFuncAddr, BOOL fClose = FALSE)

		// ��������� ���������� ���������
		: _hFuncAddr(hFuncAddr), _pvFuncAddr(pvFuncAddr), _fClose(fClose) {}

	// ���������� 
	public: virtual ~FunctionExtension() 
	{
		// ��������� ������� ������ ������� 
		if (_fClose && _hFuncAddr) ::CryptFreeOIDFunctionAddress(_hFuncAddr, 0); 
	}
	// ����� ���������� ������� ���������� 
	public: virtual PVOID Address() const override { return _pvFuncAddr; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionOID : public IFunctionExtensionOID
{
	// ��������� ������ � ��� �������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 
	// ��� ����������� � ������������� OID
	private: DWORD _dwEncodingType; std::string _strOID; PCSTR _szOID;

	// �����������
	public: FunctionExtensionOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)

		// ��������� ����������� ��������� 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID) 
	{
		// ����������� ��������� �������������
		if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }
	}
	// �����������
	public: FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID); 

	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// ��� ����������� 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID ������� ���������� 
	public: virtual PCSTR OID         () const override { return _szOID;               } 

	// ����������� ��������� �����������
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 
	// �������� �������� �����������
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// �������� �������� �����������
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// ����������� ������������� �������
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override;
	// ���������� ������� ���������� 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionDefaultOID : public IFunctionExtensionDefaultOID
{
	// ��������� ������, ��� ������� � ��� �����������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; DWORD _dwEncodingType;

	// �����������
	public: FunctionExtensionDefaultOID(HCRYPTOIDFUNCSET hFuncSet, PCSTR szFuncName, DWORD dwEncodingType)

		// ��������� ����������� ��������� 
		: _hFuncSet(hFuncSet), _strFuncName(szFuncName), _dwEncodingType(dwEncodingType) {}

	// �����������
	public: FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType); 

	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 
	// ��� ����������� 
	public: virtual DWORD EncodingType() const override { return _dwEncodingType;      } 
	// OID ������� ���������� 
	public: virtual PCSTR OID         () const override { return CRYPT_DEFAULT_OID;    } 

	// ����������� ��������� �����������
	public: virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const override; 

	// �������� �������� �����������
	public: virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const override
	{
		// �������� �������� �����������
		return std::shared_ptr<IRegistryValue>(new FunctionExtensionRegistryValue(
			_strFuncName.c_str(), OID(), _dwEncodingType, szName
		)); 
	}
	// �������� ������ ������������������ ������� 
	public: virtual std::vector<std::wstring> EnumModules() const override; 
	// ���������������� ������ 
	public: virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const override; 
	// �������� ����������� ������ 
	public: virtual void RemoveModule(PCWSTR szModule) const override; 

	// ����������� ������������� �������
	public: virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const override; 
	// ���������� ������� ���������� 
	public: virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const override; 

	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const override; 
	// ����� ���������� ������� ����������
	public: virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class FunctionExtensionSet : public IFunctionExtensionSet
{
	// ��������� ������ � ��� �������
	private: HCRYPTOIDFUNCSET _hFuncSet; std::string _strFuncName; 

	// �����������
	public: FunctionExtensionSet(PCSTR szFuncName); 
	
	// ��� ������� ���������� 
	public: virtual PCSTR FunctionName() const override { return _strFuncName.c_str(); } 

	// �������� ����� ������� ���������� �� ���������
	public: virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const override 
	{
		// �������� ����� ������� ���������� �� ���������
		return std::shared_ptr<IFunctionExtensionDefaultOID>(
			new FunctionExtensionDefaultOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType)
		); 
	}
	// ����������� ������ ������� ���������� ��� OID
	public: virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const override; 

	// ���������������� ������� ���������� ��� OID
	public: virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const override; 
	// �������� ����������� ������� ���������� ��� OID
	public: virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const override; 
 
	// �������� ����� ������� ���������� ��� OID
	public: virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const override
	{
		// �������� ����� ������� ���������� ��� OID
		return std::shared_ptr<IFunctionExtensionOID>(
			new FunctionExtensionOID(_hFuncSet, _strFuncName.c_str(), dwEncodingType, szOID)
		); 
	}
};

}}}

