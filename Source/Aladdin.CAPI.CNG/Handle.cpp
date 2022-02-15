#include "stdafx.h"
#include "Handle.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Handle.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Handle::GetSafeParam(String^ param, DWORD flags)
{$
	// ���������� ������ ���������
	DWORD cb = GetSafeParam(param, IntPtr::Zero, 0, flags); 

	// �������� ������ ��� ���������
	if (cb == 0) return nullptr; array<BYTE>^ buffer = gcnew array<BYTE>(cb);

	// �������� ��������� �� �����
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// �������� �������� ���������
	cb = GetSafeParam(param, IntPtr(pbBuffer), cb, flags); 

	// �������� ������ ������
	if (cb == 0) return nullptr; Array::Resize(buffer, cb); return buffer;
}

array<BYTE>^ Aladdin::CAPI::CNG::Handle::GetParam(String^ param, DWORD flags)
{$
	// ���������� ������ ���������
	DWORD cb = GetParam(param, IntPtr::Zero, 0, flags); 

	// �������� ������ ��� ���������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// �������� ��������� �� �����
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// �������� �������� ���������
	cb = GetParam(param, IntPtr(pbBuffer), cb, flags); 

	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

String^ Aladdin::CAPI::CNG::Handle::GetString(String^ param, DWORD flags)
{$
	// �������� �������� ���������
	array<BYTE>^ data = GetParam(param, 0); 
	
	// �������� ������ ������
	Array::Resize(data, data->Length - 2); 

	// ������������� �������� ���������
	return Encoding::Unicode->GetString(data); 
}

DWORD Aladdin::CAPI::CNG::Handle::GetLong(String^ param, DWORD flags)
{$
	// �������� �������� ���������
	DWORD value = 0; GetParam(param, IntPtr(&value), sizeof(value), flags); return value; 
}

void Aladdin::CAPI::CNG::Handle::SetParam(String^ param, array<BYTE>^ value, DWORD flags)
{$
	// ��������� ������� ��������
	if (value == nullptr || value->Length == 0) SetParam(param, IntPtr::Zero, 0, flags); 
	else {
		// �������� ��������� �� �����
		pin_ptr<BYTE> ptrValue = &value[0]; PBYTE pbValue = ptrValue; 

		// ���������� �������� ���������
		SetParam(param, IntPtr(pbValue), value->Length, flags); 
	}
}

void Aladdin::CAPI::CNG::Handle::SetString(String^ param, String^ value, DWORD flags)
{$
	// ��������� ������� ��������
	if (value == nullptr) SetParam(param, IntPtr::Zero, 0, flags); 
	else {
		// ������������ ������
		array<BYTE>^ data = Encoding::Unicode->GetBytes(value); 
		
		// ������� ����������� ������
		Array::Resize(data, data->Length + 2); data[data->Length - 2] = 0; 

		// ���������� ��������
		data[data->Length - 1] = 0; SetParam(param, data, flags); 
	}
}

void Aladdin::CAPI::CNG::Handle::SetLong(String^ param, DWORD value, DWORD flags)
{$
	// ���������� �������� ���������
	SetParam(param, IntPtr(&value), sizeof(value), flags); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ��������� �����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BHashHandle^ Aladdin::CAPI::CNG::BHashHandle::Duplicate(DWORD flags)
{$
	// �������� ������ ��� �������
	IntPtr pbObject = Marshal::AllocHGlobal(cbObj); BCRYPT_HASH_HANDLE hDup;
	try { 
		// ������� ����� ��������� �����������
		AE_CHECK_NTSTATUS(::BCryptDuplicateHash(Value, 
			&hDup, (PUCHAR)pbObject.ToPointer(), cbObj, flags
		)); 
		// ������� ����� ��������� �����������
		return gcnew BHashHandle(hDup, pbObject, cbObj); 
	}
	// ��� ������ ���������� ������
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

DWORD Aladdin::CAPI::CNG::BHashHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BHashHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BHashHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

void Aladdin::CAPI::CNG::BHashHandle::HashData(array<BYTE>^ data, int dataOff, int dataLen, DWORD flags)
{$
	// ���������� ���� ������
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(Value, ptrData, dataLen, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::BHashHandle::FinishHash(DWORD flags)
{$
	// ���������� ������ ���-��������
	DWORD cbHash = GetLong(BCRYPT_HASH_LENGTH, 0); 

	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cbHash); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(Value, ptrBuffer, cbHash, flags)); return buffer; 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::BSecretHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BSecretHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BSecretHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::BSecretHandle::DeriveKey(
	String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags)
{$
	// ���������� ��� ������������
	pin_ptr<CONST WCHAR> szKDF = PtrToStringChars(nameKDF); 

	// ������������� ��� ���������
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)params.ToPointer(); 

	// �������� ������ ��� �����
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// ��������� ������������ �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(Value, 
		szKDF, pParameters, ptrKey, keySize, &keySize, flags
	));
	// �������� ������ ������
	Array::Resize(key, keySize); return key; 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::NSecretHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NSecretHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NSecretHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// ���������� �������� �������
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NSecretHandle::DeriveKey(
	String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags)
{$
	// ���������� ��� ������������
	pin_ptr<CONST WCHAR> szKDF = PtrToStringChars(nameKDF); flags &= ~NCRYPT_SILENT_FLAG;

	// ������������� ��� ���������
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)params.ToPointer(); 

	// �������� ������ ��� �����
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// ��������� ������������ �����
	SECURITY_STATUS status = ::NCryptDeriveKey(Value, 
		szKDF, pParameters, ptrKey, keySize, &keySize, flags
	); 
	// �������� ������ ������
	AE_CHECK_WINERROR(status); Array::Resize(key, keySize); return key;
}

///////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BKeyHandle::Duplicate(DWORD flags)
{$
	BCRYPT_KEY_HANDLE hDup; 

	// �������� ������ ��� �������
	IntPtr pbObject = (cbObj != 0) ? Marshal::AllocHGlobal(cbObj) : IntPtr::Zero; 
	try { 
		// ������� ����� �����
		AE_CHECK_NTSTATUS(::BCryptDuplicateKey(Value, 
			&hDup, (PUCHAR)pbObject.ToPointer(), cbObj, flags
		)); 
		// ������� ����� �����
		return gcnew BKeyHandle(hDup, pbObject, cbObj); 
	}
	// ��� ������ ���������� ������
	catch(Exception^) { if (pbObject != IntPtr::Zero) Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BKeyHandle::ImportPublicKeyInfo(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, DWORD flags)
{$
	// �������� ���������� �����
	array<BYTE>^ encoded = publicKeyInfo->Encoded; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cb = 0; 
	
	// ���������� ������ �������� �����
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, 
		X509_PUBLIC_KEY_INFO, ptrEncoded, encoded->Length, 0, 0, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<UCHAR> pbDecoded(cb ? cb : 1); BCRYPT_KEY_HANDLE hKey = 0; 

	// �������� �������� �����
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, 
		X509_PUBLIC_KEY_INFO, ptrEncoded, encoded->Length, 0, &pbDecoded[0], &cb
	)); 
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptImportPublicKeyInfoEx2( 
		X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)&pbDecoded[0], flags, 0, &hKey)
	);
	// ������� �������� ����
	return gcnew BKeyHandle(hKey, IntPtr::Zero, 0);  
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BKeyHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Export(BKeyHandle^ hExportKey, String^ blobType, 
	DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// ���������� ��� ��������
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// ���������� ��������� �� �����
	PUCHAR pbBlob = (PUCHAR)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// ������� ��������� �����
	BCRYPT_KEY_HANDLE handle = (hExportKey != nullptr) ? hExportKey->Value : nullptr; 

	// �������������� ����
	AE_CHECK_NTSTATUS(::BCryptExportKey(
		Value, handle, szBlobType, pbBlob, cb, &cb, flags
	));
	return cb; 
}

#if _WIN32_WINNT >= 0x0602
array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::DeriveKey(DWORD keySize, IntPtr params, DWORD flags)
{$
	// ������������� ��� ���������
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)params.ToPointer(); 

	// �������� ������ ��� �����
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// ��������� ������������ �����
	AE_CHECK_CNG_RESULT(::BCryptKeyDerivation(Value, pParameters, ptrKey, keySize, &keySize, flags));

	// �������� ������ ������
	Array::Resize(key, keySize); return key; 
}
#endif

Aladdin::CAPI::CNG::BSecretHandle^ Aladdin::CAPI::CNG::BKeyHandle::AgreementSecret(
	BKeyHandle^ hPublicKey, DWORD flags)
{$
	BCRYPT_SECRET_HANDLE hSecret;

	// ������� ��������� �����
	BCRYPT_KEY_HANDLE handle = (hPublicKey != nullptr) ? hPublicKey->Value : nullptr; 

	// ��������� ������������ ������ �����
	AE_CHECK_NTSTATUS(::BCryptSecretAgreement(Value, handle, &hSecret, flags)); 

	// ������� ����������� ������
	return gcnew BSecretHandle(hSecret); 
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Encrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
	DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	DWORD cb = dataLen; 

	// �������� ����� ���������� �������
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 32); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 
	
	// ��� ���������� �������������
	if (iv == nullptr || iv->Length == 0)
	{
		// ����������� ������
		AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
			ptrData, cb, 0, nullptr, 0, ptrBuf, cb + 32, &cb, flags));
	}
	// �������� ����� �������������
	else { pin_ptr<BYTE> ptrIV = &iv[0]; 

		// ����������� ������
		AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
			ptrData, cb, 0, ptrIV, iv->Length, ptrBuf, cb + 32, &cb, flags));
	}
	// ����������� ������
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Decrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
	DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	DWORD cb = dataLen; 

	// �������� ����� ���������� �������
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// �������� ����� ������
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 
	
	// ��� ���������� �������������
	if (iv == nullptr || iv->Length == 0)
	{
		// ������������ ������
		AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
			ptrData, cb, 0, nullptr, 0, ptrBuf, cb, &cb, flags));
	}
	// �������� ����� �������������
	else { pin_ptr<BYTE> ptrIV = &iv[0]; 

		// ������������ ������
		AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
			ptrData, cb, 0, ptrIV, iv->Length, ptrBuf, cb, &cb, flags));
	}
	// ����������� ������
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ���������� ������ ���������� 
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0; 
	
	// �������� ����� ������
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// ���������� ������ ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, nullptr, 0, &cb, flags
	));
	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, ptrBuffer, cb, &cb, flags
	));
	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;
	
	// �������� ����� ������
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// ���������� ������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, nullptr, 0, &cb, flags
	));
	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, ptrBuffer, cb, &cb, flags
	));
	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags)
{$
	// ���������� ������ ���������� 
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0; 
	
	// �������� ����� ������
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// ���������� ������ ������
	AE_CHECK_NTSTATUS(::BCryptSignHash(Value, 
		pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags
	));
	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// ��������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptSignHash(Value, 
		pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags
	));
	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

void Aladdin::CAPI::CNG::BKeyHandle::VerifySignature(
	IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); DWORD cbSignature = signature->Length; 
	
	// �������� ����� ������
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// �������� ����� �������
	pin_ptr<BYTE> ptrSignature = (cbSignature > 0) ? &signature[0] : nullptr; 

	// ��������� ������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(Value, 
		pvPadding, ptrHash, hash->Length, ptrSignature, cbSignature, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::NKeyHandle::Finalize(DWORD flags)
{$
	// ��������� �������� ���� ������
	SECURITY_STATUS status = ::NCryptFinalizeKey(Value, flags); 

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// ��������� �������� ���� ������
		status = ::NCryptFinalizeKey(Value, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); 
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NKeyHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// ���������� �������� �������
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::Export(NKeyHandle^ hExportKey, 
	String^ blobType, DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// ���������� ��� ��������
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// ���������� ��������� �� �����
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// ������� ��������� �����
	NCRYPT_KEY_HANDLE handle = (hExportKey != nullptr) ? hExportKey->Value : 0; 

	// �������������� ����
	SECURITY_STATUS status = ::NCryptExportKey(Value, handle, szBlobType, 0, pbBlob, cb, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// �������������� �����
		flags &= ~NCRYPT_SILENT_FLAG; cb = cbBlob; 
		
        // �������������� ����
		status = ::NCryptExportKey(Value, handle, szBlobType, 0, pbBlob, cb, &cb, flags); 
	}
    // ��������� ���������� ������
    AE_CHECK_WINERROR(status); return cb;
}

#if _WIN32_WINNT >= 0x0602
array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::DeriveKey(DWORD keySize, IntPtr params, DWORD flags)
{$
	flags &= ~NCRYPT_SILENT_FLAG; 

	// ������������� ��� ���������
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)params.ToPointer(); 

	// �������� ������ ��� �����
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// ��������� ������������ �����
	SECURITY_STATUS status = ::NCryptKeyDerivation(
		Value, pParameters, ptrKey, keySize, &keySize, flags
	);
	// �������� ������ ������
    AE_CHECK_WINERROR(status); Array::Resize(key, keySize); return key;
}
#endif

Aladdin::CAPI::CNG::NSecretHandle^ Aladdin::CAPI::CNG::NKeyHandle::AgreementSecret(
	NKeyHandle^ hPublicKey, DWORD flags)
{$
	NCRYPT_SECRET_HANDLE hSecret;

	// ������� ��������� �����
	NCRYPT_KEY_HANDLE handle = (hPublicKey != nullptr) ? hPublicKey->Value : 0; 

	// ��������� ������������ ������ �����
	SECURITY_STATUS status = ::NCryptSecretAgreement(Value, handle, &hSecret, flags); 

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// ��������� ������������ �����
		status = ::NCryptSecretAgreement(Value, handle, &hSecret, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); return gcnew NSecretHandle(hSecret);
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// ���������� ����� ������
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// ���������� ������ ������
	SECURITY_STATUS status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // ���������� ������ ������
		status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags); 
	}
	// �������� ����� ���������� �������
	AE_CHECK_WINERROR(status); array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// ���������� ����� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// ����������� ������
	status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// �������������� �����
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // ����������� ������
		status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags); 
	}
	// �������� ������ ������
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// ���������� ����� ������
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// ���������� ������ ������
	SECURITY_STATUS status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // ���������� ������ ������
		status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags); 
	}
	// �������� ����� ���������� �������
	AE_CHECK_WINERROR(status); array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// ���������� ����� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// ������������ ������
	status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// �������������� �����
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // ������������ ������
		status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags); 
	}
	// �������� ������ ������
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// ���������� ����� ������
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// ���������� ������ ������
	SECURITY_STATUS status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags);

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // ���������� ������ ������
		status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags); 
	}
	// �������� ����� ���������� �������
	AE_CHECK_WINERROR(status); cb *= 2; array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// ���������� ����� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// ��������� ���-��������
	status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags); 

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// �������������� �����
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // ��������� ���-��������
		status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags); 
	}
	// �������� ������ ������
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

void Aladdin::CAPI::CNG::NKeyHandle::VerifySignature(
	IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags)
{$
	// ���������� ������ ����������
	PVOID pvPadding = padding.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 
	
	// �������� ����� ������
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// �������� ����� �������
	pin_ptr<BYTE> ptrSignature = (signature->Length > 0) ? &signature[0] : nullptr; 

	// ��������� ������� ���-��������
	AE_CHECK_WINERROR(::NCryptVerifySignature(Value, 
		pvPadding, ptrHash, hash->Length, ptrSignature, signature->Length, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ���������� ���������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BProviderHandle::BProviderHandle(String^ provider, String^ alg, DWORD flags)
{
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szAlg = PtrToStringChars(alg); BCRYPT_ALG_HANDLE hObject;

	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(provider); 

	// ������� ���������
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hObject, szAlg, szProvider, flags));

	// ���������� ���������
	SetHandle(IntPtr((PVOID)hObject)); 
}

DWORD Aladdin::CAPI::CNG::BProviderHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BProviderHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// ��������� ���������� ������
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BProviderHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

void Aladdin::CAPI::CNG::BProviderHandle::Generate(
	array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen, DWORD flags)
{$
	// �������� ����� ������
	pin_ptr<BYTE> ptrBuffer = (bufferLen > 0) ? &buffer[bufferOff] : nullptr; 

	// ������������� ������ � ������
	AE_CHECK_NTSTATUS(::BCryptGenRandom(Value, ptrBuffer, bufferLen, flags)); 
}

Aladdin::CAPI::CNG::BHashHandle^ Aladdin::CAPI::CNG::BProviderHandle::CreateHash(
	array<BYTE>^ key, DWORD flags)
{$
	// ���������� ������ �������
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); 
	
	// �������� ������ ��� �������
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); 
	try { 
		// ��� ���������� �����
		BCRYPT_HASH_HANDLE hHash; if (key == nullptr || key->Length == 0)
		{
			// ������� �������� �����������
			AE_CHECK_NTSTATUS(::BCryptCreateHash(Value, &hHash, 
				(PUCHAR)pbObject.ToPointer(), cbObject, nullptr, 0, flags
			)); 
		}
		// ���������� ����� ������
		else { pin_ptr<BYTE> ptrKey = &key[0]; 

			// ������� �������� ���������� ������������
			AE_CHECK_NTSTATUS(::BCryptCreateHash(Value, &hHash, 
				(PUCHAR)pbObject.ToPointer(), cbObject, ptrKey, key->Length, flags
			)); 
		}
		// ������� �������� �����������
		return gcnew BHashHandle(hHash, pbObject, cbObject);  
	}
	// ��� ������ ���������� ������
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::GenerateKey(DWORD flags)
{$
	// ���������� ������ �������
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); BYTE secret = 0;  
	
	// �������� ������ ��� �������
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); BCRYPT_KEY_HANDLE hKey; 
	try { 
		// ������� ���� ����������
		AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(Value, 
			&hKey, (PUCHAR)pbObject.ToPointer(), cbObject, &secret, 0, flags
		)); 
		// ������� ���� ����������
		return gcnew BKeyHandle(hKey, pbObject, cbObject);  
	}
	// ��� ������ ���������� ������
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::ImportKey(
	BKeyHandle^ hImportKey, String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags)
{$
	// ���������� ��� �������
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// ���������� ��������� �� �����
	PUCHAR pbData = (PUCHAR)ptrData.ToPointer(); BCRYPT_KEY_HANDLE hKey;

	// ���������� ������ �������
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); 
	
	// �������� ������ ��� �������
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); 

	// ������� ��������� �����
	BCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : nullptr; 
	try { 
		// ������������� ����
		AE_CHECK_NTSTATUS(::BCryptImportKey(Value, handle, szBlobType, 
			&hKey, (PUCHAR)pbObject.ToPointer(), cbObject, pbData, cbData, flags
		)); 
		// ������� ��������������� ����
		return gcnew BKeyHandle(hKey, pbObject, cbObject); 
	}
	// ��� ������ ���������� ������
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::CreateKeyPair(
	DWORD length, DWORD flags)
{$
	BCRYPT_KEY_HANDLE hKeyPair; 

	// ������ �������� ���� ������
	AE_CHECK_NTSTATUS(::BCryptGenerateKeyPair(Value, &hKeyPair, length, flags)); 

	// ������� ������ ���� ������
	return gcnew BKeyHandle(hKeyPair, IntPtr::Zero, 0);  
}

void Aladdin::CAPI::CNG::BProviderHandle::FinalizeKeyPair(BKeyHandle^ hKeyPair, DWORD flags)
{$
	// ��������� �������� ���� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair->Value, flags));
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::ImportKeyPair(
	BKeyHandle^ hImportKey, String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags)
{$
	BCRYPT_KEY_HANDLE hKeyPair;

	// ���������� ��� �������
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// ���������� ��������� �� �����
	PUCHAR pbData = (PUCHAR)ptrData.ToPointer();

	// ������� ��������� �����
	BCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : nullptr; 

	// ������������� �������� ����
	AE_CHECK_NTSTATUS(::BCryptImportKeyPair(Value, handle, 
		szBlobType, &hKeyPair, pbData, cbData, flags
	)); 
	// ������� �������� ����
	return gcnew BKeyHandle(hKeyPair, IntPtr::Zero, 0); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ���������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NProviderHandle::NProviderHandle(String^ name, DWORD flags)
{
	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); NCRYPT_PROV_HANDLE hObject;

	// ������� ���������
	AE_CHECK_WINERROR(::NCryptOpenStorageProvider(&hObject, szName, flags));

	// ���������� ���������
	SetHandle(IntPtr((PVOID)hObject)); 
}

DWORD Aladdin::CAPI::CNG::NProviderHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NProviderHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// �������� ��������
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NProviderHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// ���������� �������� �������
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<String^>^ Aladdin::CAPI::CNG::NProviderHandle::EnumerateAlgorithms(DWORD type, DWORD flags)
{$
	// ���������������� ����������
	NCryptAlgorithmName* pInfo = 0; DWORD count = 0; flags &= ~NCRYPT_SILENT_FLAG; 

	// ����������� ���������
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(Value, type, &count, &pInfo, flags);  

	// �������� ������ ��� ����
	AE_CHECK_WINERROR(status); array<String^>^ algs = gcnew array<String^>(count); 

	// ��������� ����� ���������
	for (DWORD i = 0; i < count; i++) algs[i] = gcnew String(pInfo[i].pszName); 

	// ���������� ���������� ������
	if (pInfo != NULL) ::NCryptFreeBuffer(pInfo); return algs; 
}

array<String^>^ Aladdin::CAPI::CNG::NProviderHandle::EnumerateKeys(String^ scope, DWORD flags)
{$
	// ������� ������ ���� ������
	List<String^>^ list = gcnew List<String^>(); NCryptKeyName* pInfo = 0; PVOID pState = 0;

	// ������������� ���
	pin_ptr<CONST WCHAR> szScope = PtrToStringChars(scope); flags &= ~NCRYPT_SILENT_FLAG; 

	// �������� �������� ������� �����
	SECURITY_STATUS status = ::NCryptEnumKeys(Value, szScope, &pInfo, &pState, flags); 
	
	// �� ���������� ������������
	while (status == ERROR_SUCCESS) 
	{
		// ���������� ��� �����
		String^ name = gcnew String(pInfo->pszName); if (!list->Contains(name)) list->Add(name);

		// �������� �������� ���������� �����
		status = ::NCryptEnumKeys(Value, szScope, &pInfo, &pState, flags); 
	}
	// ���������� ���������� ������
	if (pInfo != NULL) ::NCryptFreeBuffer(pInfo); if (pState != NULL) ::NCryptFreeBuffer(pState); 

	// ������� ������ ����
	return list->ToArray();
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::StartCreateKey(
	String^ name, String^ algID, DWORD keyType, DWORD flags)
{$
	// ��������������� ��� ����� /* TODO */
	NCRYPT_KEY_HANDLE hKey; if (algID != "RSA") keyType = 0; 

	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szAlg = PtrToStringChars(algID); 

    // ���������� ��� �����
    pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); 
	
	// ������� ����
	AE_CHECK_WINERROR(::NCryptCreatePersistedKey(Value, &hKey, szAlg, szName, keyType, flags)); 

	// ������� ��������� ����
	return gcnew NKeyHandle(hKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::OpenKey(
	String^ name, DWORD keyType, DWORD flags)
{$
	// ���������� ��� �����
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); NCRYPT_KEY_HANDLE hKey; 

	// �������� ���� /* TODO */
	SECURITY_STATUS status = ::NCryptOpenKey(Value, &hKey, szName, 0 /*keyType*/, flags); 

	// ��� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) 
	{
		// ��������� ������� �����
		return (SUCCEEDED(status)) ? gcnew NKeyHandle(hKey) : nullptr; 
	}
	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// �������� ���� /* TODO */
		status = ::NCryptOpenKey(Value, &hKey, szName, 0 /*keyType*/, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// ��������� ������� �����
	return (SUCCEEDED(status)) ? gcnew NKeyHandle(hKey) : nullptr; 
}

void Aladdin::CAPI::CNG::NProviderHandle::DeleteKey(NKeyHandle^ hKeyPair, DWORD flags)
{$
	// ������� ����
	SECURITY_STATUS status = ::NCryptDeleteKey(hKeyPair->Value, flags); 

	// ���������� ������� ����������������� ����������
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// ��������� ��� ������
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
        // ������� ����
		status = ::NCryptDeleteKey(hKeyPair->Value, flags & ~NCRYPT_SILENT_FLAG);
	}
	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); hKeyPair->SetHandleAsInvalid();
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::ImportPublicKey(
	String^ blobType, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	// ���������� ��� �������
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); NCRYPT_KEY_HANDLE hKey;
	
	// �������� ��������� �� �����
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// ������������� ����
	SECURITY_STATUS status = ::NCryptImportKey(Value, 0, szBlobType, 0, &hKey, pbBlob, cbBlob, flags); 

	// ��������� ���������� ������
	AE_CHECK_WINERROR(status); return gcnew NKeyHandle(hKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::StartImportKeyPair(
	String^ name, NKeyHandle^ hImportKey, String^ blobType, IntPtr ptrBlob, 
    DWORD cbBlob, DWORD flags)
{$
	NCRYPT_KEY_HANDLE hKey; 

	// ������������� ��� �����
	pin_ptr<CONST WCHAR> szName     = PtrToStringChars(name    ); 
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType);

	// ���������� ��������� �� �����
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); flags |= NCRYPT_DO_NOT_FINALIZE_FLAG; 

	// ������� �������� ��� �����
	NCryptBuffer param = { 0, NCRYPTBUFFER_PKCS_KEY_NAME, nullptr }; 

	// ������� ������ ����������
    NCryptBufferDesc params = { NCRYPTBUFFER_VERSION, 1, &param }; 

    // ��� �������� ����� �����
    NCryptBufferDesc* ptr = nullptr; if (name != nullptr) 
    { 
        // ������� ��� �����
        param.pvBuffer = (PVOID)(PCWSTR)szName; ptr = &params; 

		// ���������� ������ ������ � ������
        param.cbBuffer = (name->Length + 1) * sizeof(wchar_t); 
    }
	// ������� ��������� �����
	NCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : 0; 

	// ������������� ����
	SECURITY_STATUS status = ::NCryptImportKey(
		Value, handle, szBlobType, ptr, &hKey, pbBlob, cbBlob, flags
	); 
	// ������� ��������� ����
	AE_CHECK_WINERROR(status); return gcnew NKeyHandle(hKey); 
}

