#pragma once
#include <vector>
#include "crypto.h"

namespace Windows {

///////////////////////////////////////////////////////////////////////////////
// ����������������� �����������. ��� hexType ����� ��������� ��������: 
// 1) CRYPT_STRING_HEXRAW - ����������������� ����������� ��� ������������ � 
//    ����������� ��������� ������ (�� �������������� �� Windows Vista); 
// 2) CRYPT_STRING_HEX - ����������������� ����������� � ����������� ������ 
//    ��������� � ����������� ��������� ������ � ���������� �� ������. ��� 
//    ���� ������ ������ �������� �������� �� ����� 16 ������; 
// 3) CRYPT_STRING_HEXASCII - ����������������� ����������� � ����������� ������ 
//    ��������� � ����������� ��������� ������ � ���������� �� ������. ��� 
//    ���� ����� ������ ������ �������� �������� �� ����� 16 ������, � ������ - 
//    ��������������� ������ ASCII-������� (��� � ���� Memory Visual Studio);  
// 4) CRYPT_STRING_HEXADDR - ����������������� ����������� � ����������� ������ 
//    ��������� � ����������� ��������� ������ � ���������� �� ������. ��� 
//    ���� ����� ������ ������ �������� ����������������� 2-�������� ��������, 
//    � ������ - �������� �� ����� 16 ������ (��� � ���� Memory Visual Studio); 
// 5) CRYPT_STRING_HEXASCIIADDR - ����������������� ����������� � ����������� 
//    ������ ��������� � ����������� ��������� ������ � ���������� �� ������. 
//    ��� ���� ����� ������ ������ �������� ����������������� 2-�������� 
//    ��������, �� ������ - �������� �� ����� 16 ������, � ������ - 
//    ��������������� ������ ASCII-������� (��� � ���� Memory Visual Studio). 
// 
// ������� ������ ������� �� �������� CR LF. ������������� ����� 
// CRYPT_STRING_NOCR ���������� ������������ ��� �������� ������ ������ 
// ������ LF. ������������� ����� CRYPT_STRING_NOCRLF (�� �������������� 
// �� Windows Vista) �������� � ����, ��� ������� ������ ������ �� 
// ������������ (�� ����� ������ ��� ����� CRYPT_STRING_HEXASCII, 
// CRYPT_STRING_HEXADDR � CRYPT_STRING_HEXASCIIADDR). 
///////////////////////////////////////////////////////////////////////////////

// ������������ ������
template <typename T> std::basic_string<T> EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 
// ������������ ������
template <> WINCRYPT_CALL std::string  EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 
template <> WINCRYPT_CALL std::wstring EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 

// ������������� ������
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCSTR  szEncoded, DWORD hexType); 
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCWSTR szEncoded, DWORD hexType); 

// ������������� ������
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCSTR  szEncoded, PDWORD pHexType = nullptr); 
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCWSTR szEncoded, PDWORD pHexType = nullptr); 

///////////////////////////////////////////////////////////////////////////////
// ����������� Base-64. ��� headerType ����� ��������� ��������:
// 1) CRYPT_STRING_BASE64 - ����������� Base-64 ��� ���������� � ������������ 
//    � ����������� ��������� ������; 
// 2) CRYPT_STRING_BASE64HEADER - ����������� Base-64 � ���������� BEGIN 
//    CERTIFICATE � ������������ END CERTIFICATE � ����������� ��������� 
//    ������ � ���������� �� ������. ��� ���� ������ ������ �������� �� ����� 
//    76 ��������; 
// 3) CRYPT_STRING_BASE64REQUESTHEADER - ����������� Base-64 � ���������� 
//    BEGIN NEW CERTIFICATE REQUEST � ������������ END NEW CERTIFICATE REQUEST 
//    � ����������� ��������� ������ � ���������� �� ������. ��� ���� ������ 
//    ������ �������� �� ����� 76 ��������; 
// 4) CRYPT_STRING_BASE64X509CRLHEADER - ����������� Base-64 � ���������� 
//    BEGIN X509 CRL � ������������ BEGIN X509 CRL � ����������� ��������� 
//    ������ � ���������� �� ������. ��� ���� ������ ������ �������� �� ����� 
//    76 ��������; 
// 
// ������� ������ ������� �� �������� CR LF. ������������� ����� 
// CRYPT_STRING_NOCR ���������� ������������ ��� �������� ������ ������ 
// ������ LF. ������������� ����� CRYPT_STRING_NOCRLF (�� �������������� 
// �� Windows Vista) �������� � ����, ��� ������� ������ ������ �� 
// ������������ (�� ����� ������ ��� ����� CRYPT_STRING_HEXASCII, 
// CRYPT_STRING_HEXADDR � CRYPT_STRING_HEXASCIIADDR). 
///////////////////////////////////////////////////////////////////////////////

// ������������ ������
template <typename T> std::basic_string<T> EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 
// ������������ ������
template <> WINCRYPT_CALL std::string  EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 
template <> WINCRYPT_CALL std::wstring EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 

// ������������� ������
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCSTR  szEncoded, BOOL hasHeader); 
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCWSTR szEncoded, BOOL hasHeader); 

// ������������� ������
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCSTR  szEncoded, PDWORD pHeaderType = nullptr); 
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCWSTR szEncoded, PDWORD pHeaderType = nullptr); 

// ������������� ������
WINCRYPT_CALL std::vector<BYTE> DecodeBase64OrAsn1(LPCVOID pvEncoded, DWORD cbEncoded, PDWORD pType = nullptr); 
}
