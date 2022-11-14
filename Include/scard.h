#pragma once
#include <winscard.h>
#include "crypto.h"

namespace Windows { namespace PCSC {

///////////////////////////////////////////////////////////////////////
// ����� ������ �� ������������
///////////////////////////////////////////////////////////////////////
class ReaderSession  
{
	// ��������� ������, ������������ �������� � ATR �����-�����
    private: SCARDHANDLE _hCard; DWORD _protocol; std::vector<BYTE> _atr; 

	// ����������� 
    public: ReaderSession(SCARDHANDLE hCard, DWORD protocol)

        // ��������� ���������� ��������� 
        : _hCard(hCard), _protocol(protocol)
    {
        // �������� ATR �����-�����
        _atr = GetAttribute(SCARD_ATTR_ATR_STRING); 
    }
    // �������� �������������� ����
    public: operator SCARDHANDLE() const { return _hCard; }

    // ATR �����-�����
    public: const std::vector<BYTE>& ATR() const { return _atr; }
    // ������������ ��������
    public: DWORD Protocol() const { return _protocol; }

    // �������� ���������� ����� �����������
    public: std::vector<std::wstring> GetReaderNames() const; 

    // �������� ������� �����������/�����-�����
    public: std::vector<BYTE> GetAttribute(DWORD attrID) const; 

    // �������������/�������������� �����-�����
    public: void Lock(); void Unlock(); 

    // ��������� ������� �����������
    public: std::vector<BYTE> SendControl(DWORD code, LPCVOID pvData, DWORD cbData); 
    // ��������� ������� �����-�����
    public: std::vector<BYTE> SendCommand(LPCVOID pvData, DWORD cbData); 
}; 

///////////////////////////////////////////////////////////////////////////
// ����������� �����-����
///////////////////////////////////////////////////////////////////////////
class Reader
{
    // �������� ���������� � ���������� ��� ����������� 
    private: SCARDCONTEXT _hContext; std::wstring _name;

    // �����������
    public: Reader(SCARDCONTEXT hContext, PCWSTR szName) 

        // ��������� ���������� ��������� 
        : _hContext(hContext), _name(szName) {}

    // �������� ���������� ����� �����������
    public: std::vector<std::wstring> GetReaderNames() const
    {
        // ������� ����� �������� ������
        DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

        // ������� ����� ������ �� �����-������
        std::shared_ptr<ReaderSession> pSession = CreateSession(openMode, protocols); 

        // �������� ���������� ����� �����������
        return pSession->GetReaderNames(); 
    }
    // ���������� ��� �����������
    public: PCWSTR Name() const { return _name.c_str(); } 

    // ��������� � �����-����� �����������
    public: DWORD GetState() const; std::shared_ptr<class Card> OpenCard(); 

    // ������� ����� ������ �� �����-������
    public: std::shared_ptr<ReaderSession> CreateSession(DWORD openMode, DWORD protocols) const; 

    // �������� �� �����-�������
    public: void EjectCard   (); // ������� �����-�����
    public: void ResetCard   (); // ������������� �����-�����
    public: void ShutdownCard(); // ��������� �����-�����
};

///////////////////////////////////////////////////////////////////////////////
// ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
class CardType 
{ 
    // �������� ���������� � ��� ����
    private: SCARDCONTEXT _hContext; std::wstring _name; 

    // �����������
    public: CardType(SCARDCONTEXT hContext, PCWSTR szCardName) 

        // ��������� ���������� ��������� 
        : _hContext(hContext), _name(szCardName) {}

    // ��� ���� �����-�����
    public: PCWSTR Name() const { return _name.c_str(); } 

    // ������������� ���������� ����������
    public: GUID GetPrimaryInterface() const; 
    // �������������� �����������
    public: std::vector<GUID> GetInterfaces() const; 

    // �������� ��� ����������
    public: std::wstring GetCryptoProvider(DWORD providerID) const;  
    // ���������� ��� ����������
    public: void SetCryptoProvider(DWORD providerID, PCWSTR szProvider); 
}; 

///////////////////////////////////////////////////////////////////////////////
// �����-����� 
///////////////////////////////////////////////////////////////////////////////
class Card 
{ 
    // �������� ���������� � ���������� ��� ����������� 
    private: SCARDCONTEXT _hContext; Reader _reader; std::vector<BYTE> _atr; 

    // �����������
    public: Card(SCARDCONTEXT hContext, PCWSTR szReader, const std::vector<BYTE>& atr)

        // ��������� ���������� ���������
        : _hContext(hContext), _reader(hContext, szReader), _atr(atr) {}

    // �����������
    public: Card(SCARDCONTEXT hContext, PCWSTR szReader); 

    // ������������ �����������
    public: const Reader& Reader() const { return _reader; }
    // ATR �����-�����
    public: const std::vector<BYTE>& ATR() const { return _atr; }

    // ����� ����� �����-�����
    public: std::vector<std::wstring> EnumCardTypes(LPCGUID pGuids, DWORD cGuids) const; 
    // �������� ��� �����-�����
    public: std::shared_ptr<CardType> GetCardType(PCWSTR szCartType) const
    {
        // �������� ��� �����-�����
        return std::shared_ptr<CardType>(new CardType(_hContext, szCartType)); 
    }
    // ��������� � GUID �����-����� 
    public: DWORD GetState() const; GUID GetGUID() const;

	// ����������������� ���������
    public: std::shared_ptr<Crypto::ICardStore> GetProvider(DWORD providerID) const; 
};
}}
