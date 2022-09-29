#include "pch.h"
#include "scard.h"
#include "csp.h"
#include "ncng.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "scard.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// ����� ������ �� ������������
///////////////////////////////////////////////////////////////////////
struct ReaderSessionDeleter { void operator()(Windows::PCSC::ReaderSession* pSession)
{
    // ������� ����� �� ������������ � ������� ������
    ::SCardDisconnect(*pSession, SCARD_LEAVE_CARD); delete pSession; 
}};

std::vector<std::wstring> Windows::PCSC::ReaderSession::GetReaderNames() const
{
    // ���������� ��������� ������ ������ 
    DWORD cchNames = 0; AE_CHECK_HRESULT(::SCardStatusW(_hCard, 
        nullptr, &cchNames, nullptr, nullptr, nullptr, nullptr
    ));
    // ��������� ������� ����
    if (cchNames == 0) return std::vector<std::wstring>(); 

    // �������� ����� ���������� ������� 
    std::vector<std::wstring> names; std::wstring strNames(cchNames, 0); 

    // �������� ���������� ����� ������������
    AE_CHECK_HRESULT(::SCardStatusW(_hCard, 
        &strNames[0], &cchNames, nullptr, nullptr, nullptr, nullptr
    ));
    // ��� ���� ���������� ���� ������������
    for (PCWSTR szName = strNames.c_str(); *szName; szName += wcslen(szName) + 1)
    {
        // ��������� ��� � ������
        names.push_back(szName); 
    }
    return names; 
}

std::vector<BYTE> Windows::PCSC::ReaderSession::GetAttribute(DWORD attrID) const
{
    // ���������� ��������� ������ ������
    DWORD cb = 0; AE_CHECK_HRESULT(::SCardGetAttrib(_hCard, attrID, nullptr, &cb));

    // �������� ����� ���������� �������
    std::vector<BYTE> attr(cb, 0); if (cb == 0) return attr; 

    // �������� ������� �����������
    AE_CHECK_HRESULT(::SCardGetAttrib(_hCard, attrID, &attr[0], &cb));

    // �������� ������ ��������
    attr.resize(cb); return attr; 
}

void Windows::PCSC::ReaderSession::Lock()
{
    // ������ ���������� �� �����-������
    AE_CHECK_HRESULT(::SCardBeginTransaction(_hCard));
}

    // �������������� �����-�����
void Windows::PCSC::ReaderSession::Unlock()
{
    // ��������� ���������� �� �����-������
    AE_CHECK_HRESULT(::SCardEndTransaction(_hCard, SCARD_LEAVE_CARD));
}

std::vector<BYTE> Windows::PCSC::ReaderSession::SendControl(DWORD code, LPCVOID pvData, DWORD cbData)
{
    // �������� ����� ���������� �������
    DWORD cb = 32768; std::vector<BYTE> outBuffer(cb); 

    // �������� ������� �����������
    AE_CHECK_HRESULT(::SCardControl(_hCard, code, pvData, cbData, &outBuffer[0], cb, &cb));

    // �������� ������ ������
    outBuffer.resize(cb); return outBuffer; 
}

// ��������� ������� �����-�����
std::vector<BYTE> Windows::PCSC::ReaderSession::SendCommand(LPCVOID pvData, DWORD cbData)
{
    // ������� ������������ ��������
    SCARD_IO_REQUEST request = { _protocol, sizeof(request) }; 
            
    // �������� ����� ���������� �������
    DWORD cb = 32768; std::vector<BYTE> recvBuffer(cb); 

    // �������� ������� �����-�����
    AE_CHECK_HRESULT(::SCardTransmit(_hCard, 
        &request, (LPCBYTE)pvData, cbData, &request, &recvBuffer[0], &cb
    ));
    // �������� ������ ������
    recvBuffer.resize(cb); return recvBuffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
GUID Windows::PCSC::CardType::GetPrimaryInterface() const 
{ 
    // �������� ������������� ���������� ����������
    GUID guid = GUID_NULL; AE_CHECK_HRESULT(
        ::SCardGetProviderIdW(_hContext, _name.c_str(), &guid
    )); 
    return guid; 
} 

std::vector<GUID> Windows::PCSC::CardType::GetInterfaces() const
{
    // �������� ��������� ����� �����������
    DWORD cGuids = 0; LONG code = ::SCardListInterfacesW(_hContext, _name.c_str(), nullptr, &cGuids); 

    // ��������� ��� ������
    if (code == SCARD_E_UNKNOWN_CARD) AE_CHECK_HRESULT(code); 

    // ��������� ���������� ������
    if (code != SCARD_S_SUCCESS) return std::vector<GUID>(); 

    // ������� ������ �����������
    std::vector<GUID> guids(cGuids, GUID_NULL); if (cGuids == 0) return guids; 

    // ��������� ������ ����������� 
    AE_CHECK_HRESULT(::SCardListInterfacesW(_hContext, _name.c_str(), &guids[0], &cGuids)); 

    // ������� �������������� ����� �����������
    guids.resize(cGuids); return guids; 
}

std::wstring Windows::PCSC::CardType::GetCryptoProvider(DWORD providerID) const
{
    // ������� ������� ��������������� ��������� ������
    PWSTR szProvider = nullptr; DWORD cchProvider = SCARD_AUTOALLOCATE; 

    // �������� ��� ���������� 
    LONG code = ::SCardGetCardTypeProviderNameW(
        _hContext, _name.c_str(), providerID, (PWSTR)&szProvider, &cchProvider
    ); 
    // ��������� ��� ������
    if (code == SCARD_E_UNKNOWN_CARD) AE_CHECK_HRESULT(code); 

    // ��������� ���������� ������
    if (code != SCARD_S_SUCCESS) return std::wstring(); 

    // ��������� ��� ���������� 
    std::wstring provider(szProvider); 
    
    // ���������� ���������� �������
    ::SCardFreeMemory(_hContext, szProvider); return provider; 
}

void Windows::PCSC::CardType::SetCryptoProvider(DWORD providerID, PCWSTR szProvider)
{
    // ���������� ��� ���������� 
    AE_CHECK_HRESULT(::SCardSetCardTypeProviderNameW(
        _hContext, _name.c_str(), providerID, szProvider
    )); 
}

///////////////////////////////////////////////////////////////////////////////
// �����-����� 
///////////////////////////////////////////////////////////////////////////////
Windows::PCSC::Card::Card(SCARDCONTEXT hContext, PCWSTR szReader)

    // ��������� ���������� ���������
    : _hContext(hContext), _reader(hContext, szReader) 
{
    // ������� ����� �������� ������
    DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

    // ��������� ������� �����-�����
    std::shared_ptr<ReaderSession> pSession = _reader.CreateSession(openMode, protocols); 

    // �������� ATR �����-�����
    _atr = pSession->ATR(); 
}

std::vector<std::wstring> Windows::PCSC::Card::EnumCardTypes(LPCGUID pGuids, DWORD cGuids) const
{
    // ������� ������� ��������������� ��������� ������
    std::vector<std::wstring> cardTypes; PWSTR szCardTypes = nullptr; DWORD cchCards = SCARD_AUTOALLOCATE; 

    // ����������� ���� �����-����
    AE_CHECK_HRESULT(::SCardListCardsW(_hContext, &_atr[0], pGuids, cGuids, (PWSTR)&szCardTypes, &cchCards)); 

    // ��� ���� ����� �����-����
    for (PCWSTR szCardType = szCardTypes; *szCardType; szCardType += wcslen(szCardType) + 1)
    {
        // �������� ��� �����-�����
        cardTypes.push_back(szCardType); 
    }
    // ���������� ���������� ������
    ::SCardFreeMemory(_hContext, szCardTypes); return cardTypes; 
}

DWORD Windows::PCSC::Card::GetState() const
{
    // ���������������� ���������
    SCARD_READERSTATE state = { _reader.Name(), nullptr }; 

    // ������� ����������� ���������
    state.dwCurrentState = SCARD_STATE_UNAWARE; state.dwEventState = SCARD_STATE_UNAWARE;  

    // �������� ���������� � ��������� ������������
    LONG code = ::SCardGetStatusChangeW(_hContext, 0, &state, 1); 

     // ��������� ���������� ������
     if (code != SCARD_S_SUCCESS) return SCARD_STATE_EMPTY; 

     // ��������� ��������� �����������
     if ((state.dwEventState & SCARD_STATE_MUTE     ) != 0) return SCARD_STATE_MUTE; 
     if ((state.dwEventState & SCARD_STATE_EXCLUSIVE) != 0) return SCARD_STATE_EXCLUSIVE; 
     if ((state.dwEventState & SCARD_STATE_INUSE    ) != 0) return SCARD_STATE_INUSE; 
     if ((state.dwEventState & SCARD_STATE_PRESENT  ) != 0) return SCARD_STATE_PRESENT; 

     // ��������� ����������
     return SCARD_STATE_EMPTY; 
}

GUID Windows::PCSC::Card::GetGUID() const
{
    // �������� ����������������� ���������
    std::shared_ptr<Crypto::IProvider> pProvider = GetProvider(SCARD_PROVIDER_CSP); 

    // ��������� ������� ����������
    if (!pProvider) return GUID_NULL; 

    // ������� GUID �����-�����
    return ((const Crypto::CSP::CardProvider*)pProvider.get())->GetCardGUID(); 
}

std::shared_ptr<Windows::Crypto::IProvider> 
Windows::PCSC::Card::GetProvider(DWORD providerID) const
{
    // ����������� ���� �����-�����
    std::vector<std::wstring> cardTypes = EnumCardTypes(nullptr, 0); 

    // ��� ���� ����� �����-����
    for (size_t i = 0; i < cardTypes.size(); i++)
    {
        // �������� ��� �����-�����
        std::shared_ptr<CardType> pCardType = GetCardType(cardTypes[i].c_str()); 

        // �������� ��� ����������
        std::wstring providerName = pCardType->GetCryptoProvider(providerID); 

        // ��������� ������� �����
        if (providerName.length() == 0) continue; switch (providerID)
        {
        case SCARD_PROVIDER_CSP: {

            // ������� ������ ���������� 
            return std::shared_ptr<Crypto::IProvider>(
                new Crypto::CSP::CardProvider(providerName.c_str(), _reader.Name())
            ); 
        }
        case SCARD_PROVIDER_KSP: {

            // ������� �����������
            std::wstring reader = L"\\\\.\\" + std::wstring(_reader.Name()) + L"\\"; 

            // ������� ������ ���������� 
            return std::shared_ptr<Crypto::IProvider>(
                new Crypto::NCrypt::Provider(providerName.c_str(), reader.c_str(), 0)
            ); 
        }}
    }
    return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// ����������� �����-����
///////////////////////////////////////////////////////////////////////////
DWORD Windows::PCSC::Reader::GetState() const
{
    // ���������������� ���������
    SCARD_READERSTATE state = { _name.c_str(), nullptr }; 

    // ������� ����������� ���������
    state.dwCurrentState = SCARD_STATE_UNAWARE; state.dwEventState = SCARD_STATE_UNAWARE;  

    // �������� ���������� � ��������� ������������
    LONG code = ::SCardGetStatusChangeW(_hContext, 0, &state, 1); 

     // ��������� ���������� ������
     if (code != SCARD_S_SUCCESS) return SCARD_STATE_UNAVAILABLE; 

     // ��������� ��������� �����������
     if ((state.dwEventState & SCARD_STATE_PRESENT) != 0) return SCARD_STATE_PRESENT; 
     if ((state.dwEventState & SCARD_STATE_EMPTY  ) != 0) return SCARD_STATE_EMPTY; 
     if ((state.dwEventState & SCARD_STATE_UNKNOWN) != 0) return SCARD_STATE_UNKNOWN; 

     // ��������� ����������
     return SCARD_STATE_UNAVAILABLE; 
}

std::shared_ptr<Windows::PCSC::Card> Windows::PCSC::Reader::OpenCard()
{
    // ������� ����� �������� ������
    DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

    // ��������� ������� �����-�����
    std::shared_ptr<ReaderSession> pSession = CreateSession(openMode, protocols); 
        
    // ������� �����-�����
    return std::shared_ptr<Card>(new Card(_hContext, _name.c_str(), pSession->ATR())); 
}

std::shared_ptr<Windows::PCSC::ReaderSession>
Windows::PCSC::Reader::CreateSession(DWORD openMode, DWORD protocols) const 
{
    // ������� ����� �� ������������
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(
        ::SCardConnectW(_hContext, _name.c_str(), openMode, protocols, &hCard, &protocols)
    ); 
    // ������� ������ ������
    return std::shared_ptr<ReaderSession>(
        new ReaderSession(hCard, protocols), ReaderSessionDeleter()
    ); 
}

void Windows::PCSC::Reader::EjectCard() 
{
    // ������� ����� �������� ������
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // ������� ����� �� ������������
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // ������� �����-�����
    ::SCardDisconnect(hCard, SCARD_EJECT_CARD); 
}

void Windows::PCSC::Reader::ResetCard()
{
    // ������� ����� �������� ������
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // ������� ����� �� ������������
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // ������������� �����-�����
    ::SCardDisconnect(hCard, SCARD_RESET_CARD); 
}

void Windows::PCSC::Reader::ShutdownCard()
{
    // ������� ����� �������� ������
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // ������� ����� �� ������������
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // ������������� �����-�����
    ::SCardDisconnect(hCard, SCARD_UNPOWER_CARD); 
}

