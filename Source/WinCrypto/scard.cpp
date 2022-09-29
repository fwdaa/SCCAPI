#include "pch.h"
#include "scard.h"
#include "csp.h"
#include "ncng.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "scard.tmh"
#endif 

///////////////////////////////////////////////////////////////////////
// Сеанс работы со считывателем
///////////////////////////////////////////////////////////////////////
struct ReaderSessionDeleter { void operator()(Windows::PCSC::ReaderSession* pSession)
{
    // закрыть сеанс со считывателем и удалить объект
    ::SCardDisconnect(*pSession, SCARD_LEAVE_CARD); delete pSession; 
}};

std::vector<std::wstring> Windows::PCSC::ReaderSession::GetReaderNames() const
{
    // определить требуемый размер буфера 
    DWORD cchNames = 0; AE_CHECK_HRESULT(::SCardStatusW(_hCard, 
        nullptr, &cchNames, nullptr, nullptr, nullptr, nullptr
    ));
    // проверить наличие имен
    if (cchNames == 0) return std::vector<std::wstring>(); 

    // выделить буфер требуемого размера 
    std::vector<std::wstring> names; std::wstring strNames(cchNames, 0); 

    // получить логические имена считывателей
    AE_CHECK_HRESULT(::SCardStatusW(_hCard, 
        &strNames[0], &cchNames, nullptr, nullptr, nullptr, nullptr
    ));
    // для всех логических имен считывателей
    for (PCWSTR szName = strNames.c_str(); *szName; szName += wcslen(szName) + 1)
    {
        // сохранить имя в список
        names.push_back(szName); 
    }
    return names; 
}

std::vector<BYTE> Windows::PCSC::ReaderSession::GetAttribute(DWORD attrID) const
{
    // определить требуемый размер буфера
    DWORD cb = 0; AE_CHECK_HRESULT(::SCardGetAttrib(_hCard, attrID, nullptr, &cb));

    // выделить буфер требуемого размера
    std::vector<BYTE> attr(cb, 0); if (cb == 0) return attr; 

    // получить атрибут считывателя
    AE_CHECK_HRESULT(::SCardGetAttrib(_hCard, attrID, &attr[0], &cb));

    // изменить размер атрибута
    attr.resize(cb); return attr; 
}

void Windows::PCSC::ReaderSession::Lock()
{
    // начать транзакцию со смарт-картой
    AE_CHECK_HRESULT(::SCardBeginTransaction(_hCard));
}

    // разблокировать смарт-карту
void Windows::PCSC::ReaderSession::Unlock()
{
    // завершить транзакцию со смарт-картой
    AE_CHECK_HRESULT(::SCardEndTransaction(_hCard, SCARD_LEAVE_CARD));
}

std::vector<BYTE> Windows::PCSC::ReaderSession::SendControl(DWORD code, LPCVOID pvData, DWORD cbData)
{
    // выделить буфер требуемого размера
    DWORD cb = 32768; std::vector<BYTE> outBuffer(cb); 

    // передать команду считывателю
    AE_CHECK_HRESULT(::SCardControl(_hCard, code, pvData, cbData, &outBuffer[0], cb, &cb));

    // изменить размер буфера
    outBuffer.resize(cb); return outBuffer; 
}

// отправить команду смарт-карте
std::vector<BYTE> Windows::PCSC::ReaderSession::SendCommand(LPCVOID pvData, DWORD cbData)
{
    // указать используемый протокол
    SCARD_IO_REQUEST request = { _protocol, sizeof(request) }; 
            
    // выделить буфер требуемого размера
    DWORD cb = 32768; std::vector<BYTE> recvBuffer(cb); 

    // передать команду смарт-карте
    AE_CHECK_HRESULT(::SCardTransmit(_hCard, 
        &request, (LPCBYTE)pvData, cbData, &request, &recvBuffer[0], &cb
    ));
    // изменить размер буфера
    recvBuffer.resize(cb); return recvBuffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Тип смарт-карты
///////////////////////////////////////////////////////////////////////////////
GUID Windows::PCSC::CardType::GetPrimaryInterface() const 
{ 
    // получить идентификатор первичного интерфейса
    GUID guid = GUID_NULL; AE_CHECK_HRESULT(
        ::SCardGetProviderIdW(_hContext, _name.c_str(), &guid
    )); 
    return guid; 
} 

std::vector<GUID> Windows::PCSC::CardType::GetInterfaces() const
{
    // получить требуемое число интерфейсов
    DWORD cGuids = 0; LONG code = ::SCardListInterfacesW(_hContext, _name.c_str(), nullptr, &cGuids); 

    // проверить код ошибки
    if (code == SCARD_E_UNKNOWN_CARD) AE_CHECK_HRESULT(code); 

    // проверить отсутствие ошибок
    if (code != SCARD_S_SUCCESS) return std::vector<GUID>(); 

    // создать список интерфейсов
    std::vector<GUID> guids(cGuids, GUID_NULL); if (cGuids == 0) return guids; 

    // заполнить список интерфейсов 
    AE_CHECK_HRESULT(::SCardListInterfacesW(_hContext, _name.c_str(), &guids[0], &cGuids)); 

    // указать действительное число интерфейсов
    guids.resize(cGuids); return guids; 
}

std::wstring Windows::PCSC::CardType::GetCryptoProvider(DWORD providerID) const
{
    // указать признак автоматического выделения памяти
    PWSTR szProvider = nullptr; DWORD cchProvider = SCARD_AUTOALLOCATE; 

    // получить имя провайдера 
    LONG code = ::SCardGetCardTypeProviderNameW(
        _hContext, _name.c_str(), providerID, (PWSTR)&szProvider, &cchProvider
    ); 
    // проверить код ошибки
    if (code == SCARD_E_UNKNOWN_CARD) AE_CHECK_HRESULT(code); 

    // проверить отсутствие ошибок
    if (code != SCARD_S_SUCCESS) return std::wstring(); 

    // сохранить имя провайдера 
    std::wstring provider(szProvider); 
    
    // освободить выделенные ресурсы
    ::SCardFreeMemory(_hContext, szProvider); return provider; 
}

void Windows::PCSC::CardType::SetCryptoProvider(DWORD providerID, PCWSTR szProvider)
{
    // установить имя провайдера 
    AE_CHECK_HRESULT(::SCardSetCardTypeProviderNameW(
        _hContext, _name.c_str(), providerID, szProvider
    )); 
}

///////////////////////////////////////////////////////////////////////////////
// Смарт-карта 
///////////////////////////////////////////////////////////////////////////////
Windows::PCSC::Card::Card(SCARDCONTEXT hContext, PCWSTR szReader)

    // сохранить переданные параметры
    : _hContext(hContext), _reader(hContext, szReader) 
{
    // указать режим открытия сеанса
    DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

    // проверить наличие смарт-карты
    std::shared_ptr<ReaderSession> pSession = _reader.CreateSession(openMode, protocols); 

    // получить ATR смарт-карты
    _atr = pSession->ATR(); 
}

std::vector<std::wstring> Windows::PCSC::Card::EnumCardTypes(LPCGUID pGuids, DWORD cGuids) const
{
    // указать признак автоматического выделения памяти
    std::vector<std::wstring> cardTypes; PWSTR szCardTypes = nullptr; DWORD cchCards = SCARD_AUTOALLOCATE; 

    // перечислить типы смарт-карт
    AE_CHECK_HRESULT(::SCardListCardsW(_hContext, &_atr[0], pGuids, cGuids, (PWSTR)&szCardTypes, &cchCards)); 

    // для всех типов смарт-карт
    for (PCWSTR szCardType = szCardTypes; *szCardType; szCardType += wcslen(szCardType) + 1)
    {
        // добавить тип смарт-карты
        cardTypes.push_back(szCardType); 
    }
    // освободить выделенную память
    ::SCardFreeMemory(_hContext, szCardTypes); return cardTypes; 
}

DWORD Windows::PCSC::Card::GetState() const
{
    // инициализировать структуру
    SCARD_READERSTATE state = { _reader.Name(), nullptr }; 

    // указать неизвестное состояние
    state.dwCurrentState = SCARD_STATE_UNAWARE; state.dwEventState = SCARD_STATE_UNAWARE;  

    // получить информацию о состоянии считывателей
    LONG code = ::SCardGetStatusChangeW(_hContext, 0, &state, 1); 

     // проверить отсутствие ошибок
     if (code != SCARD_S_SUCCESS) return SCARD_STATE_EMPTY; 

     // проверить состояние считывателя
     if ((state.dwEventState & SCARD_STATE_MUTE     ) != 0) return SCARD_STATE_MUTE; 
     if ((state.dwEventState & SCARD_STATE_EXCLUSIVE) != 0) return SCARD_STATE_EXCLUSIVE; 
     if ((state.dwEventState & SCARD_STATE_INUSE    ) != 0) return SCARD_STATE_INUSE; 
     if ((state.dwEventState & SCARD_STATE_PRESENT  ) != 0) return SCARD_STATE_PRESENT; 

     // состояние неизвестно
     return SCARD_STATE_EMPTY; 
}

GUID Windows::PCSC::Card::GetGUID() const
{
    // получить криптографический провайдер
    std::shared_ptr<Crypto::IProvider> pProvider = GetProvider(SCARD_PROVIDER_CSP); 

    // проверить наличие провайдера
    if (!pProvider) return GUID_NULL; 

    // вернуть GUID смарт-карты
    return ((const Crypto::CSP::CardProvider*)pProvider.get())->GetCardGUID(); 
}

std::shared_ptr<Windows::Crypto::IProvider> 
Windows::PCSC::Card::GetProvider(DWORD providerID) const
{
    // перечислить типы смарт-карты
    std::vector<std::wstring> cardTypes = EnumCardTypes(nullptr, 0); 

    // для всех типов смарт-карт
    for (size_t i = 0; i < cardTypes.size(); i++)
    {
        // получить тип смарт-карты
        std::shared_ptr<CardType> pCardType = GetCardType(cardTypes[i].c_str()); 

        // получить имя провайдера
        std::wstring providerName = pCardType->GetCryptoProvider(providerID); 

        // проверить наличие имени
        if (providerName.length() == 0) continue; switch (providerID)
        {
        case SCARD_PROVIDER_CSP: {

            // вернуть объект провайдера 
            return std::shared_ptr<Crypto::IProvider>(
                new Crypto::CSP::CardProvider(providerName.c_str(), _reader.Name())
            ); 
        }
        case SCARD_PROVIDER_KSP: {

            // указать считыватель
            std::wstring reader = L"\\\\.\\" + std::wstring(_reader.Name()) + L"\\"; 

            // вернуть объект провайдера 
            return std::shared_ptr<Crypto::IProvider>(
                new Crypto::NCrypt::Provider(providerName.c_str(), reader.c_str(), 0)
            ); 
        }}
    }
    return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// Считыватель смарт-карт
///////////////////////////////////////////////////////////////////////////
DWORD Windows::PCSC::Reader::GetState() const
{
    // инициализировать структуру
    SCARD_READERSTATE state = { _name.c_str(), nullptr }; 

    // указать неизвестное состояние
    state.dwCurrentState = SCARD_STATE_UNAWARE; state.dwEventState = SCARD_STATE_UNAWARE;  

    // получить информацию о состоянии считывателей
    LONG code = ::SCardGetStatusChangeW(_hContext, 0, &state, 1); 

     // проверить отсутствие ошибок
     if (code != SCARD_S_SUCCESS) return SCARD_STATE_UNAVAILABLE; 

     // проверить состояние считывателя
     if ((state.dwEventState & SCARD_STATE_PRESENT) != 0) return SCARD_STATE_PRESENT; 
     if ((state.dwEventState & SCARD_STATE_EMPTY  ) != 0) return SCARD_STATE_EMPTY; 
     if ((state.dwEventState & SCARD_STATE_UNKNOWN) != 0) return SCARD_STATE_UNKNOWN; 

     // состояние неизвестно
     return SCARD_STATE_UNAVAILABLE; 
}

std::shared_ptr<Windows::PCSC::Card> Windows::PCSC::Reader::OpenCard()
{
    // указать режим открытия сеанса
    DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

    // проверить наличие смарт-карты
    std::shared_ptr<ReaderSession> pSession = CreateSession(openMode, protocols); 
        
    // вернуть смарт-карту
    return std::shared_ptr<Card>(new Card(_hContext, _name.c_str(), pSession->ATR())); 
}

std::shared_ptr<Windows::PCSC::ReaderSession>
Windows::PCSC::Reader::CreateSession(DWORD openMode, DWORD protocols) const 
{
    // создать сеанс со считывателем
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(
        ::SCardConnectW(_hContext, _name.c_str(), openMode, protocols, &hCard, &protocols)
    ); 
    // вернуть объект сеанса
    return std::shared_ptr<ReaderSession>(
        new ReaderSession(hCard, protocols), ReaderSessionDeleter()
    ); 
}

void Windows::PCSC::Reader::EjectCard() 
{
    // указать режим открытия сеанса
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // создать сеанс со считывателем
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // извлечь смарт-карту
    ::SCardDisconnect(hCard, SCARD_EJECT_CARD); 
}

void Windows::PCSC::Reader::ResetCard()
{
    // указать режим открытия сеанса
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // создать сеанс со считывателем
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // перезагрузить смарт-карту
    ::SCardDisconnect(hCard, SCARD_RESET_CARD); 
}

void Windows::PCSC::Reader::ShutdownCard()
{
    // указать режим открытия сеанса
    DWORD openMode = SCARD_SHARE_DIRECT; DWORD protocol = 0;

    // создать сеанс со считывателем
    SCARDHANDLE hCard = NULL; AE_CHECK_HRESULT(::SCardConnectW(
        _hContext, _name.c_str(), openMode, protocol, &hCard, &protocol
    )); 
    // перезагрузить смарт-карту
    ::SCardDisconnect(hCard, SCARD_UNPOWER_CARD); 
}

