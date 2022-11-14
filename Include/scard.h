#pragma once
#include <winscard.h>
#include "crypto.h"

namespace Windows { namespace PCSC {

///////////////////////////////////////////////////////////////////////
// Сеанс работы со считывателем
///////////////////////////////////////////////////////////////////////
class ReaderSession  
{
	// описатель сеанса, используемый протокол и ATR смарт-карты
    private: SCARDHANDLE _hCard; DWORD _protocol; std::vector<BYTE> _atr; 

	// конструктор 
    public: ReaderSession(SCARDHANDLE hCard, DWORD protocol)

        // сохранить переданные параметры 
        : _hCard(hCard), _protocol(protocol)
    {
        // получить ATR смарт-карты
        _atr = GetAttribute(SCARD_ATTR_ATR_STRING); 
    }
    // оператор преобразования типа
    public: operator SCARDHANDLE() const { return _hCard; }

    // ATR смарт-карты
    public: const std::vector<BYTE>& ATR() const { return _atr; }
    // используемый протокол
    public: DWORD Protocol() const { return _protocol; }

    // получить логические имена считывателя
    public: std::vector<std::wstring> GetReaderNames() const; 

    // получить атрибут считывателя/смарт-карты
    public: std::vector<BYTE> GetAttribute(DWORD attrID) const; 

    // заблокировать/разблокировать смарт-карту
    public: void Lock(); void Unlock(); 

    // отправить команду считывателю
    public: std::vector<BYTE> SendControl(DWORD code, LPCVOID pvData, DWORD cbData); 
    // отправить команду смарт-карте
    public: std::vector<BYTE> SendCommand(LPCVOID pvData, DWORD cbData); 
}; 

///////////////////////////////////////////////////////////////////////////
// Считыватель смарт-карт
///////////////////////////////////////////////////////////////////////////
class Reader
{
    // контекст диспетчера и логическое имя считывателя 
    private: SCARDCONTEXT _hContext; std::wstring _name;

    // конструктор
    public: Reader(SCARDCONTEXT hContext, PCWSTR szName) 

        // сохранить переданные параметры 
        : _hContext(hContext), _name(szName) {}

    // получить логические имена считывателя
    public: std::vector<std::wstring> GetReaderNames() const
    {
        // указать режим открытия сеанса
        DWORD openMode = SCARD_SHARE_SHARED; DWORD protocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; 

        // открыть сеанс работы со смарт-картой
        std::shared_ptr<ReaderSession> pSession = CreateSession(openMode, protocols); 

        // получить логические имена считывателя
        return pSession->GetReaderNames(); 
    }
    // логическое имя считывателя
    public: PCWSTR Name() const { return _name.c_str(); } 

    // состояние и смарт-карта считывателя
    public: DWORD GetState() const; std::shared_ptr<class Card> OpenCard(); 

    // открыть сеанс работы со смарт-картой
    public: std::shared_ptr<ReaderSession> CreateSession(DWORD openMode, DWORD protocols) const; 

    // операции со смарт-картами
    public: void EjectCard   (); // извлечь смарт-карту
    public: void ResetCard   (); // перезагрузить смарт-карту
    public: void ShutdownCard(); // выключить смарт-карту
};

///////////////////////////////////////////////////////////////////////////////
// Тип смарт-карты
///////////////////////////////////////////////////////////////////////////////
class CardType 
{ 
    // контекст диспетчера и имя типа
    private: SCARDCONTEXT _hContext; std::wstring _name; 

    // конструктор
    public: CardType(SCARDCONTEXT hContext, PCWSTR szCardName) 

        // сохранить переданные параметры 
        : _hContext(hContext), _name(szCardName) {}

    // имя типа смарт-карты
    public: PCWSTR Name() const { return _name.c_str(); } 

    // идентификатор первичного провайдера
    public: GUID GetPrimaryInterface() const; 
    // идентификаторы интерфейсов
    public: std::vector<GUID> GetInterfaces() const; 

    // получить имя провайдера
    public: std::wstring GetCryptoProvider(DWORD providerID) const;  
    // установить имя провайдера
    public: void SetCryptoProvider(DWORD providerID, PCWSTR szProvider); 
}; 

///////////////////////////////////////////////////////////////////////////////
// Смарт-карта 
///////////////////////////////////////////////////////////////////////////////
class Card 
{ 
    // контекст диспетчера и логическое имя считывателя 
    private: SCARDCONTEXT _hContext; Reader _reader; std::vector<BYTE> _atr; 

    // конструктор
    public: Card(SCARDCONTEXT hContext, PCWSTR szReader, const std::vector<BYTE>& atr)

        // сохранить переданные параметры
        : _hContext(hContext), _reader(hContext, szReader), _atr(atr) {}

    // конструктор
    public: Card(SCARDCONTEXT hContext, PCWSTR szReader); 

    // используемый считыватель
    public: const Reader& Reader() const { return _reader; }
    // ATR смарт-карты
    public: const std::vector<BYTE>& ATR() const { return _atr; }

    // имена типов смарт-карты
    public: std::vector<std::wstring> EnumCardTypes(LPCGUID pGuids, DWORD cGuids) const; 
    // получить тип смарт-карты
    public: std::shared_ptr<CardType> GetCardType(PCWSTR szCartType) const
    {
        // получить тип смарт-карты
        return std::shared_ptr<CardType>(new CardType(_hContext, szCartType)); 
    }
    // состояние и GUID смарт-карты 
    public: DWORD GetState() const; GUID GetGUID() const;

	// криптографический провайдер
    public: std::shared_ptr<Crypto::ICardStore> GetProvider(DWORD providerID) const; 
};
}}
