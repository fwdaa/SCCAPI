using System;

namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Состояние считывателя
    ///////////////////////////////////////////////////////////////////////////
    public struct ReaderStatus
    {
        public string[] readers;    // имена считывателей
        public uint     state;      // состояние считывателя/смарт-карты
        public Protocol protocol;   // используемый протокол
        public byte[]   atr;        // ATR вставленной карты
    }
}
