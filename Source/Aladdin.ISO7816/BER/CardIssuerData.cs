using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Данные эмитента (0x45)
    ///////////////////////////////////////////////////////////////////////////
    public class CardIssuerData : DataObject
    {
        // конструктор
        public CardIssuerData(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CardIssuerData, content) {}
    }
}
