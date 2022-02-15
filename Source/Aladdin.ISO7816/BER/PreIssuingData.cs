using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Данные, предваряющие эмиссию карты (0x46)
    ///////////////////////////////////////////////////////////////////////////
    public class PreIssuingData : DataObject
    {
        // конструктор
        public PreIssuingData(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.PreIssuingData, content) {}
    }
}
