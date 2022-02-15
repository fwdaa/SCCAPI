using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Произвольные данные (0x53)
    ///////////////////////////////////////////////////////////////////////////
    public class DiscretionaryData : DataObject
    {
        // конструктор
        public DiscretionaryData(byte[] content) 
        
            // сохранить переданные параметры
            : this(Tag.DiscretionaryData, content) {} 

        // конструктор
        public DiscretionaryData(Tag tag, byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, tag, content) {} 
    }
}
