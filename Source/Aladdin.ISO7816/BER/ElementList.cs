using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Список элементов (0x5F 0x41)
    ///////////////////////////////////////////////////////////////////////////
    public class ElementList : DataObject
    {
        // конструктор
        public ElementList(byte[] content) 
    
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.ElementList, content) {}
    }
}
