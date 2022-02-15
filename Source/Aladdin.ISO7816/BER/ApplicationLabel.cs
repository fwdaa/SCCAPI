using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Метка приложения (0x50)
    ///////////////////////////////////////////////////////////////////////////
    public class ApplicationLabel : DataObject
    {
        // конструктор
        public ApplicationLabel(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.ApplicationLabel, content) {}
    }
}
