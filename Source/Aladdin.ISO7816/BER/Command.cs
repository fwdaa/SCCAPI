using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Команда на выполнение (0x52)
    ///////////////////////////////////////////////////////////////////////////
    public class Command : ISO7816.DataObject
    {
        // команда APDU
        public readonly ISO7816.Command Value; 

        // конструктор закодирования
        public Command(ISO7816.Command value) 
    
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CommandAPDU, value.Encoded) 
    
            // сохранить переданные параметры
            { Value = value; }
    
        // конструктор раскодирования
        public Command(byte[] content)
    
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CommandAPDU, content)  
        {
            // раскодировать команду
            Value = new ISO7816.Command(content); 
        }
    }
}
