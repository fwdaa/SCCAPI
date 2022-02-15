using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Унифицированный указатель ресурса (0x5F 0x50)
    ///////////////////////////////////////////////////////////////////////////
    public class URL : DataObject
    {
        // конструктор
        public URL(byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.UniformResourceLocator, content) {} 
    }
}
