using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон безопасного обмена сообщениями (0x7D)
    ///////////////////////////////////////////////////////////////////////////
    public class SecureMessaging : DataObjectTemplate
    {
        // конструктор закодирования
        public SecureMessaging(params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.SecureMessaging, objects) {}

        // конструктор раскодирования
        public SecureMessaging(TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : base(Authority.ISO7816, ISO7816.Tag.SecureMessaging, tagScheme, content) {} 
    }
}
