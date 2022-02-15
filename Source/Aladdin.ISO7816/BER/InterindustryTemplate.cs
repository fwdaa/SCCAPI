using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон для межотраслевых информационных объектов (0x7E)
    ///////////////////////////////////////////////////////////////////////////
    public class InterindustryTemplate : DataObjectTemplate
    {
        // конструктор закодирования
        public InterindustryTemplate(params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.InterindustryTemplate, objects) {}
        
        // конструктор раскодирования
        public InterindustryTemplate(TagScheme tagScheme, byte[] content) 
        
            // проверить корректность данных
            : base(Authority.ISO7816, ISO7816.Tag.InterindustryTemplate, tagScheme, content) {} 
    }
}
