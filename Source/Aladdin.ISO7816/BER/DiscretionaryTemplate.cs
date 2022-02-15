using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Произвольные информационные объекты (0x73)
    ///////////////////////////////////////////////////////////////////////////
    public class DiscretionaryTemplate : DataObjectTemplate
    {
        // конструктор закодирования
        public DiscretionaryTemplate(params DataObject[] objects)
        
            // сохранить переданные параметры
            : this(Tag.DiscretionaryTemplate, objects) {}

        // конструктор закодирования
        public DiscretionaryTemplate(Tag tag, params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, tag, objects) {}
        
        // конструктор раскодирования
        public DiscretionaryTemplate(TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : this(Tag.DiscretionaryTemplate, tagScheme, content) {} 

        // конструктор раскодирования
        public DiscretionaryTemplate(Tag tag, TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : base(Authority.ISO7816, tag, tagScheme, content) {} 
    }
}
