package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Произвольные информационные объекты (0x73)
///////////////////////////////////////////////////////////////////////////
public class DiscretionaryTemplate extends DataObjectTemplate
{
    // конструктор закодирования
    public DiscretionaryTemplate(DataObject... objects)
    {
        // сохранить переданные параметры
        this(Tag.DISCRETIONARY_TEMPLATE, objects);
    }
    // конструктор закодирования
    public DiscretionaryTemplate(Tag tag, DataObject... objects)
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, objects);
    }
    // конструктор раскодирования
    public DiscretionaryTemplate(TagScheme tagScheme, byte[] content) throws IOException
    {
        // проверить корректность данных
        this(Tag.DISCRETIONARY_TEMPLATE, tagScheme, content); 
    }
    // конструктор раскодирования
    public DiscretionaryTemplate(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
    {
        // проверить корректность данных
        super(Authority.ISO7816, tag, tagScheme, content); 
    }
}
