package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Шаблон для межотраслевых информационных объектов (0x7E)
///////////////////////////////////////////////////////////////////////////
public class InterindustryTemplate extends DataObjectTemplate
{
    // конструктор закодирования
    public InterindustryTemplate(List<DataObject> objects)
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.INTERINDUSTRY_TEMPLATE, objects);
    }
    // конструктор закодирования
    public InterindustryTemplate(DataObject... objects)
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.INTERINDUSTRY_TEMPLATE, objects);
    }
    // конструктор раскодирования
    public InterindustryTemplate(TagScheme tagScheme, byte[] content) throws IOException
    {
        // проверить корректность данных
        super(Authority.ISO7816, Tag.INTERINDUSTRY_TEMPLATE, tagScheme, content); 
    }
}
