package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Шаблон безопасного обмена сообщениями (0x7D)
///////////////////////////////////////////////////////////////////////////////
public class SecureMessaging extends DataObjectTemplate
{
    // конструктор закодирования
    public SecureMessaging(DataObject... objects)
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.SECURE_MESSAGING, objects); 
    }
    // конструктор раскодирования
    public SecureMessaging(TagScheme tagScheme, byte[] content) throws IOException
    {    
        // проверить корректность данных
        super(Authority.ISO7816, Tag.SECURE_MESSAGING, tagScheme, content); 
    } 
}
