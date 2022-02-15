package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import aladdin.asn1.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Описание идентификатора алгоритма
///////////////////////////////////////////////////////////////////////////////
public class MechanismID extends DataObjectTemplate
{
    // конструктор раскодирования
    public MechanismID(TagScheme tagScheme, byte[] content) throws IOException
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.context(0x0C, PC.CONSTRUCTED), tagScheme, content); 
        
        // проверить число элементов
        if (size() < 2) throw new IOException();
        
        // проверить тип первого элемента
        if (!get(0).tag().equals(Tag.context(0x00, PC.PRIMITIVE))) 
        {
            // при ошибке выбросить исключение
            throw new IOException();
        }
        // для всех оставшихся элементов
        for (int i = 1; i < size(); i++)
        {
            // проверить тип элемента
            if (!get(i).tag().equals(Tag.OBJECT_IDENTIFIER))
            {
                // при ошибке выбросить исключение
                throw new IOException();
            }
        }
    } 
    // идентификатор алгоритма
    public final byte[] reference() { return get(0).content(); }
    
    // описание алгоритма
    public final ObjectIdentifier[] objectID() throws IOException
    {
        // выделить буфер требуемого размера
        ObjectIdentifier[] objIDs = new ObjectIdentifier[size() - 1]; 
        
        // для всех идентификаторов
        for (int i = 1; i < size(); i++) { DataObject obj = get(i); 
            
            // раскодировать идентификатор
            objIDs[i - 1] = new ObjectIdentifier(
                Encodable.encode(obj.tag().asnTag, obj.tag().pc, obj.content())
            ); 
        }
        // вернуть идентификатор
        return objIDs; 
    }
}
