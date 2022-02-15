package aladdin.iso7816;
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Байты предыстории
///////////////////////////////////////////////////////////////////////////////
public class HistoricalBytes extends CardEnvironment
{
    // используемые объекты и закодированное представление
    private final List<DataObject> objects; private final byte[] encoded; 
    
    // конструктор
    public HistoricalBytes(byte[] encoded, int offset, int length) throws IOException
    {
        // проверить корректность данных
        super(TagScheme.DEFAULT); if (length < 1) throw new IOException(); 
        
        // скопировать представление
        this.encoded = new byte[length]; System.arraycopy(encoded, offset, this.encoded, 0, length);
        
        // создать список объектов
        objects = new ArrayList<DataObject>(); 

        // для стандартного формата
        if (encoded[offset] == 0x00 || encoded[offset] == 0x80)
        {
            // для всех объектов
            for (int index = 1; index < length; )
            {
                // для непоследнего элемента
                if (encoded[offset] == 0x80 || index < length - 3)
                {
                    // раскодировать объект
                    CompactTLV obj = new CompactTLV(
                        encoded, offset + index, length - index
                    ); 
                    // перейти на следующий элемент
                    objects.add(obj.toObject()); index += obj.encoded().length;
                }
                else { byte[] content = new byte[3];

                    // извлечь значение
                    System.arraycopy(encoded, offset + index, content, 0, length - index); 

                    // закодировать объект
                    CompactTLV obj = new CompactTLV(Tag.LIFE_CYCLE, content); 

                    // перейти на следующий элемент
                    objects.add(obj.toObject()); index = length; 
                }
            }
        }
    }
    // перечислитель объектов
    @Override public final Iterator<DataObject> iterator() 
    { 
        // перечислитель объектов
        return objects.iterator(); 
    }
    // закодированное представление
    public final byte[] encoded() { return encoded; }
}
