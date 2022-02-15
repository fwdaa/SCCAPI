package aladdin.iso7816;
import aladdin.asn1.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Способ кодирования данных
///////////////////////////////////////////////////////////////////////////////
public class DataCoding 
{
    // схема кодирования и байт способа записи и дополнения
    private final TagScheme scheme; private final byte value; 
    
    // конструктор
    public DataCoding(TagScheme scheme) { this(scheme, (byte)0x02); }
    
    // конструктор
    public DataCoding(TagScheme scheme, byte value) 
    { 
        // сохранить переданные параметры
        this.scheme = scheme; this.value = value; 
    }
    // конструктор
    public DataCoding(DataCoding dataCoding, TagScheme scheme) 
    { 
        // сохранить переданные параметры
        this.scheme = scheme; this.value = dataCoding.value; 
    }
    // используемая схема кодирования
    public final TagScheme tagScheme() { return scheme; }
    
    // способ записи
    public WriteType writeEraseType() 
    {
        switch ((value >>> 5) & 0x3)
        {
        case 0: return WriteType.WRITE_ERASED; 
        case 2: return WriteType.WRITE_OR; 
        case 3: return WriteType.WRITE_AND; 
        }
        return WriteType.PROPRIETARY; 
    }
    // размер адресуемых единиц в тетрадах
    public int quartetUnitSize()
    {
        // вернуть адресуемых единиц в тетрадах
        return (1 << (value & 0x0F)); 
    }
    // извлечь закодированные представления
    public final IEncodable[] extract(byte[] content) throws IOException
    {
        // указать возможность дополнения байтами FF
        boolean paddingFF = ((value & 0x10) == 0); int offset = 0; 
            
        // создать пустой список закодированных представлений
        List<IEncodable> encodables = new ArrayList<IEncodable>(); 

        // для всех байтов содержимого
        for (; offset < content.length; offset++)
        {
            // проверить наличие заполнения
            if (paddingFF && content[offset] == 0xFF) continue; 

            // проверить отсутствие заполнения
            if (content[offset] != 0) break; 
        }
        // для всех внутренних объектов
        while (offset < content.length)
        { 
            // раскодировать содержимое
            IEncodable encodable = Encodable.decode(
                content, offset, content.length - offset
            ); 
            // добавить представление в список
            encodables.add(encodable); offset += encodable.encoded().length; 
            
            // для всех байтов содержимого
            for (; offset < content.length; offset++)
            {
                // проверить наличие заполнения
                if (paddingFF && content[offset] == 0xFF) continue; 

                // проверить отсутствие заполнения
                if (content[offset] != 0) break; 
            }
        }
        // вернуть раскодированные объекты
        return encodables.toArray(new IEncodable[encodables.size()]); 
    }
    // закодировать объекты
    public final byte[] encode(DataObject... objects) throws IOException
    {
        // закодировать объекты
        return DataObject.encode(scheme, objects); 
    }
    // раскодировать объекты
    public final DataObject[] decode(byte[] content, boolean interindustry) throws IOException
    {
        // указать параметры
        Authority outerAuthority = (interindustry) ? Authority.ISO7816 : null; 
        
        // раскодировать объекты
        return decode(outerAuthority, content); 
    }
    // раскодировать объекты
    public final DataObject[] decode(Authority outerAuthority, byte[] content) throws IOException
    {
        // извлечь закодированные представления
        IEncodable[] encodables = extract(content); 
        
        // создать список объектов
        DataObject[] objs = new DataObject[encodables.length]; 
        
        // для всех закодированных представлений
        for (int i = 0; i < encodables.length; i++)
        {
            // определить тип представления
            Tag tag = new Tag(encodables[i].tag(), encodables[i].pc()); 
            
            // раскодировать объекты
            objs[i] = scheme.decode(outerAuthority, tag, encodables[i].content()); 
        }
        return objs; 
    }
}
