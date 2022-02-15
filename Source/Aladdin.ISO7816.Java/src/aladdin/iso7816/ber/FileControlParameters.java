package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import aladdin.asn1.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Шаблон FCP (0x62)
///////////////////////////////////////////////////////////////////////////////
public class FileControlParameters extends DataObjectTemplate
{
    // конструктор закодирования
    public FileControlParameters(DataObject... objects)
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.FILE_CONTROL_PARAMETERS, objects); 
    }
    // конструктор раскодирования
    public FileControlParameters(TagScheme tagScheme, byte[] content) throws IOException
    {    
        // проверить корректность данных
        super(Authority.ISO7816, Tag.FILE_CONTROL_PARAMETERS, tagScheme, content); 
    } 
    // объединить объекты описания
    public final FileControlParameters сombine(DataObjectTemplate objects)
    {
        // проверить наличие объектов
        if (objects == null) return this; List<DataObject> objs = new ArrayList<DataObject>();
        
        // добавить объекты в список
        for (DataObject obj : this   ) objs.add(obj); 
        for (DataObject obj : objects) objs.add(obj);
        
        // вернуть новый набор
        return new FileControlParameters(objs.toArray(new DataObject[objs.size()])); 
    }
    // переопределение схемы кодирования объектов
    public TagScheme getTagScheme(TagScheme tagScheme) throws IOException
    {
        // найти объект
        DataObject[] objs = get(Tag.COMPATIBLE_TAG_SCHEME); if (objs.length != 0) 
        {
            // раскодировать объект
            return TagScheme.decodeTagScheme(objs[0].tag(), objs[0].content()); 
        }
        // найти объект
        objs = get(Tag.COEXISTENT_TAG_SCHEME); if (objs.length != 0) 
        {
            // раскодировать объект
            return new TagScheme.Coexistent(objs[0].content()); 
        }
        return tagScheme; 
    }
    // переопределение схемы кодирования данных
    public DataCoding getDataCoding(DataCoding dataCoding) throws IOException
    {
        // получить схему кодирования объектов
        TagScheme tagScheme = getTagScheme(dataCoding.tagScheme()); 
        
        // получить дескриптор файла
        DataObject[] objs = get(Tag.context(0x02, PC.PRIMITIVE)); 
        
        // проверить наличие дескриптора
        if (objs.length == 0) return new DataCoding(dataCoding, tagScheme); 
        
        // получить содержимое
        byte[] content = objs[0].content(); if (content.length < 2)
        {
            // вернуть значение по умолчанию
            return new DataCoding(dataCoding, tagScheme);
        }
        // вернуть способ кодирования данных
        return new DataCoding(tagScheme, content[1]);
    }
    // определить структуру файла
    public final FileStructure fileStructure() 
    {
        // получить дескриптор файла
        DataObject[] objs = get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return FileStructure.UNKNOWN; 

        // получить содержимое
        byte[] content = objs[0].content(); 
            
        // проверить размер содержимого
        if (content.length < 1 || (content[0] & 0x80) != 0)
        {
            // указать значение по умолчанию
            return FileStructure.UNKNOWN; 
        }
        // в зависимости установленных битов
        if (((content[0] >>> 3) & 0x7) != 0x7)
        {
            // в зависимости установленных битов
            switch (content[0] & 0x7)
            {
            case 0x1: return FileStructure.TRANSPARENT;
            case 0x2: return FileStructure.LINEAR_FIXED;
            case 0x3: return FileStructure.LINEAR_FIXED_TLV;
            case 0x4: return FileStructure.LINEAR_VARIABLE;
            case 0x5: return FileStructure.LINEAR_VARIABLE_TLV;
            case 0x6: return FileStructure.CYCLIC_FIXED;
            case 0x7: return FileStructure.CYCLIC_FIXED_TLV;
            }
        }
        else {
            // в зависимости установленных битов
            switch (content[0] & 0x7)
            {
            case 0x1: return FileStructure.DATA_OBJECT_BERTLV;
            case 0x2: return FileStructure.DATA_OBJECT_SIMPLETLV;
            }
        }
        // структура файла неизвестна
        return FileStructure.UNKNOWN;
    }
    // идентификатор файла
    public Short id()
    { 
        // найти объект
        DataObject[] objs = get(Tag.context(0x03, PC.PRIMITIVE)); if (objs.length == 0) return null; 
        
        // получить содержимое
        byte[] content = objs[0].content(); if (content.length != 2) return null; 
        
        // раскодировать идентификатор
        return (short)(((content[0] & 0xFF) << 8) | (content[1] & 0xFF)); 
    }
    // общий размер байтов
    public final java.lang.Integer totalBytes() 
    {
        // найти объект
        DataObject[] objs = get(Tag.context(0x01, PC.PRIMITIVE)); if (objs.length == 0) return null; 
        
        // получить содержимое
        byte[] content = objs[0].content(); if (content.length != 2) return null; 
        
        // скопировать значимые байты
        byte[] value = new byte[4]; System.arraycopy(content, 0, value, 2, 2);
        
        // раскодировать общий размер данных
        return (((content[0] & 0xFF) << 8) | (content[1] & 0xFF)); 
    }
    // стадия жизненного цикла
    public final LifeCycle lifeCycle() 
    {
        // указать тип данных
        Tag tag = Tag.context(0x0A, PC.PRIMITIVE); 
        
        // найти объект
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
        
        // раскодировать объект
        return new LifeCycle(tag, objs[0].content()); 
    }
    // произвольные данные
    public final DiscretionaryData[] disсretionaryData()
    {
        // создать список внутренних объектов
        List<DiscretionaryData> objs = new ArrayList<DiscretionaryData>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.context(0x05, PC.PRIMITIVE))) continue; 
                
            // добавить внутренний объект в список
            objs.add(new DiscretionaryData(obj.tag(), obj.content())); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new DiscretionaryData[objs.size()]); 
    }
    // шаблон произвольные данные
    public final DiscretionaryTemplate[] disсretionaryTemplates(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<DiscretionaryTemplate> objs = new ArrayList<DiscretionaryTemplate>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.context(0x05, PC.CONSTRUCTED))) continue; 
                
            // добавить внутренний объект в список
            objs.add(new DiscretionaryTemplate(obj.tag(), tagScheme, obj.content())); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new DiscretionaryTemplate[objs.size()]); 
    }
}
