package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import java.util.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Шаблон FMD (0x64)
///////////////////////////////////////////////////////////////////////////
public class FileManagementData extends DataObjectTemplate
{
    // конструктор закодирования
    public FileManagementData(DataObject... objects)
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.FILE_MANAGEMENT_DATA, objects); 
    }
    // конструктор раскодирования
    public FileManagementData(TagScheme tagScheme, byte[] content) throws IOException
    {    
        // проверить корректность данных
        super(Authority.ISO7816, Tag.FILE_MANAGEMENT_DATA, tagScheme, content); 
    } 
    // схема кодирования
    public final TagScheme getTagScheme(TagScheme tagScheme) throws IOException
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
    // идентификатор приложения 
    public ApplicationIdentifier[] applicationIdentifiers(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<ApplicationIdentifier> objs = new ArrayList<ApplicationIdentifier>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.APPLICATION_IDENTIFIER)) continue; 
                
            // добавить внутренний объект в список
            objs.add(ApplicationIdentifier.decode(obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.add(template.applicationIdentifier()); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new ApplicationIdentifier[objs.size()]); 
    }
    // метки приложения
    public ApplicationLabel[] applicationLabels(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<ApplicationLabel> objs = new ArrayList<ApplicationLabel>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.APPLICATION_LABEL)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new ApplicationLabel(obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.applicationLabels(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new ApplicationLabel[objs.size()]); 
    }
    // дата истечения срока действия карты 
    public CardExpirationDate[] cardExpirationDates() throws IOException
    {
        // создать список внутренних объектов
        List<CardExpirationDate> objs = new ArrayList<CardExpirationDate>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.CARD_EXPIRATION_DATE)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new CardExpirationDate(obj.content())); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new CardExpirationDate[objs.size()]); 
    }
    // произвольные данные
    public DiscretionaryData[] discretionaryData(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<DiscretionaryData> objs = new ArrayList<DiscretionaryData>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.DISCRETIONARY_DATA)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new DiscretionaryData(obj.tag(), obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.discretionaryData(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new DiscretionaryData[objs.size()]); 
    }
    // шаблоны произвольных данных
    public DiscretionaryTemplate[] discretionaryTemplates(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<DiscretionaryTemplate> objs = new ArrayList<DiscretionaryTemplate>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.DISCRETIONARY_TEMPLATE)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new DiscretionaryTemplate(obj.tag(), tagScheme, obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.discretionaryTemplates(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new DiscretionaryTemplate[objs.size()]); 
    }
    // внутренние шаблоны приложения
    private ApplicationTemplate[] applicationTemplates(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<ApplicationTemplate> objs = new ArrayList<ApplicationTemplate>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.APPLICATION_TEMPLATE)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new ApplicationTemplate(tagScheme, obj.content())); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new ApplicationTemplate[objs.size()]); 
    }
}
