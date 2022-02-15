package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Шаблон приложения (0x61)
///////////////////////////////////////////////////////////////////////////
public class ApplicationTemplate extends DataObjectTemplate
{
    // конструктор закодирования
    public ApplicationTemplate(DataObject... objects)
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.APPLICATION_TEMPLATE, objects); 
    
        // проверить наличие идентификатора приложения
        if (get(Tag.APPLICATION_IDENTIFIER).length != 1) throw new IllegalArgumentException(); 
    }
    // конструктор раскодирования
    public ApplicationTemplate(TagScheme tagScheme, byte[] content) throws IOException
    {    
        // проверить корректность данных
        super(Authority.ISO7816, Tag.APPLICATION_TEMPLATE, tagScheme, content); 
    
        // проверить наличие идентификатора приложения
        if (get(Tag.APPLICATION_IDENTIFIER).length != 1) throw new IOException(); 
    } 
    // идентификатор приложения 
    public ApplicationIdentifier applicationIdentifier() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.APPLICATION_IDENTIFIER)[0]; 
        
        // вернуть значение объекта
        return ApplicationIdentifier.decode(obj.content()); 
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
    // ссылки на файлы
    public FileReference[] fileReferences(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<FileReference> objs = new ArrayList<FileReference>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.FILE_REFERENCE)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new FileReference(obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.fileReferences(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new FileReference[objs.size()]); 
    }
    // исполняемые команды
    public Command[] commands(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<Command> objs = new ArrayList<Command>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.COMMAND_APDU)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new Command(obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.commands(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new Command[objs.size()]); 
    }
    // унифицированные указатели ресурса
    public URL[] uniformResourceLocators(TagScheme tagScheme) throws IOException
    {
        // создать список внутренних объектов
        List<URL> objs = new ArrayList<URL>(); 

        // для всех внутренних объектов
        for (DataObject obj : this) 
        {
            // проверить совпадение идентификаторов
            if (!obj.tag().equals(Tag.UNIFORM_RESOURCE_LOCATOR)) continue; 
                
            // добавить внутренний объект в список
            objs.add(new URL(obj.content())); 
        }
        // для всех внутренних шаблонов
        for (ApplicationTemplate template : applicationTemplates(tagScheme))
        {
            // добавить объекты из внутренних шаблонов в список
            objs.addAll(Arrays.asList(template.uniformResourceLocators(tagScheme))); 
        }
        // вернуть внутренние объекты
        return objs.toArray(new URL[objs.size()]); 
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
