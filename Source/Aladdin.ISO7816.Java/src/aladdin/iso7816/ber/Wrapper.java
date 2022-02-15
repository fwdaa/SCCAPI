package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Враппер (0x63)
///////////////////////////////////////////////////////////////////////////
public class Wrapper extends DataObjectTemplate
{
    // конструктор закодирования
    public Wrapper(DataObject... objects)
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.WRAPPER, objects);
        
        // проверить число элементов
        if (size() < 2) throw new IllegalArgumentException();
        
        // получить типы элементов
        Tag listTag = get(0).tag(); Tag targetTag = get(1).tag();
        
        // проверить тип первого элемента
        if (!listTag.equals(Tag.TAG_LIST            ) && 
            !listTag.equals(Tag.HEADER_LIST         ) &&
            !listTag.equals(Tag.EXTENDED_HEADER_LIST) && 
            !listTag.equals(Tag.ELEMENT_LIST        )) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
        // проверить тип второго элемента
        if (targetTag.equals(Tag.FILE_REFERENCE))
        {
            // проверить число элементов
            if (size() != 2) throw new IllegalArgumentException();
        }
        // проверить тип второго элемента
        else if (targetTag.equals(Tag.COMMAND_APDU))
        {
            // для всех последующих элементов
            for (int i = 2; i < size(); i++)
            {
                // проверить тип элемента
                if (!get(i).tag().equals(Tag.COMMAND_APDU))
                {
                    // при ошибке выбросить исключение
                    throw new IllegalArgumentException();
                }
            }
        }
        // при ошибке выбросить исключение
        else throw new IllegalArgumentException(); 
    }
    // конструктор раскодирования
    public Wrapper(TagScheme tagScheme, byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.WRAPPER, tagScheme, content); 
        
        // проверить число элементов
        if (size() < 2) throw new IOException();
        
        // получить типы элементов
        Tag listTag = get(0).tag(); Tag targetTag = get(1).tag();
        
        // проверить тип первого элемента
        if (!listTag.equals(Tag.TAG_LIST            ) && 
            !listTag.equals(Tag.HEADER_LIST         ) &&
            !listTag.equals(Tag.EXTENDED_HEADER_LIST) && 
            !listTag.equals(Tag.ELEMENT_LIST        )) 
        {
            // при ошибке выбросить исключение
            throw new IOException();
        }
        // проверить тип второго элемента
        if (targetTag.equals(Tag.FILE_REFERENCE))
        {
            // проверить число элементов
            if (size() != 2) throw new IOException();
        }
        // проверить тип второго элемента
        else if (targetTag.equals(Tag.COMMAND_APDU))
        {
            // для всех последующих элементов
            for (int i = 2; i < size(); i++)
            {
                // проверить тип элемента
                if (!get(i).tag().equals(Tag.COMMAND_APDU))
                {
                    // при ошибке выбросить исключение
                    throw new IOException();
                }
            }
        }
        // при ошибке выбросить исключение
        else throw new IOException(); 
    }
    // cписок тэгов
    public TagList tagList() throws IOException
    {
        // проверить тип объекта
        if (!get(0).tag().equals(Tag.TAG_LIST)) return null; 
        
        // выполнить преобразование типа
        return new TagList(get(0).content()); 
    }
    // список заголовков
    public HeaderList headerList() throws IOException
    {
        // проверить тип объекта
        if (!get(0).tag().equals(Tag.HEADER_LIST)) return null; 
        
        // выполнить преобразование типа
        return new HeaderList(get(0).content()); 
    }
    // расширенный список заголовков
    public ExtendedHeaderList extendedHeaderList() throws IOException
    {
        // проверить тип объекта
        if (!get(0).tag().equals(Tag.EXTENDED_HEADER_LIST)) return null; 
        
        // выполнить преобразование типа
        return new ExtendedHeaderList(get(0).content()); 
    }
    // список элементов
    public ElementList elementList()
    {
        // проверить тип объекта
        if (!get(0).tag().equals(Tag.ELEMENT_LIST)) return null; 
        
        // выполнить преобразование типа
        return new ElementList(get(0).content()); 
    }
    // ссылка на файл
    public FileReference fileReference()
    {
        // проверить тип объекта
        if (!get(1).tag().equals(Tag.FILE_REFERENCE)) return null; 
        
        // выполнить преобразование типа
        return new FileReference(get(1).content()); 
    }
    // команды на выполнение
    public Command[] commands() throws IOException
    {
        // проверить тип объекта
        if (!get(1).tag().equals(Tag.COMMAND_APDU)) return null; 
        
        // создать список команд
        Command[] commands = new Command[size() - 1]; 
        
        // заполнить список команд
        for (int i = 0; i < commands.length; i++)
        {
            // раскодировать команду
            commands[i] = new Command(get(i + 1).content()); 
        }
        return commands; 
    }
}

