using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Враппер (0x63)
    ///////////////////////////////////////////////////////////////////////////
    public class Wrapper : DataObjectTemplate
    {
        // конструктор закодирования
        public Wrapper(params DataObject[] objects)

            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.Wrapper, objects)
        {
            // проверить число элементов
            if (Count < 2) throw new ArgumentException();
        
            // получить типы элементов
            Tag listTag = this[0].Tag; Tag targetTag = this[1].Tag;
        
            // проверить тип первого элемента
            if (listTag != ISO7816.Tag.TagList            && 
                listTag != ISO7816.Tag.HeaderList         &&
                listTag != ISO7816.Tag.ExtendedHeaderList && 
                listTag != ISO7816.Tag.ElementList        ) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
            // проверить тип второго элемента
            if (targetTag == ISO7816.Tag.FileReference)
            {
                // проверить число элементов
                if (Count != 2) throw new ArgumentException();
            }
            // проверить тип второго элемента
            else if (targetTag == ISO7816.Tag.CommandAPDU)
            {
                // для всех последующих элементов
                for (int i = 2; i < Count; i++)
                {
                    // проверить тип элемента
                    if (this[i].Tag != ISO7816.Tag.CommandAPDU)
                    {
                        // при ошибке выбросить исключение
                        throw new ArgumentException();
                    }
                }
            }
            // при ошибке выбросить исключение
            else throw new ArgumentException();
        }
        // конструктор раскодирования
        public Wrapper(TagScheme tagScheme, byte[] content) 

            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.Wrapper, tagScheme, content) 
        {
            // проверить число элементов
            if (Count < 2) throw new InvalidDataException();
        
            // получить типы элементов
            Tag listTag = this[0].Tag; Tag targetTag = this[1].Tag;
        
            // проверить тип первого элемента
            if (listTag != ISO7816.Tag.TagList            && 
                listTag != ISO7816.Tag.HeaderList         &&
                listTag != ISO7816.Tag.ExtendedHeaderList && 
                listTag != ISO7816.Tag.ElementList        ) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // проверить тип второго элемента
            if (targetTag == ISO7816.Tag.FileReference)
            {
                // проверить число элементов
                if (Count != 2) throw new InvalidDataException();
            }
            // проверить тип второго элемента
            else if (targetTag == ISO7816.Tag.CommandAPDU)
            {
                // для всех последующих элементов
                for (int i = 2; i < Count; i++)
                {
                    // проверить тип элемента
                    if (this[i].Tag != ISO7816.Tag.CommandAPDU)
                    {
                        // при ошибке выбросить исключение
                        throw new InvalidDataException();
                    }
                }
            }
            // при ошибке выбросить исключение
            else throw new InvalidDataException();
        }
        // cписок тэгов
        public TagList TagList { get  
        {
            // проверить тип объекта
            if (this[0].Tag != ISO7816.Tag.TagList) return null; 
        
            // выполнить преобразование типа
            return new TagList(this[0].Content); 
        }}
        // список заголовков
        public HeaderList HeaderList { get 
        {
            // проверить тип объекта
            if (this[0].Tag != ISO7816.Tag.HeaderList) return null; 
        
            // выполнить преобразование типа
            return new HeaderList(this[0].Content); 
        }}
        // расширенный список заголовков
        public ExtendedHeaderList ExtendedHeaderList { get  
        {
            // проверить тип объекта
            if (this[0].Tag != ISO7816.Tag.ExtendedHeaderList) return null; 
        
            // выполнить преобразование типа
            return new ExtendedHeaderList(this[0].Content); 
        }}
        // список элементов
        public ElementList ElementList { get 
        {
            // проверить тип объекта
            if (this[0].Tag != ISO7816.Tag.ElementList) return null; 
        
            // выполнить преобразование типа
            return new ElementList(this[0].Content); 
        }}
        // ссылка на файл
        public FileReference FileReference { get 
        {
            // проверить тип объекта
            if (this[1].Tag != ISO7816.Tag.FileReference) return null; 
        
            // выполнить преобразование типа
            return new FileReference(this[1].Content); 
        }}
        // команды на выполнение
        public Command[] Commands { get  
        {
            // проверить тип объекта
            if (this[1].Tag != ISO7816.Tag.CommandAPDU) return null; 
        
            // создать список команд
            Command[] commands = new Command[Count - 1]; 
        
            // заполнить список команд
            for (int i = 0; i < commands.Length; i++)
            {
                // раскодировать команду
                commands[i] = new Command(this[i + 1].Content); 
            }
            return commands; 
        }}
    }
}
