using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон приложения (0x61)
    ///////////////////////////////////////////////////////////////////////////
    public class ApplicationTemplate : DataObjectTemplate
    {
        // конструктор закодирования
        public ApplicationTemplate(params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.ApplicationTemplate, objects) 
        {
            // проверить наличие идентификатора приложения
            if (this[ISO7816.Tag.ApplicationIdentifier].Length != 1) throw new ArgumentException(); 
        }
        // конструктор раскодирования
        public ApplicationTemplate(TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : base(Authority.ISO7816, ISO7816.Tag.ApplicationTemplate, tagScheme, content) 
        {
            // проверить наличие идентификатора приложения
            if (this[ISO7816.Tag.ApplicationIdentifier].Length != 1) throw new IOException(); 
        } 
        // идентификатор приложения 
        public ApplicationIdentifier ApplicationIdentifier { get 
        {
            // найти объект
            DataObject obj = this[ISO7816.Tag.ApplicationIdentifier][0]; 

            // вернуть значение объекта
            return ApplicationIdentifier.Decode(obj.Content); 
        }}
        // метки приложения
        public ApplicationLabel[] ApplicationLabels(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<ApplicationLabel> objs = new List<ApplicationLabel>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.ApplicationLabel) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new ApplicationLabel(obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.ApplicationLabels(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // ссылки на файлы
        public FileReference[] FileReferences(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<FileReference> objs = new List<FileReference>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.FileReference) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new FileReference(obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.FileReferences(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // исполняемые команды
        public Command[] Commands(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<Command> objs = new List<Command>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.CommandAPDU) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new Command(obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.Commands(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // унифицированные указатели ресурса
        public URL[] UniformResourceLocators(TagScheme tagScheme)
        {
            // создать список внутренних объектов
            List<URL> objs = new List<URL>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.UniformResourceLocator) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new URL(obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.UniformResourceLocators(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // произвольные данные
        public DiscretionaryData[] DiscretionaryData(TagScheme tagScheme)
        {
            // создать список внутренних объектов
            List<DiscretionaryData> objs = new List<DiscretionaryData>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.DiscretionaryData) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new DiscretionaryData(obj.Tag, obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.DiscretionaryData(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // шаблоны произвольных данных
        public DiscretionaryTemplate[] DiscretionaryTemplates(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<DiscretionaryTemplate> objs = new List<DiscretionaryTemplate>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.DiscretionaryTemplate) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new DiscretionaryTemplate(obj.Tag, tagScheme, obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.AddRange(template.DiscretionaryTemplates(tagScheme)); 
            }
            return objs.ToArray(); 
        }
        // внутренние шаблоны приложения
        private ApplicationTemplate[] ApplicationTemplates(TagScheme tagScheme)
        {
            // создать список внутренних объектов
            List<ApplicationTemplate> objs = new List<ApplicationTemplate>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.ApplicationTemplate) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new ApplicationTemplate(tagScheme, obj.Content)); 
            }
            return objs.ToArray(); 
        }
    }
}
