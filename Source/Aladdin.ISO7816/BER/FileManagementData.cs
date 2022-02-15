using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон FMD (0x64)
    ///////////////////////////////////////////////////////////////////////////
    public class FileManagementData : DataObjectTemplate
    {
        // конструктор закодирования
        public FileManagementData(params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.FileManagementData, objects) {}

        // конструктор раскодирования
        public FileManagementData(TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : base(Authority.ISO7816, ISO7816.Tag.FileManagementData, tagScheme, content) {} 

        // схема кодирования
        public TagScheme GetTagScheme(TagScheme tagScheme)
        {
            // найти объект
            DataObject[] objs = this[ISO7816.Tag.CompatibleTagScheme]; if (objs.Length != 0)
            { 
                // раскодировать объект
                return TagScheme.DecodeTagScheme(objs[0].Tag, objs[0].Content); 
            }
            // найти объект
            objs = this[ISO7816.Tag.CoexistentTagScheme]; if (objs.Length != 0)
            { 
                // раскодировать объект
                return new TagScheme.Coexistent(objs[0].Content); 
            }
            return tagScheme; 
        }
        // идентификатор приложения 
        public ApplicationIdentifier[] ApplicationIdentifiers(TagScheme tagScheme)
        {
            // создать список внутренних объектов
            List<ApplicationIdentifier> objs = new List<ApplicationIdentifier>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.ApplicationIdentifier) continue; 
                
                // добавить внутренний объект в список
                objs.Add(ApplicationIdentifier.Decode(obj.Content)); 
            }
            // для всех внутренних шаблонов
            foreach (ApplicationTemplate template in ApplicationTemplates(tagScheme))
            {
                // добавить объекты из внутренних шаблонов в список
                objs.Add(template.ApplicationIdentifier); 
            }
            return objs.ToArray(); 
        }
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
        // дата истечения срока действия карты 
        public CardExpirationDate[] CardExpirationDates(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<CardExpirationDate> objs = new List<CardExpirationDate>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != ISO7816.Tag.CardExpirationDate) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new CardExpirationDate(obj.Content)); 
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
