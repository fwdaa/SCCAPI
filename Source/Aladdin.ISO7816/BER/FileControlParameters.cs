using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон FCP (0x62)
    ///////////////////////////////////////////////////////////////////////////
    public class FileControlParameters : DataObjectTemplate
    {
        // конструктор закодирования
        public FileControlParameters(params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.FileControlParameters, objects) {}

        // конструктор раскодирования
        public FileControlParameters(TagScheme tagScheme, byte[] content)
        
            // проверить корректность данных
            : base(Authority.ISO7816, ISO7816.Tag.FileControlParameters, tagScheme, content) {} 

        // объединить объекты описания
        public FileControlParameters Combine(DataObjectTemplate objects)
        {
            // проверить наличие объектов
            if (objects == null) return this; 

            // создать список объектов
            List<DataObject> objs = new List<DataObject>(this); 

            // добавить объекты в список
            objs.AddRange(objects); return new FileControlParameters(objs.ToArray()); 
        }
        // переопределение схемы кодирования объектов
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
        // переопределение схемы кодирования данных
        public DataCoding GetDataCoding(DataCoding dataCoding)
        {
            // получить схему кодирования объектов
            TagScheme tagScheme = GetTagScheme(dataCoding.TagScheme); 
        
            // получить дескриптор файла
            DataObject[] objs = this[Tag.Context(0x02, ASN1.PC.Primitive)]; 
        
            // проверить наличие дескриптора
            if (objs.Length == 0) return new DataCoding(dataCoding, tagScheme); 
        
            // получить содержимое
            byte[] content = objs[0].Content; if (content.Length < 2)
            {
                // вернуть значение по умолчанию
                return new DataCoding(dataCoding, tagScheme);
            }
            // вернуть способ кодирования данных
            return new DataCoding(tagScheme, content[1]);
        }
        // определить структуру файла
        public FileStructure FileStructure { get  
        {
            // получить дескриптор файла
            DataObject[] objs = this[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return FileStructure.Unknown; 

            // получить содержимое
            byte[] content = objs[0].Content; 
            
            // проверить размер содержимого
            if (content.Length < 1 || (content[0] & 0x80) != 0)
            {
                // указать значение по умолчанию
                return FileStructure.Unknown; 
            }
            // в зависимости установленных битов
            if (((content[0] >> 3) & 0x7) != 0x7)
            {
                // в зависимости установленных битов
                switch (content[0] & 0x7)
                {
                case 0x1: return FileStructure.Transparent;
                case 0x2: return FileStructure.LinearFixed;
                case 0x3: return FileStructure.LinearFixedTLV;
                case 0x4: return FileStructure.LinearVariable;
                case 0x5: return FileStructure.LinearVariableTLV;
                case 0x6: return FileStructure.CyclicFixed;
                case 0x7: return FileStructure.CyclicFixedTLV;
                }
            }
            else {
                // в зависимости установленных битов
                switch (content[0] & 0x7)
                {
                case 0x1: return FileStructure.DataObjectBERTLV;
                case 0x2: return FileStructure.DataObjectSimpleTLV;
                }
            }
            // структура файла неизвестна
            return FileStructure.Unknown;
        }}
        // идентификатор файла
        public ushort? ID { get 
        { 
            // найти объект
            DataObject[] objs = this[Tag.Context(0x03, ASN1.PC.Primitive)]; if (objs.Length == 0) return null; 
        
            // получить содержимое
            byte[] content = objs[0].Content; if (content.Length != 2) return null; 
        
            // раскодировать идентификатор
            return (ushort)((content[0] << 8) | content[1]); 
        }}
        // общий размер байтов
        public int? TotalBytes { get 
        {
            // найти объект
            DataObject[] objs = this[Tag.Context(0x01, ASN1.PC.Primitive)]; if (objs.Length == 0) return null; 
        
            // получить содержимое
            byte[] content = objs[0].Content; if (content.Length != 2) return null; 
        
            // скопировать значимые байты
            byte[] value = new byte[4]; Array.Copy(content, 0, value, 2, 2);
        
            // раскодировать общий размер данных
            return (content[0] << 8) | content[1]; 
        }}
        // стадия жизненного цикла
        public LifeCycle LifeCycle { get  
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x0A, ASN1.PC.Primitive); 

            // найти объект
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new LifeCycle(tag, objs[0].Content); 
        }}
        // произвольные данные
        public DiscretionaryData[] DisсretionaryData { get
        {
            // создать список внутренних объектов
            List<DiscretionaryData> objs = new List<DiscretionaryData>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != Tag.Context(0x05, ASN1.PC.Primitive)) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new DiscretionaryData(obj.Tag, obj.Content)); 
            }
            // вернуть внутренние объекты
            return objs.ToArray(); 
        }}
        // шаблон произвольные данные
        public DiscretionaryTemplate[] DisсretionaryTemplates(TagScheme tagScheme) 
        {
            // создать список внутренних объектов
            List<DiscretionaryTemplate> objs = new List<DiscretionaryTemplate>(); 

            // для всех внутренних объектов
            foreach (DataObject obj in this) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag != Tag.Context(0x05, ASN1.PC.Constructed)) continue; 
                
                // добавить внутренний объект в список
                objs.Add(new DiscretionaryTemplate(obj.Tag, tagScheme, obj.Content)); 
            }
            // вернуть внутренние объекты
            return objs.ToArray(); 
        }
    }
}
