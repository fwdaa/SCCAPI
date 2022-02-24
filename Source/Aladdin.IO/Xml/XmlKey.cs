using System;
using System.Xml;
using System.IO;
using System.Security;
using System.Collections.Generic;

namespace Aladdin.IO.Xml
{
    ///////////////////////////////////////////////////////////////////////////
    // Иерархическая структура XML
    ///////////////////////////////////////////////////////////////////////////
    public sealed class XmlKey
    {
        // способ сохранения документа
        public delegate void Save(XmlDocument document); 

        // создать документ
        public static XmlKey CreateDocument(string fileName, string root)
        {
            // указать параметры записи
            XmlWriterSettings writeSettings = new XmlWriterSettings(); 

            // указать наличие отступов
            writeSettings.Indent = true;

            // создать документ 
            return CreateDocument(fileName, root, writeSettings); 
        }
        // создать документ
        public static XmlKey CreateDocument(
            string fileName, string root, XmlWriterSettings writeSettings)
        { 
            // проверить наличие параметров
            if (writeSettings == null) throw new ArgumentException(); 

            // проверить отсутствие файла
            if (File.Exists(fileName)) throw new IOException(); 

            // указать функцию сохранения документа
            Save save = delegate (XmlDocument doc)
            {
                // указать способ записи в файл
                using (XmlWriter writer = XmlWriter.Create(
                    fileName, writeSettings))
                {
                    // записать документ в файл
                    doc.WriteTo(writer); 
                }
            }; 
            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // создать корневой элемент
            XmlElement element = document.CreateElement(root); 
                    
            // добавить корневой элемент в документ
            document.AppendChild(element); save(document); 
            
            // вернуть документ
            return new XmlKey(document, save); 
        }
        // открыть документ
        public static XmlKey OpenDocument(string fileName, FileAccess access)
        {
            // указать отсутствие записи
            XmlWriterSettings writeSettings = null; if (access != FileAccess.Read)
            { 
                // указать наличие отступов
                writeSettings = new XmlWriterSettings(); writeSettings.Indent = true;
            }
            // открыть документ
            return OpenDocument(fileName, null, writeSettings); 
        }
        // открыть документ
        public static XmlKey OpenDocument(string fileName, 
            XmlReaderSettings readSettings, XmlWriterSettings writeSettings)
        { 
            // проверить наличие файла
            if (!File.Exists(fileName)) throw new IOException(); 

            // проверить наличие параметров
            if (readSettings == null) readSettings = new XmlReaderSettings(); 

            // указать функцию сохранения документа
            Save save = delegate (XmlDocument doc)
            {
                // указать способ записи в файл
                using (XmlWriter writer = XmlWriter.Create(
                    fileName, writeSettings))
                {
                    // записать документ в файл
                    doc.WriteTo(writer); 
                }
            }; 
            // проверить указание параметров записи
            if (writeSettings == null) save = null; 

            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // указать способ чтения XML
            using (XmlReader reader = XmlReader.Create(
                fileName, readSettings))
            { 
                // прочитать модель документа
                document.Load(reader); 
            }
            // вернуть документ
            return new XmlKey(document, save); 
        }
        // элемент и способ сохранения документа
        private XmlElement element; private Save save; 

        // конструктор
        public XmlKey(XmlDocument document, Save save)
        { 
            // проверить наличие корневого элемента
            if (document.DocumentElement == null) throw new IOException(); 

            // сохранить переданные параметры
            this.element = document.DocumentElement; this.save = save; 
        } 
        // конструктор
        public XmlKey(XmlElement element, Save save)
        { 
            // сохранить переданные параметры
            this.element = element; this.save = save; 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Перечислить элементы
        ///////////////////////////////////////////////////////////////////////
		public List<XmlKey> EnumerateKeys(FileAccess access)
        {
            // проверить соответствие доступа
            if (save == null && access != FileAccess.Read)
            {
                // выбросить исключение
                throw new SecurityException(); 
            }
            // создать список разделов реестра
            List<XmlKey> childs = new List<XmlKey>(); 

            // для всех дочерних элементов
            foreach (XmlNode child in element.ChildNodes)
            {
                // проверить тип элемента
                if (child.NodeType != XmlNodeType.Element) continue; 

                // добавить дочерний элемент
                childs.Add(new XmlKey((XmlElement)child, 
                    (access != FileAccess.Read) ? save : null
                )); 
            }
            return childs; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать новый элемент
        ///////////////////////////////////////////////////////////////////////
		public XmlKey CreateKey(string name)
        {
            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // указать используемый документ
            XmlDocument document = element.OwnerDocument; 

            // создать элемент
            XmlElement created = document.CreateElement(name); 

            // добавить элемент в документ
            element.AppendChild(created); save(document); 
            
            // вернуть созданный элемент
            return new XmlKey(created, save); 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Открыть или создать раздел
        ///////////////////////////////////////////////////////////////////////
		public XmlKey OpenOrCreateKey(string name)
        {
            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // для всех дочерних элементов
            foreach (XmlNode child in element.ChildNodes)
            {
                // проверить тип элемента
                if (child.NodeType != XmlNodeType.Element) continue; 

                // проверить имя элемента
                if (child.Name != name) continue; 

                 // вернуть дочерний элемент
                 return new XmlKey((XmlElement)child, save); 
            }
            // создать новый элемент
            return CreateKey(name); 
        } 
		///////////////////////////////////////////////////////////////////////
		// Открыть элемент
		///////////////////////////////////////////////////////////////////////
		public XmlKey OpenKey(string name, FileAccess access)
        {
            // проверить соответствие доступа
            if (save == null && access != FileAccess.Read)
            {
                // выбросить исключение
                throw new SecurityException(); 
            }
            // для всех дочерних элементов
            foreach (XmlNode child in element.ChildNodes)
            {
                // проверить тип элемента
                if (child.NodeType != XmlNodeType.Element) continue; 

                // проверить имя элемента
                if (child.Name != name) continue; 

                // вернуть дочерний элемент
                return new XmlKey((XmlElement)child, 
                    (access != FileAccess.Read) ? save : null
                ); 
            }
            return null; 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Удалить элемент
        ///////////////////////////////////////////////////////////////////////
		public void DeleteKey(XmlKey key)
        {
            // проверить соответствие элементов
            if (!Object.ReferenceEquals(key.element.ParentNode, element))
            {
                // выбросить исключение
                throw new InvalidOperationException(); 
            }
            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // получить документ элемента
            XmlDocument document = element.OwnerDocument; 

            // удалить подраздел
            element.RemoveChild(key.element); save(document); 
        }
		///////////////////////////////////////////////////////////////////////
        // Получить значение элемента
		///////////////////////////////////////////////////////////////////////
		public string GetValue() 
        { 
            // вернуть содержимое элемента
            return (!element.HasChildNodes) ? element.InnerText : null;
        }
		///////////////////////////////////////////////////////////////////////
        // Установить значение элемента
		///////////////////////////////////////////////////////////////////////
		public void SetValue(string value) 
        { 
            // проверить корректность операции
            if (element.HasChildNodes) throw new InvalidOperationException();

            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // установить значение элемента
            element.InnerText = (value != null) ? value : String.Empty; 
        }
		///////////////////////////////////////////////////////////////////////
        // Перечислить атрибуты
		///////////////////////////////////////////////////////////////////////
		public string[] EnumerateAttributes()
        {
            // создать список имен
            List<String> names = new List<String>(); 

            // для всех атрибутов элемента
            foreach (XmlAttribute attribute in element.Attributes)
            {
                // добавить имя атрибута
                names.Add(attribute.Name); 
            }
            // вернуть список имен
            return names.ToArray(); 
        }
		///////////////////////////////////////////////////////////////////////
        // Получить значение атрибута
		///////////////////////////////////////////////////////////////////////
		public string GetAttribute(string name, string def)
        {
            // для всех атрибутов элемента
            foreach (XmlAttribute attribute in element.Attributes)
            {
                // проверить совпадение имени
                if (attribute.Name != name) continue; 

                // вернуть значение атрибута
                return attribute.Value; 
            }
            return def; 
        }
		///////////////////////////////////////////////////////////////////////
        // Установить значение атрибута
		///////////////////////////////////////////////////////////////////////
		public void SetAttribute(string name, string value)
        {
            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // проверить наличие значения 
            if (value == null) value = String.Empty; 

            // получить документ элемента
            XmlDocument document = element.OwnerDocument; 

            // указать значение атрибута
            element.SetAttribute(name, value); save(document); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Удалить атрибут
        ///////////////////////////////////////////////////////////////////////
		public void DeleteAttribute(string name)
        {
            // проверить соответствие доступа
            if (save == null) throw new SecurityException(); 

            // получить документ элемента
            XmlDocument document = element.OwnerDocument; 

            // для всех атрибутов элемента
            foreach (XmlAttribute attribute in element.Attributes)
            {
                // проверить совпадение имени
                if (attribute.Name != name) continue; 

                // удалить атрибут
                element.RemoveAttributeNode(attribute); save(document); return; 
            }
        }
    }
}
