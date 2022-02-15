using System;
using System.Collections.Generic;
using System.Xml;

namespace Aladdin.IO.Xml
{
    ///////////////////////////////////////////////////////////////////////////////
    // Утилиты для работы с XML
    ///////////////////////////////////////////////////////////////////////////////
    public static class DOM 
    {
        // создать документ
        public static XmlDocument CreateDocument(string rootElement)
        {
            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // создать корневой элемент
            XmlElement element = document.CreateElement(rootElement); 
                    
            // добавить корневой элемент в документ
            document.AppendChild(element); return document; 
        }
        // прочитать документ
        public static XmlDocument ReadDocument(string inputFile, XmlReaderSettings settings)
        {
            // указать параметры по умолчанию
            if (settings == null) settings = new XmlReaderSettings(); 

            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // указать способ чтения XML
            using (XmlReader reader = XmlReader.Create(inputFile, settings))
            { 
                // прочитать модель документа
                document.Load(reader); 
            }
            return document; 
        }
        // прочитать дочерние элементы 
        public static XmlElement[] ReadElements(XmlNode node)
        {
            // создать список элементов
            List<XmlElement> elements = new List<XmlElement>(); 
        
            // получить дочерние элементы 
            XmlNodeList nodes = node.ChildNodes; 
            
            // для всех элементов
            for (int i = 0; i < nodes.Count; i++) 
            {
                // проверить тип элемента
                if (nodes[i].NodeType != XmlNodeType.Element) continue;                
                
                // добавить элемент в список
                elements.Add((XmlElement)nodes[i]);
            }
            // вернуть список элементов
            return elements.ToArray(); 
        }
        // записать документ
        public static void WriteDocument(XmlDocument document, 
            string outputFile, XmlWriterSettings settings)
        {
            // указать параметры по умолчанию
            if (settings == null) { settings = new XmlWriterSettings(); 

                // указать наличие форматирования
                settings.Indent = true; 
            }
            // указать способ записи в файл
            using (XmlWriter writer = XmlWriter.Create(outputFile, settings))
            {
                // записать документ в файл
                document.WriteTo(writer); 
            }
        }
    }
}
