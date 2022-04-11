using System;
using System.IO;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания фабрики классов
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigFactory 
    {
        // имя фабрики и класса фабрики
        private string name; private string className; 
    
        // конструктор
        public ConfigFactory(XmlElement element)
        {
            // получить имя элемента 
            name = element.GetAttribute("name"); 
            // проверить наличие имени элемента
            if (name.Length == 0) throw new IOException(); 
        
            // получить класс фабрики
            className = element.GetAttribute("class"); 
            // проверить наличие класса фабрики
            if (className.Length == 0) throw new IOException(); 
        }
        // имя элемента
        public string Name { get { return name; }}
        // класс фабрики
        public string Class { get { return className; }}
    }
}