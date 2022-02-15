using System;
using System.IO;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания генератора случайных данных
    ///////////////////////////////////////////////////////////////////////////
    public class ConfigRand 
    {
        // имя элемента, имя класса фабрики и признак обязательного использования 
        private string name; private string className; private string critical; 
    
        // конструктор
        public ConfigRand(XmlElement element)
        {
            // получить имя элемента 
            name = element.GetAttribute("name"); 
            // проверить наличие имени элемента
            if (name.Length == 0) throw new IOException(); 
        
            // получить класс фабрики
            className = element.GetAttribute("class"); 
            // проверить наличие класса фабрики
            if (className.Length == 0) throw new IOException(); 

            // получить признак обязательного использования
            critical = element.GetAttribute("critical"); 
        }
        // имя элемента
        public string Name { get { return name; }}
        // класс фабрики
        public string Class { get { return className; }} 
    
        // признак обязательного использования
        public bool Critical { get  
        { 
            // признак обязательного использования
            return (critical.Length > 0) ? Boolean.Parse(critical) : false; 
        }} 
    }
}
