using System;
using System.IO;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания генератора случайных данных
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigRandFactory 
    {
        // имя элемента, имя класса фабрики и признак наличия GUI
        private string name; private string className; private string gui; 
    
        // конструктор
        public ConfigRandFactory(XmlElement element)
        {
            // получить имя элемента 
            name = element.GetAttribute("name"); 
            // проверить наличие имени элемента
            if (name.Length == 0) throw new IOException(); 
        
            // получить класс фабрики
            className = element.GetAttribute("class"); 
            // проверить наличие класса фабрики
            if (className.Length == 0) throw new IOException(); 

            // получить признак наличия GUI
            gui = element.GetAttribute("gui"); 
        }
        // имя элемента
        public string Name { get { return name; }}
        // класс фабрики
        public string Class { get { return className; }} 
    
        // признак наличия GUI
        public bool GUI { get  
        { 
            // признак наличия GUI
            return (gui.Length > 0) ? Boolean.Parse(gui) : false; 
        }} 
    }
}
