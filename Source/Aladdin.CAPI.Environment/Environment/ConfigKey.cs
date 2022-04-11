using System;
using System.IO;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания идентификатора ключа
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigKey 
    {
        // идентификатор ключа, отображаемое имя
        private string oid; private string name;
        // имя расширения и класс культуры 
        private string plugin; private string className;
    
        // конструктор
        public ConfigKey(XmlElement element)
        {
            // получить идентификатор ключа
            oid = element.GetAttribute("oid"); 
            // проверить наличие идентификатора ключа
            if (oid.Length == 0) throw new IOException(); 
        
            // получить отображаемое имя
            name = element.GetAttribute("name"); 
            // проверить наличие отображаемого имени
            if (name.Length == 0) throw new IOException(); 
        
            // получить имя расширения 
            plugin = element.GetAttribute("plugin"); 
            // проверить наличие имени расширения 
            if (plugin.Length == 0) throw new IOException(); 

            // получить класс культуры
            className = element.GetAttribute("class"); 
            // проверить наличие класса культуры
            if (className.Length == 0) throw new IOException(); 
        }
        // идентификатор ключа
        public string OID { get { return oid; }} 
        // отображаемое имя
        public string Name { get { return name; }}
        // имя расширения 
        public string Plugin { get { return plugin; }}
        // класс культуры 
        public string Class { get { return className; }}
    }
}
