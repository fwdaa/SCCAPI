using System;
using System.Xml;
using System.Collections.Generic;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры приложения
    ///////////////////////////////////////////////////////////////////////////
    public class ConfigSection 
    {
	    // фабрики алгоритмов и генераторы случайных данных
        private List<ConfigFactory> factories; private List<ConfigRand> rands;
	    // расширения криптографических культур и идентификаторы ключей
        private List<ConfigPlugin> plugins; private List<ConfigKey> keys; 

        // конструктор
        public static ConfigSection FromFile(string fileName)
        {
            // прочитать параметры приложения
            return new ConfigSection(IO.Xml.DOM.ReadDocument(fileName, null)); 
        }
        // конструктор
        public ConfigSection(XmlDocument document)
        {
            // создать пустые списки
            factories = new List<ConfigFactory>(); rands = new List<ConfigRand>(); 
            plugins   = new List<ConfigPlugin >(); keys  = new List<ConfigKey >(); 
        
            // получить элемент для фабрик
            XmlNodeList factoriesNodes = document.GetElementsByTagName("factories");
            
            // проверить наличие элемента
            if (factoriesNodes.Count > 0)
            {
                // для всех фабрик
                foreach (XmlElement element in IO.Xml.DOM.ReadElements(factoriesNodes[0])) 
                try {
                    // раскодировать элемент фабрики
                    factories.Add(new ConfigFactory(element));
                }
                catch {}
            }
            // получить элемент для генераторов случайных данных
            XmlNodeList randsNodes = document.GetElementsByTagName("rands");
            
            // проверить наличие элемента
            if (randsNodes.Count > 0)
            {
                // для всех генераторов случайных данных
                foreach (XmlElement element in IO.Xml.DOM.ReadElements(randsNodes[0])) 
                try {
                    // раскодировать элемент генератора случайных данных
                    rands.Add(new ConfigRand(element));
                }
                catch {}
            }
            // получить элемент для расширений криптографических культур
            XmlNodeList pluginsNodes = document.GetElementsByTagName("plugins");
            
            // проверить наличие элемента
            if (pluginsNodes.Count > 0)
            {
                // для всех расширений криптографических культур
                foreach (XmlElement element in IO.Xml.DOM.ReadElements(pluginsNodes[0])) 
                try {
                    // раскодировать элемент расширения криптографической культуры
                    plugins.Add(new ConfigPlugin(element));
                }
                catch {}
            }
            // получить элемент для идентификаторов ключей
            XmlNodeList keysNodes = document.GetElementsByTagName("keys");
            
            // проверить наличие элемента
            if (keysNodes.Count > 0)
            {
                // для всех идентификаторов ключей
                foreach (XmlElement element in IO.Xml.DOM.ReadElements(keysNodes[0])) 
                try {
                    // раскодировать элемент идентификатора ключа
                    keys.Add(new ConfigKey(element));
                }
                // вернуть список имен
                catch {}
            }
        }
	    // фабрики алгоритмов
	    public List<ConfigFactory> Factories { get { return factories; }}
	    // генераторы случайных данных
	    public List<ConfigRand   > Rands     { get { return rands;     }}
	    // расширения криптографических культур
	    public List<ConfigPlugin > Plugins   { get { return plugins;   }}
	    // идентификаторы ключей
	    public List<ConfigKey    > Keys      { get { return keys;      }}
    }
}
