using System;
using System.IO;
using System.Xml;
using System.Collections.Generic;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры приложения
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigSection 
    {
	    // фабрики алгоритмов и генераторы случайных данных
        private List<ConfigFactory> factories; private List<ConfigRandFactory> rands;
	    // расширения криптографических культур и идентификаторы ключей
        private List<ConfigPlugin> plugins; private List<ConfigKey> keys; 

        // конструктор
        public static ConfigSection FromFile(string fileName)
        {
            // указать параметры по умолчанию
            XmlReaderSettings settings = new XmlReaderSettings(); 

            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // указать способ чтения XML
            using (XmlReader reader = XmlReader.Create(fileName, settings))
            { 
                // прочитать модель документа
                document.Load(reader); 
            }
            // прочитать параметры приложения
            return new ConfigSection(document); 
        }
        // конструктор
        public static ConfigSection FromStream(Stream stream)
        {
            // указать параметры по умолчанию
            XmlReaderSettings settings = new XmlReaderSettings(); 

            // создать объект документа 
            XmlDocument document = new XmlDocument(); 

            // указать способ чтения XML
            using (XmlReader reader = XmlReader.Create(stream, settings))
            { 
                // прочитать модель документа
                document.Load(reader); 
            }
            // прочитать параметры приложения
            return new ConfigSection(document); 
        }
        // конструктор
        public ConfigSection(XmlDocument document)
        {
            // создать пустые списки
            factories = new List<ConfigFactory>(); rands = new List<ConfigRandFactory>(); 
            plugins   = new List<ConfigPlugin >(); keys  = new List<ConfigKey        >(); 
        
            // получить элемент для фабрик
            XmlNodeList factoriesNodes = document.GetElementsByTagName("factories");
            
            // проверить наличие элемента
            if (factoriesNodes.Count > 0)
            {
                // получить дочерние элементы 
                XmlNodeList nodes = factoriesNodes[0].ChildNodes; 
            
                // для всех элементов
                for (int i = 0; i < nodes.Count; i++) 
                {
                    // проверить тип элемента
                    if (nodes[i].NodeType != XmlNodeType.Element) continue;                
                
                    // добавить элемент в список
                    factories.Add(new ConfigFactory((XmlElement)nodes[i]));
                }
            }
            // получить элемент для генераторов случайных данных
            XmlNodeList randsNodes = document.GetElementsByTagName("rands");
            
            // проверить наличие элемента
            if (randsNodes.Count > 0)
            {
                // получить дочерние элементы 
                XmlNodeList nodes = randsNodes[0].ChildNodes; 
            
                // для всех элементов
                for (int i = 0; i < nodes.Count; i++) 
                {
                    // проверить тип элемента
                    if (nodes[i].NodeType != XmlNodeType.Element) continue;                

                    // раскодировать элемент генератора случайных данных
                    rands.Add(new ConfigRandFactory((XmlElement)nodes[i]));
                }
            }
            // получить элемент для расширений криптографических культур
            XmlNodeList pluginsNodes = document.GetElementsByTagName("plugins");
            
            // проверить наличие элемента
            if (pluginsNodes.Count > 0)
            {
                // получить дочерние элементы 
                XmlNodeList nodes = pluginsNodes[0].ChildNodes; 
            
                // для всех элементов
                for (int i = 0; i < nodes.Count; i++) 
                {
                    // проверить тип элемента
                    if (nodes[i].NodeType != XmlNodeType.Element) continue;                

                    // раскодировать элемент расширения криптографической культуры
                    plugins.Add(new ConfigPlugin((XmlElement)nodes[i]));
                }
            }
            // получить элемент для идентификаторов ключей
            XmlNodeList keysNodes = document.GetElementsByTagName("keys");
            
            // проверить наличие элемента
            if (keysNodes.Count > 0)
            {
                // получить дочерние элементы 
                XmlNodeList nodes = keysNodes[0].ChildNodes; 
            
                // для всех элементов
                for (int i = 0; i < nodes.Count; i++) 
                {
                    // проверить тип элемента
                    if (nodes[i].NodeType != XmlNodeType.Element) continue;                

                    // раскодировать элемент идентификатора ключа
                    keys.Add(new ConfigKey((XmlElement)nodes[i]));
                }
            }
        }
	    // фабрики алгоритмов
	    public List<ConfigFactory    > Factories { get { return factories; }}
	    // генераторы случайных данных
	    public List<ConfigRandFactory> Rands     { get { return rands;     }}
	    // расширения криптографических культур
	    public List<ConfigPlugin     > Plugins   { get { return plugins;   }}
	    // идентификаторы ключей
	    public List<ConfigKey        > Keys      { get { return keys;      }}
    }
}
