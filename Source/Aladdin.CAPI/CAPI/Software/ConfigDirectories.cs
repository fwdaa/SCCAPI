using System;
using System.IO;
using System.Xml;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
    ///////////////////////////////////////////////////////////////////////////
    // Хранилище каталогов в файле конфигурации
    ///////////////////////////////////////////////////////////////////////////
    public class ConfigDirectories : IDirectoriesSource
    {
		// имя файла конфигурации и модель документа
		private string configFile; private XmlDocument document; 

		// конструктор
		public ConfigDirectories(Scope scope, string configName)
		{ 
            // указать тип каталога
            Environment.SpecialFolder type = (scope == Scope.System) ? 
                Environment.SpecialFolder.CommonApplicationData : 
                Environment.SpecialFolder.ApplicationData; 

            // получить профиль пользователя
            string directory = Environment.GetFolderPath(type); 

            // указать полный путь к файлу
            configFile = String.Format("{0}{1}{2}", directory, 
                Path.DirectorySeparatorChar, configName); 
            try {
                // при наличии файла
                if (File.Exists(configFile))
                {
                    // прочитать модель документа
                    document =  IO.Xml.DOM.ReadDocument(configFile, null); 
                }
                // при отсутствии файла создать пустой документ
                else document = IO.Xml.DOM.CreateDocument("configuration"); 
            }
            catch {} 
		}  
        // перечислить каталоги
        public virtual string[] EnumerateDirectories()
        {
            // проверить поддержку операции
            if (document == null) return new string[0]; 
        
            // получить элемент для каталогов
            XmlNodeList directoriesNodes = document.GetElementsByTagName("directories");
        
            // проверить наличие элемента
            if (directoriesNodes.Count == 0) return new string[0]; 
        
            // создать список каталогов
            List<String> directories = new List<String>(); 
        
            // для всех каталогов
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(directoriesNodes[0])) 
            try {
                // добавить каталог в список
                directories.Add(element.InnerText);
            }
            // вернуть список каталогов
            catch {} return directories.ToArray(); 
        }
        // добавить каталог
        public virtual void AddDirectory(string directory)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для каталогов
            XmlNodeList directoriesNodes = document.GetElementsByTagName("directories"); 
            
            // при отсутствии элемента
            XmlElement directoriesNode = null; if (directoriesNodes.Count == 0)
            {
                // создать новый элемент
                directoriesNode = document.CreateElement("directories"); 
            
                // добавить элемент в документ
                document.DocumentElement.AppendChild(directoriesNode); 
            }
            // сохранить элемент для каталогов
            else { directoriesNode = (XmlElement)directoriesNodes[0]; }
                
            // создать новый элемент
            XmlElement directoryNode = document.CreateElement("directory"); 

            // добавить элемент в документ
            directoriesNode.AppendChild(directoryNode); 

            // указать путь к каталогу
            directoryNode.InnerText = directory; 

            // записать документ в файл
            IO.Xml.DOM.WriteDocument(document, configFile, null); 
        }
        // удалить каталог
        public virtual void RemoveDirectory(string directory)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для каталогов
            XmlNodeList directoriesNodes = document.GetElementsByTagName("directories"); 
            
            // при отсутствии элемента
            XmlElement directoriesNode = null; if (directoriesNodes.Count == 0)
            {
                // создать новый элемент
                directoriesNode = document.CreateElement("directories"); 
            
                // добавить элемент в документ
                document.DocumentElement.AppendChild(directoriesNode); 
            }
            // сохранить элемент для каталогов
            else { directoriesNode = (XmlElement)directoriesNodes[0]; }
                
            // для всех каталогов
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(directoriesNode)) 
            {
                // сравнить имена каталогов
                if (directory == element.InnerText)
                { 
                    // удалить элемент 
                    directoriesNode.RemoveChild(element); 

                    // записать документ в файл
                    IO.Xml.DOM.WriteDocument(document, configFile, null); break; 
                }
            }
        }
    }
}
