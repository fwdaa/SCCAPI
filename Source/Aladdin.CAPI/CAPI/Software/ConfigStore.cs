using System;
using System.IO;
using System.Xml;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Раздел файла конфигурации как хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class ConfigStore : ContainerStore
	{
		// имя файла конфигурации и модель документа
		private string configFile; private XmlDocument document; 

		// конструктор
		public ConfigStore(CryptoProvider provider, Scope scope, string configName) 
            
            // сохранить переданные параметры
            : base(provider, scope) 
        {
            // указать тип каталога
            Environment.SpecialFolder type = (scope == Scope.System) ? 
                Environment.SpecialFolder.CommonApplicationData : 
                Environment.SpecialFolder.ApplicationData; 

            // получить профиль пользователя
            string directory = Environment.GetFolderPath(type); 

            // указать полный путь к файлу
            configFile = String.Format("{0}{1}{2}", 
                directory, Path.DirectorySeparatorChar, configName
            ); 
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
        // имя хранилища
        public override object Name
        {
            // имя хранилища
            get { return (Scope == Scope.System) ? "FSLM" : "FSCU"; }
        }
		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
		public override string[] EnumerateObjects()
		{
            // проверить поддержку операции
            if (document == null) return new string[0]; 

            // получить элемент для контейнеров
            XmlNodeList containersNodes = document.GetElementsByTagName("containers");
            
            // проверить наличие элемента
            if (containersNodes.Count == 0) return new string[0]; 
        
            // создать список имен
            List<String> names = new List<String>(); 

            // для всех контейнеров
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(containersNodes[0])) 
            try {
                // получить имя контейнера
                string name = element.GetAttribute("name"); 

                // добавить имя контейнера в список
                if (name.Length != 0) names.Add(name);
            }
	        // вернуть список имен
            catch {} return names.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление физическими потоками
		///////////////////////////////////////////////////////////////////////
        protected override ContainerStream CreateStream(object name)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            XmlNodeList containersNodes = document.GetElementsByTagName("containers"); 
            
            // при отсутствии элемента
            XmlElement containersNode = null; if (containersNodes.Count == 0)
            {
                // создать новый элемент
                containersNode = document.CreateElement("containers"); 
            
                // добавить элемент в документ
                document.DocumentElement.AppendChild(containersNode); 
            }
            // сохранить элемент для контейнеров
            else { containersNode = (XmlElement)containersNodes[0]; }
                
            // для всех контейнеров
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(containersNode)) 
            {
                // сравнить имена контейнеров
                if (String.Compare(element.GetAttribute("name"), (string)name, true) == 0) 
                { 
                    // проверить отсутствие элемента
                    throw new IOException(); 
                }
            }
            // создать новый элемент
            XmlElement containerNode = document.CreateElement("container"); 

            // добавить элемент в документ
            containersNode.AppendChild(containerNode); 

            // указать имя элемента 
            containerNode.SetAttribute("name", (string)name); 

            // вернуть поток данных в файле конфигурации
            return new ReadWriteElementStream(configFile, document, containerNode); 
        }
        protected override ContainerStream OpenStream(object name, FileAccess access)
        {
            // проверить поддержку операции
            if (configFile == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            XmlNodeList containersNodes = document.GetElementsByTagName("containers"); 
            
            // проверить наличие элемента
            if (containersNodes.Count == 0) throw new NotFoundException(); 

            // получить элемент для контейнеров
            XmlElement containersNode = (XmlElement)containersNodes[0];
        
            // для всех контейнеров
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(containersNode)) 
            {
                // сравнить имена контейнеров
                if (String.Compare(element.GetAttribute("name"), (string)name, true) == 0) 
                { 
                    // вернуть поток данных в файле конфигурации
                    if (access == FileAccess.Read) return new ReadElementStream(element); 

                    // вернуть поток данных в файле конфигурации
                    else return new ReadWriteElementStream(configFile, document, element); 
                }
            }
            // проверить наличие элемента
            throw new NotFoundException(); 
        }
        protected override void DeleteStream(object name)
        {
            // проверить поддержку операции
            if (configFile == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            XmlNodeList containersNodes = document.GetElementsByTagName("containers"); 
            
            // проверить наличие элемента
            if (containersNodes.Count == 0) return; 

            // получить элемент для контейнеров
            XmlElement containersNode = (XmlElement)containersNodes[0];
        
            // для всех контейнеров
            foreach (XmlElement element in IO.Xml.DOM.ReadElements(containersNode)) 
            {
                // сравнить имена контейнеров
                if (String.Compare(element.GetAttribute("name"), (string)name, true) == 0) 
                { 
                    // удалить элемент 
                    containersNode.RemoveChild(element); 
            
                    // записать документ в файл
                    IO.Xml.DOM.WriteDocument(document, configFile, null); 
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
        // Поток хранилища данных в файле конфигурации (только для чтения)
	    ///////////////////////////////////////////////////////////////////////////
	    private class ReadElementStream : ContainerStream
        {
            // узел элемента
            private XmlElement containerNode; 

	        // конструктор
	        public ReadElementStream(XmlElement containerNode)
	        {
                // сохранить переданные параметры
                this.containerNode = containerNode; 
            }
            // узел элемента
            protected XmlElement ContainerNode { get { return containerNode; }}
        
            // имя контейнера
            public override object Name { get { return UniqueID; }}
        
            // уникальный идентификатор
            public override string UniqueID 
            { 
                // уникальный идентификатор
                get { return containerNode.GetAttribute("name"); }
            }
            // прочитать данные
            public override byte[] Read()
            {
                // получить содержимое элемента
                return Base64.GetDecoder().Decode(containerNode.InnerText); 
            }
            // записать данные
		    public override void Write(byte[] buffer)
		    {
                // выбрость исключение
                throw new IOException(); 
		    }
	    }
	    ///////////////////////////////////////////////////////////////////////////
        // Поток хранилища данных в файле конфигурации (для чтения и записи)
	    ///////////////////////////////////////////////////////////////////////////
	    private class ReadWriteElementStream : ReadElementStream
        {
            // имя файла и модель документа
            private string configFile; private XmlDocument document; 
        
	        // конструктор
	        public ReadWriteElementStream(string configFile, 
                XmlDocument document, XmlElement containerNode) : base(containerNode) 
	        {
                // сохранить переданные параметры
                this.configFile = configFile; this.document = document; 
            }
            // записать данные
		    public override void Write(byte[] buffer)
		    {
                // записать данные
                ContainerNode.InnerText = Base64.GetEncoder().EncodeToString(buffer); 

                // записать документ в файл
                IO.Xml.DOM.WriteDocument(document, configFile, null); 
		    }
	    }

	}
}
