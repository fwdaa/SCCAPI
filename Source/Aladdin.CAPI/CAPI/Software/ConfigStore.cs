using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Раздел файла конфигурации как хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class ConfigStore : ContainerStore
	{
		// модель документа
		private IO.Xml.XmlKey document; 

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
            string configFile = String.Format("{0}{1}{2}", 
                directory, Path.DirectorySeparatorChar, configName
            ); 
            try {
                // при отсутствии файла
                if (!File.Exists(configFile))
                {
                    // создать документ
                    document = IO.Xml.XmlKey.CreateDocument(
                        configFile, "configuration"
                    ); 
                }
                else {
                    // открыть документ
                    document = IO.Xml.XmlKey.OpenDocument(
                        configFile, FileAccess.ReadWrite
                    ); 
                }
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

            // создать список имен
            List<String> names = new List<String>(); 

            // получить элемент для контейнеров
            IO.Xml.XmlKey key = document.OpenKey("containers", FileAccess.Read); 
             
            // проверить наличие элемента
            if (key == null) return new string[0]; 

            // для всех каталогов
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(FileAccess.Read))
            {
                // добавить каталог в список
                names.Add(child.GetAttribute("name", null));
            }
	        // вернуть список имен
            return names.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление физическими потоками
		///////////////////////////////////////////////////////////////////////
        protected override ContainerStream CreateStream(object name)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            IO.Xml.XmlKey key = document.OpenOrCreateKey("containers"); 
             
            // для всех контейнеров
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(FileAccess.Read))
            {
                // получить имя контейнера
                string value = child.GetAttribute("name", null); 

                // сравнить имена контейнеров
                if (String.Compare(value, name.ToString(), true) == 0) 
                { 
                    // проверить отсутствие элемента
                    throw new IOException(); 
                }
            }
            // добавить новый элемент 
            IO.Xml.XmlKey created = document.CreateKey("container"); 
            
            // указать имя контейнера
            created.SetAttribute("name", name.ToString()); 
            
            // вернуть поток данных в файле конфигурации
            return new ElementStream(created);
        }
        protected override ContainerStream OpenStream(object name, FileAccess access)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            IO.Xml.XmlKey key = document.OpenKey("containers", access); 

            // проверить наличие элемента
            if (key == null) throw new NotFoundException(); 

            // для всех контейнеров
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(access))
            {
                // получить имя контейнера
                string value = child.GetAttribute("name", null); 

                // сравнить имена контейнеров
                if (String.Compare(value, (string)name, true) == 0) 
                { 
                    // вернуть поток данных в файле конфигурации
                    return new ElementStream(child); 
                }
            }
            // контейнер не найден
            throw new NotFoundException(); 
        }
        protected override void DeleteStream(object name)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для контейнеров
            IO.Xml.XmlKey key = document.OpenKey("containers", FileAccess.ReadWrite); 
             
            // проверить наличие элемента
            if (key == null) return; 

            // для всех контейнеров
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(FileAccess.Read))
            {
                // получить имя контейнера
                string value = child.GetAttribute("name", null); 

                // сравнить имена контейнеров
                if (String.Compare(value, (string)name, true) == 0) 
                { 
                    // удалить контейнер
                    key.DeleteKey(child); return; 
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
        // Поток хранилища данных в файле конфигурации (только для чтения)
	    ///////////////////////////////////////////////////////////////////////////
	    private class ElementStream : ContainerStream
        {
            // узел элемента
            private IO.Xml.XmlKey element; 

	        // конструктор
	        public ElementStream(IO.Xml.XmlKey element)
	        {
                // сохранить переданные параметры
                this.element = element; 
            }
            // имя контейнера
            public override object Name { get { return UniqueID; }}
        
            // уникальный идентификатор
            public override string UniqueID 
            { 
                // уникальный идентификатор
                get { return element.GetAttribute("name", null); }
            }
            // прочитать данные
            public override byte[] Read()
            {
                // раскодировать содержимое элемента
                return Base64.GetDecoder().Decode(element.GetValue()); 
            }
            // записать данные
		    public override void Write(byte[] buffer)
		    {
                // записать данные
                element.SetValue(Base64.GetEncoder().EncodeToString(buffer)); 
		    }
	    }
	}
}
