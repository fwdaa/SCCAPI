using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
    ///////////////////////////////////////////////////////////////////////////
    // Хранилище каталогов в файле конфигурации
    ///////////////////////////////////////////////////////////////////////////
    public class ConfigDirectories : IDirectoriesSource
    {
		// модель документа
		private IO.Xml.XmlKey document; 

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
            string configFile = String.Format("{0}{1}{2}", directory, 
                Path.DirectorySeparatorChar, configName
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
        // перечислить каталоги
        public virtual string[] EnumerateDirectories()
        {
            // проверить поддержку операции
            if (document == null) return new string[0]; 
        
            // создать список каталогов
            List<String> directories = new List<String>(); 
        
            // получить элемент для каталогов
            IO.Xml.XmlKey key = document.OpenKey("directories", FileAccess.Read); 
             
            // проверить наличие элемента
            if (key == null) return new string[0]; 

            // для всех каталогов
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(FileAccess.Read))
            {
                // добавить каталог в список
                directories.Add(child.GetValue());
            }
            // вернуть список каталогов
            return directories.ToArray(); 
        }
        // добавить каталог
        public virtual void AddDirectory(string directory)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для каталогов
            IO.Xml.XmlKey key = document.OpenOrCreateKey("directories"); 
             
            // добавить новый элемент 
            IO.Xml.XmlKey child = key.CreateKey("directory"); 

            // указать содержимое элемента
            child.SetValue(directory); 
        }
        // удалить каталог
        public virtual void RemoveDirectory(string directory)
        {
            // проверить поддержку операции
            if (document == null) throw new NotSupportedException(); 

            // получить элемент для каталогов
            IO.Xml.XmlKey key = document.OpenKey("directories", FileAccess.ReadWrite); 

            // проверить наличие элемента
            if (key == null) return; 

            // для всех каталогов
            foreach (IO.Xml.XmlKey child in key.EnumerateKeys(FileAccess.Read))
            {
                // проверить совпадение значения 
                if (child.GetValue() != directory) continue; 
                
                // удалить каталог
                key.DeleteKey(child); break; 
            }
        }
    }
}
