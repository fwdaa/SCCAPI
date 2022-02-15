using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace Aladdin.CAPI.Software
{
    ///////////////////////////////////////////////////////////////////////////
    // Хранилище каталогов в реестре
    ///////////////////////////////////////////////////////////////////////////
    public class RegistryDirectories : IDirectoriesSource
    {
		// имя раздела реестра
		private RegistryKey root; private string keyName; 

		// конструктор
		public RegistryDirectories(Scope scope, string keyName)
		{ 
            // определить ветвь реестра
            this.root = (scope == Scope.System) ? Registry.LocalMachine : Registry.CurrentUser; 

            // сохранить переданные параметры
            this.keyName = keyName; 
		}
        // признак перенаправления
        public bool HasRedirect()
        {
			// открыть раздел реестра
			using (RegistryKey key = this.root.OpenSubKey(keyName)) 
			{
    		    // проверить наличие раздела
				if (key == null) return false; 

                // прочитать значение по умолчанию 
                string value = (string)key.GetValue(null, String.Empty); 

                // проверить наличие перенаправления
                return String.Compare(value, "redirect", true) == 0; 
            }
        }
        // перечислить каталоги
        public virtual string[] EnumerateDirectories()
        {
			// открыть раздел реестра
			using (RegistryKey key = this.root.OpenSubKey(keyName)) 
			{
    		    // проверить наличие раздела
				if (key == null) return new string[0]; 

                // создать список каталогов
                List<String> directories = new List<String>(); 
                    
    		    // для каждого имени
                foreach (string name in key.GetValueNames())
			    try {
                    // прочитать имя каталога
                    string directory = (string)key.GetValue(name); 

				    // добавить имя каталога в список
				    directories.Add(directory); 
			    }
                // вернуть список каталогов
                catch {} return directories.ToArray(); 
			}
        }
        // добавить каталог
        public virtual void AddDirectory(string directory)
        {
		    // открыть раздел реестра
		    using (RegistryKey key = root.CreateSubKey(keyName)) 
		    {
                // указать имя значения
                string valueName = String.Format("{{{0}}}", Guid.NewGuid()); 

                // добавить имя каталога в реестр
                key.SetValue(valueName, directory); 
            }
        }
        // удалить каталог
        public virtual void RemoveDirectory(string directory)
        {
		    // открыть раздел реестра
			using (RegistryKey key = root.OpenSubKey(keyName, true)) 
			{
                // создать список каталогов
                if (key == null) return; 
                
                // для всех значений
                foreach (string valueName in key.GetValueNames())
                {
                    // прочитать значение
                    string value = (string)key.GetValue(valueName); 

                    // удалить значение раздела реестра
                    if (value == directory) key.DeleteValue(valueName);
                }
            }
        }
    }
}
