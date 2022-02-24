using System;
using System.IO;

namespace Aladdin.IO
{
    ///////////////////////////////////////////////////////////////////////////
    // Раздел реестра 
    ///////////////////////////////////////////////////////////////////////////
    public sealed class RegistryKey : RefObject
    {
        // раздел реестра администратора безопасности
        private Microsoft.Win32.RegistryKey registryKey; 

        // конструктор
        public RegistryKey(Microsoft.Win32.RegistryKey registryKey)
        {    
            // сохранить переданные параметры
            this.registryKey = registryKey; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            registryKey.Dispose(); base.OnDispose(); 
        }
        // полное имя раздела реестра
        public string FullName { get { return registryKey.Name; } }

        ///////////////////////////////////////////////////////////////////////
        // Перечислить разделы реестра
        ///////////////////////////////////////////////////////////////////////
		public string[] EnumerateKeys(string path) 
        { 
		    // открыть раздел реестра
            using (RegistryKey key = OpenKey(path, FileAccess.Read))  
            {
                // проверить наличие раздела
                if (key == null) return new string[0]; 
            
                // перечислить разделы реестра
                return key.EnumerateKeys(); 
            }
        } 
        // перечислить разделы реестра
		public string[] EnumerateKeys() { return registryKey.GetSubKeyNames(); }

		///////////////////////////////////////////////////////////////////////
		// Открыть для записи или создать раздел реестра
		///////////////////////////////////////////////////////////////////////
		public RegistryKey OpenOrCreateKey(string path)
        {
            // извлечь отдельные компоненты пути
            string[] names = (path != null) ? path.Split('\\') : new string[0]; 

            // указать начальные условия
            RegistryKey parent = RefObject.AddRef(this);

            // для всех компонентов пути
            for (int i = 0; i < names.Length; i++)
            {
                // открыть раздел реестра
                RegistryKey key = parent.DoOpenOrCreateKey(names[i]); 
                
                // закрыть родительский раздел
                RefObject.Release(parent); parent = key; 
            }
            return parent; 
        } 
		// открыть для записи или создать раздел реестра
		private RegistryKey DoOpenOrCreateKey(string key)
        {
			// открыть для записи или создать раздел реестра
			Microsoft.Win32.RegistryKey regKey = registryKey.CreateSubKey(key); 

			// вернуть раздел реестра
			return (regKey != null) ? new RegistryKey(regKey) : null; 
        }
		///////////////////////////////////////////////////////////////////////
		// Открыть раздел реестра
		///////////////////////////////////////////////////////////////////////
		public RegistryKey OpenKey(string path, FileAccess access)
        {
            // извлечь отдельные компоненты пути
            string[] names = (path != null) ? path.Split('\\') : new string[0]; 

            // указать начальные условия
            RegistryKey parent = RefObject.AddRef(this);

            // для всех компонентов пути
            for (int i = 0; i < names.Length; i++)
            {
                // проверить наличие раздела реестра
                if (parent == null) return null;

                // открыть раздел реестра
                RegistryKey key = parent.DoOpenKey(names[i], access); 
                
                // закрыть родительский раздел
                RefObject.Release(parent); parent = key; 
            }
            return parent; 
        } 
		// открыть раздел реестра
		private RegistryKey DoOpenKey(string key, FileAccess access)
        {
			// указать способ открытия
			bool writable = (access == FileAccess.Write || access == FileAccess.ReadWrite);  

			// открыть раздел реестра
            Microsoft.Win32.RegistryKey regKey = registryKey.OpenSubKey(key, writable); 

			// вернуть раздел реестра
			return (regKey != null) ? new RegistryKey(regKey) : null; 
        }
		///////////////////////////////////////////////////////////////////////
        // Удалить раздел реестра
		///////////////////////////////////////////////////////////////////////
		public void DeleteKey(string path)
        {
            // извлечь отдельные компоненты пути
            string[] names = (path != null) ? path.Split('\\') : new string[0]; 

            // проверить корректность параметров
            if (names.Length == 0) throw new ArgumentException(); 

            // выделить список открытых подразделов
            RegistryKey[] keys = new RegistryKey[names.Length]; keys[0] = this; 

            // для всех компонентов пути
            for (int i = 1; keys[i - 1] != null && i < keys.Length; i++)
            {
                // открыть раздел реестра
                keys[i] = keys[i - 1].DoOpenKey(names[i - 1], FileAccess.Write); 
            }
            // при наличии раздела реестра
            if (keys[keys.Length - 1] != null) 
            {
                // удалить раздел реестра
                DeleteKeyTree(keys[keys.Length - 1], names[keys.Length - 1]);
            }
            // для всех компонентов пути
            for (int i = keys.Length - 1; i > 0; i--)
            {
                // проверить наличие подраздела
                if (keys[i] == null) continue;

                // проверить наличие подразделов и значений
                if (keys[i].EnumerateKeys  ().Length != 0) break; 
                if (keys[i].EnumerateValues().Length != 0) break; 

                // удалить подраздел реестра
                try { keys[i - 1].DoDeleteKey(names[i - 1]); } catch {}
            }
            // для всех компонентов пути
            for (int i = keys.Length - 1; i > 0; i--)
            {
                // освободить выделенные ресурсы
                if (keys[i] != null) RefObject.Release(keys[i]);
            }
        } 
		private static void DeleteKeyTree(RegistryKey key, string keyName)
        {
            // открыть раздел реестра
            using (RegistryKey child = key.DoOpenKey(keyName, FileAccess.Write)) 
            {
                // проверить наличие раздела
                if (child == null) return; 
                
                // для всех подразделов реестра
                foreach (string name in child.EnumerateKeys())
                {
                    // удалить подраздел реестра
                    DeleteKeyTree(child, name); 
                }            
            }
			// удалить раздел реестра
            key.DoDeleteKey(keyName); 
        } 
        // удалить раздел реестра
		private void DoDeleteKey(string key) { registryKey.DeleteSubKey(key); }

		///////////////////////////////////////////////////////////////////////
        // Перечислить значения раздела
		///////////////////////////////////////////////////////////////////////
		public string[] EnumerateValues(string path) 
        { 
		    // открыть раздел реестра
            using (RegistryKey key = DoOpenKey(path, FileAccess.Read))  
            {
                // проверить наличие раздела
                if (key == null) return new string[0]; 
            
                // перечислить значения раздела
                return key.EnumerateValues(); 
            }
        }
	    // перечислить значения раздела
		public string[] EnumerateValues() { return registryKey.GetValueNames(); }

		///////////////////////////////////////////////////////////////////////
        // Получить значение раздела
		///////////////////////////////////////////////////////////////////////
		public object GetValue(string path, string name, object def) 
        { 
		    // открыть раздел реестра
            using (RegistryKey key = DoOpenKey(path, FileAccess.Read))
            {  
                // получить значение раздела
                return (key != null) ? key.GetValue(name, def) : def; 
            }
        }
        // получить значение раздела
		public object GetValue(string name, object def)
        {
            // получить значение раздела
            return registryKey.GetValue(name, def); 
        }
		///////////////////////////////////////////////////////////////////////
        // Установить значение раздела
		///////////////////////////////////////////////////////////////////////
		public void SetValue(string path, string name, object value) 
        { 
		    // открыть или создать раздел реестра
            using (RegistryKey key = DoOpenOrCreateKey(path))
            {
                // установить значение раздела
                key.SetValue(name, value);
            }
        }
        // установить значение раздела
		public void SetValue(string name, object value)
        {
            // установить значение раздела
            registryKey.SetValue(name, value); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Удалить значение раздела
        ///////////////////////////////////////////////////////////////////////
		public void DeleteValue(string path, string name) 
        {
            // извлечь отдельные компоненты пути
            string[] names = (path != null) ? path.Split('\\') : new string[0]; 

            // проверить корректность параметров
            if (names.Length == 0) { DeleteValue(name); return; }

            // выделить список открытых подразделов
            RegistryKey[] keys = new RegistryKey[names.Length + 1]; keys[0] = this; 

            // для всех компонентов пути
            for (int i = 1; keys[i - 1] != null && i < keys.Length; i++)
            {
                // открыть раздел реестра
                keys[i] = keys[i - 1].DoOpenKey(names[i - 1], FileAccess.Write); 
            }
            // при наличии раздела реестра
            if (keys[keys.Length - 1] != null) 
            {
                // удалить значение раздела
                try { keys[keys.Length - 1].DeleteValue(name); } catch {}
            }
            // для всех компонентов пути
            for (int i = keys.Length - 1; i > 0; i--)
            {
                // проверить наличие подраздела
                if (keys[i] == null) continue;
                  
                // проверить наличие подразделов и значений
                if (keys[i].EnumerateKeys  ().Length != 0) break; 
                if (keys[i].EnumerateValues().Length != 0) break; 

                // удалить подраздел реестра
                try { keys[i - 1].DoDeleteKey(names[i - 1]); } catch {}
            }
            // для всех компонентов пути
            for (int i = keys.Length - 1; i > 0; i--) 
            {
                // освободить выделенные ресурсы
                if (keys[i] != null) RefObject.Release(keys[i]);
            }
        }
        // удалить значение раздела
		public void DeleteValue(string name) { registryKey.DeleteValue(name); } 
    }
}
