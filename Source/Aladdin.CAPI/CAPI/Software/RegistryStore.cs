using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.Win32;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Раздел реестра как хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class RegistryStore : ContainerStore
	{
		// имя раздела реестра
		private RegistryKey root; private string keyName; 

		// конструктор
		public RegistryStore(CryptoProvider provider, Scope scope, string keyName) 
            
            // сохранить переданные параметры
            : base(provider, scope) { this.keyName = keyName; 
        
            // определить ветвь реестра
            this.root = (scope == Scope.System) ? Registry.LocalMachine : Registry.CurrentUser; 
		}  
        // имя хранилища
        public override object Name
        {
            // имя хранилища
            get { return (Scope == Scope.System) ? "HKLM" : "HKCU"; }
        }
		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
		public override string[] EnumerateObjects()
		{
            // создать список имен
            List<String> names = new List<String>(); 

			// открыть раздел реестра
			using (RegistryKey key = root.OpenSubKey(keyName))
            {
				// проверить наличие раздела
				if (key == null) return new string[0]; 

                // заполнить список имен
                names.AddRange(key.GetValueNames()); 
            }
		    // вернуть список имен
            return names.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление физическими потоками
		///////////////////////////////////////////////////////////////////////
        protected override ContainerStream CreateStream(object name)
        {
            // открыть хранилище
            return new RegistryStream(root, keyName, name.ToString(), true, true); 
        }
        protected override ContainerStream OpenStream(object name, FileAccess access)
        {
            // указать признак допустимости записи
            bool canWrite = (access != FileAccess.Read); 

            // открыть хранилище
            return new RegistryStream(root, keyName, name.ToString(), false, canWrite); 
        }
        protected override void DeleteStream(object name)
        {
            // открыть раздел реестра
            using (RegistryKey registryKey = root.OpenSubKey(keyName, true))
            {
			    // удалить значение реестра
			    registryKey.DeleteValue(name.ToString()); 
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
        // Хранилище байтовых данных в реестре
	    ///////////////////////////////////////////////////////////////////////////
	    private sealed class RegistryStream : ContainerStream
	    {
		    // раздел реестра и значение раздела
		    private RegistryKey registryKey; private string value;
        
		    // конструктор
		    public RegistryStream(RegistryKey root, 
                string key, string value, bool create, bool canWrite)
		    {
			    // открыть или создать раздел реестра
			    if (create) registryKey = root.CreateSubKey(key);
                else { 
                    // открыть раздел реестра
                    registryKey = root.OpenSubKey(key, canWrite); 
                }
                // сохранить переданные данные
                this.value = value; 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                ((IDisposable)registryKey).Dispose(); base.OnDispose(); 
            }
            // имя контейнера
            public override Object Name { get { return value; }}

            // уникальный идентификатор
            public override String UniqueID { get
            {
                // уникальный идентификатор
                return String.Format("{0}\\{1}", registryKey.Name, value); 
            }}
            // прочитать данные
            public override byte[] Read()
            {
		        // прочитать значение реестра
		        return (byte[])registryKey.GetValue(value); 
            }
		    // записать данные
		    public override void Write(byte[] buffer)
		    {
		        // записать значение реестра
		        registryKey.SetValue(value, buffer); 
		    }
	    }
	}
}
