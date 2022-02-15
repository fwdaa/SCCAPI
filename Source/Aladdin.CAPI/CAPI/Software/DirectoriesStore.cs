using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Файловое хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class DirectoriesStore : SecurityStore
	{
		// источник каталогов
		private IDirectoriesSource directoriesSource; 
        // каталоги и расширения файлов
        private List<String> directories; private string[] extensions; 

		// конструктор
		public DirectoriesStore(CryptoProvider provider, Scope scope, 
            
            // сохранить переданные параметры
            IDirectoriesSource directoriesSource, string[] extensions) : base(provider, scope) 
		{ 
            // сохранить переданные параметры
            this.directoriesSource = directoriesSource; this.extensions = extensions; 

            // создать список каталогов
            this.directories = new List<String>(); if (directoriesSource != null)
            { 
                // для всех каталогов
                foreach (string directory in directoriesSource.EnumerateDirectories())
                try {
                    // определить имя каталога
                    string path = Path.GetFullPath(directory); 

                    // при необходимости преобразовать регистр
                    if (Path.DirectorySeparatorChar == '\\') path = path.ToLower(); 

                    // добавить каталог в список
                    this.directories.Add(path); 
                }
                catch {}
            }
		}  
		// конструктор
		public DirectoriesStore(CryptoProvider provider, Scope scope, 
            
            // сохранить переданные параметры
            string[] directories, string[] extensions) : base(provider, scope) 
		{ 
            // сохранить переданные параметры
            this.directoriesSource = null; this.extensions = extensions; 

            // создать список каталогов
            this.directories = new List<String>(); 

            // для всех каталогов
            foreach (string directory in directories)
            try {
                // определить имя каталога
                string path = Path.GetFullPath(directory); 

                // при необходимости преобразовать регистр
                if (Path.DirectorySeparatorChar == '\\') path = path.ToLower(); 

                // добавить каталог в список
                this.directories.Add(path); 
            }
            catch {}
        } 
        // имя хранилища
        public override object Name { get { return "FILE"; }}

		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
        public override string[] ParseObjectName(string fullName)
        {
            // при необходимости преобразовать регистр
            if (Path.DirectorySeparatorChar == '\\') fullName = fullName.ToLower(); 

            // для всех каталогов списка
            foreach (string directory in this.directories)
            {
                // проверить совпадение имени каталога
                if (!fullName.StartsWith(directory)) continue; 

                // проверить на точное совпадение
                if (fullName.Length == directory.Length)
                {
                    // вернуть разобранное имя
                    return new string[] { directory }; 
                }
                // проверить совпадение имени каталога
                if (fullName[directory.Length] != '\\') continue; 

                // проверить на точное совпадение
                if (fullName.Length == directory.Length + 1)
                {
                    // вернуть разобранное имя
                    return new string[] { directory }; 
                }
                // извлечь имя файла
                string name = fullName.Substring(directory.Length + 1); 

                // проверить отсутствие разделителей
                if (name.Contains("\\")) continue; 

                // вернуть разобранное имя
                return new string[] { directory, name }; 
            }
            // при ошибке выбросить исключение
            throw new NotFoundException(); 
        }
		public override string[] EnumerateObjects()
		{
            // создать список каталогов
            List<String> dirs = new List<String>(); 

            // для всех каталогов
            foreach (string directory in this.directories)
            {
                // проверить наличие каталога
                DirectoryInfo info = new DirectoryInfo(directory); 

                // при наличии каталога добавить каталог в список
                if (info.Exists) dirs.Add(directory);
            }
            // перечислить каталоги
            return dirs.ToArray(); 
		}
		public override SecurityObject CreateObject(IRand rand, 
            object name, object authenticationData, params object[] parameters)
        {
            // определить имя каталога
            string directory = Path.GetFullPath(name.ToString()); 

            // при необходимости преобразовать регистр
            if (Path.DirectorySeparatorChar == '\\') directory = directory.ToLower(); 

            // проверить отсутствие каталога в списке
            if (directories.Contains(directory)) throw new IOException();

            // при наличии источника каталогов
            if (directoriesSource != null)
            { 
                // добавить имя каталога
                directoriesSource.AddDirectory(directory); 
            }
            // добавить имя каталога в список
            directories.Add(directory);

            // вернуть объект каталога
            return new DirectoryStore(this, directory, extensions); 
        }
		public override SecurityObject OpenObject(object name, FileAccess access)
        {
            // определить имя каталога
            string directory = Path.GetFullPath(name.ToString()); 

            // при необходимости преобразовать регистр
            if (Path.DirectorySeparatorChar == '\\') directory = directory.ToLower(); 

            // проверить наличие каталога в списке
            if (!directories.Contains(directory)) 
            { 
                // выбросить исключение
                throw new NotFoundException(); 
            }
            // вернуть объект каталога
            return new DirectoryStore(this, directory, extensions); 
        }
		public override void DeleteObject(object name, Authentication[] authentications)
        {
            // определить имя каталога
            string directory = Path.GetFullPath(name.ToString()); 

            // при необходимости преобразовать регистр
            if (Path.DirectorySeparatorChar == '\\') directory = directory.ToLower(); 

            // удалить имя каталога из списка
            if (directories.Contains(directory)) { directories.Remove(directory); 
            
                // при наличии источника каталогов
                if (directoriesSource != null)
                { 
                    // удалить каталог
                    try { directoriesSource.RemoveDirectory(directory); } catch {}
                }
            }
            // вызвать базовую функцию
            base.DeleteObject(name, authentications); 
        }
	}
}
