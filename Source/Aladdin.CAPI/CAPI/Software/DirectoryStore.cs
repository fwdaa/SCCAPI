using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Каталог как хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class DirectoryStore : ContainerStore
	{
	    // информация каталога и расширения файлов
	    private DirectoryInfo directoryInfo; private String[] extensions; 

		// конструктор
		public DirectoryStore(SecurityStore parent,  
            
            // сохранить переданные параметры
            string directory, string[] extensions) : base(parent) 
		{ 
		    // получить информацию каталога
            directoryInfo = new DirectoryInfo(directory); 

		    // сохранить переданные параметры
            this.extensions = extensions;
        } 
        // имя хранилища
        public override object Name { get { return directoryInfo.FullName; }}

        // допустимые расширения
        public string[] Extensions { get { return extensions; }}

		///////////////////////////////////////////////////////////////////////
		// Перечисление сертификатов в каталоге
		///////////////////////////////////////////////////////////////////////
		public static Certificate[] EnumerateCertificates(
            string directory, KeyUsage keyUsage)
		{
			// создать список сертификатов
			List<Certificate> certificates =  new List<Certificate>();
 
			// для каждого файла сертификата
			foreach (string file in Directory.GetFiles(directory, "*.cer"))
			try {
				// получить содержимое сертификата
				Certificate certificate = new Certificate(File.ReadAllBytes(file)); 

                // при указании способа использования
                if (keyUsage != KeyUsage.None)
                { 
				    // проверить область действия сертификата
				    if ((certificate.KeyUsage & keyUsage) == KeyUsage.None) continue; 
                }
				// добавить сертификат в список
				if (!certificates.Contains(certificate)) certificates.Add(certificate); 
			}
			// проверить использование программного провайдера
			catch {} return certificates.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
		public override string[] EnumerateObjects()
		{
            // проверить наличие каталога
            if (!directoryInfo.Exists) return new string[0]; 

            // создать список имен файлов
			List<String> names = new List<String>(); 

		    // для всех расширений
            foreach (string extension in extensions)
            { 
                // перечислить полные имена файлов
                IEnumerable<FileInfo> files = directoryInfo.GetFiles("*." + extension); 
                    
                // добавить имена файлов
		        foreach (FileInfo file in files) names.Add(file.Name);
            }
		    // вернуть список имен файлов
		    return names.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление физическими потоками
		///////////////////////////////////////////////////////////////////////
        protected override ContainerStream CreateStream(object name)
        {
            // получить полное имя каталога
            string fileName = directoryInfo.FullName; 
            
            // при отсутствии разделителя 
            if (fileName[fileName.Length - 1] != Path.DirectorySeparatorChar)
            {
                // указать полное имя файла
                fileName = String.Format("{0}{1}{2}", fileName, Path.DirectorySeparatorChar, name); 
            }
            // указать полное имя файла
            else fileName = String.Format("{0}{1}", fileName, name); 

            // создать хранилище
            return new FileStream(fileName, true, FileAccess.ReadWrite); 
        }
        protected override ContainerStream OpenStream(object name, FileAccess access)
        {
            // получить полное имя каталога
            string fileName = directoryInfo.FullName;
            
            // при отсутствии разделителя 
            if (fileName[fileName.Length - 1] != Path.DirectorySeparatorChar)
            {
                // указать полное имя файла
                fileName = String.Format("{0}{1}{2}", fileName, Path.DirectorySeparatorChar, name); 
            }
            // указать полное имя файла
            else fileName = String.Format("{0}{1}", fileName, name); 

            // открыть хранилище
            return new FileStream(fileName, false, access); 
        }
        protected override void DeleteStream(object name)
        {
            // получить полное имя каталога
            string fileName = directoryInfo.FullName; 
            
            // при отсутствии разделителя 
            if (fileName[fileName.Length - 1] != Path.DirectorySeparatorChar)
            {
                // указать полное имя файла
                fileName = String.Format("{0}{1}{2}", fileName, Path.DirectorySeparatorChar, name); 
            }
            // указать полное имя файла
            else fileName = String.Format("{0}{1}", fileName, name); 

            // удалить хранилище
            File.Delete(fileName);
        }
	    ///////////////////////////////////////////////////////////////////////////
        // Хранилище байтовых данных в файле
	    ///////////////////////////////////////////////////////////////////////////
	    private sealed class FileStream : ContainerStream
	    {
            // поток файла
            private System.IO.FileStream stream; private FileInfo info; 

		    // конструктор
		    public FileStream(string path, bool create, FileAccess access)
		    {
                // создать новый файл
                if (create) stream = File.Open(path, FileMode.CreateNew);

                // открыть существующий файл
                else stream = File.Open(path, FileMode.Open, access); 

                // сохранить имя файла
                info = new FileInfo(path); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                stream.Flush(); stream.Dispose(); base.OnDispose(); 
            }
            // имя контейнера
            public override Object Name { get { return info.Name; }}
            // уникальный идентификатор
            public override string UniqueID { get { return info.FullName; }}

            // прочитать данные
            public override byte[] Read()
            {
                // выделить буфер требуемого размера
                byte[] buffer = new byte[stream.Length]; stream.Position = 0;
                
                // прочитать данные
                stream.Read(buffer, 0, buffer.Length); return buffer; 
            }
		    // записать данные
		    public override void Write(byte[] buffer)
		    {
                // записать данные
                stream.Position = 0; stream.Write(buffer, 0, buffer.Length); 
		    }
	    }
	}
}
