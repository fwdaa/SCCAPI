using System;
using System.IO;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище в памяти программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public class MemoryStore : ContainerStore
	{
		// конструктор
		public MemoryStore(CryptoProvider provider) : base(provider, Scope.System) {}

        // имя хранилища
        public override object Name { get { return "MEMORY"; }}

        ///////////////////////////////////////////////////////////////////////
        // Управление физическими потоками
        ///////////////////////////////////////////////////////////////////////
        protected override ContainerStream CreateStream(object name)
        {
            // выполнить преобразование типа
            System.IO.MemoryStream stream = (System.IO.MemoryStream)name; 

            // проверить отсутствие данных
            if (stream.Length != 0) throw new IOException(); 

            // открыть хранилище
            return new MemoryStream(stream, true); 
        }
        protected override ContainerStream OpenStream(object name, FileAccess access)
        {
            // при указании потока
            if (name is System.IO.MemoryStream)
            {
                // выполнить преобразование типа
                System.IO.MemoryStream stream = (System.IO.MemoryStream)name;

                // открыть хранилище
                return new MemoryStream(stream, access != FileAccess.Read);
            }
            else {
                // проверить корректность параметров
                if (access != FileAccess.Read) throw new ArgumentException(); 

                // раскодировать содержимое
                byte[] content = Convert.FromBase64String((String)name);

                // указать используемый поток
                System.IO.MemoryStream stream = new System.IO.MemoryStream(content);

                // открыть хранилище
                return new MemoryStream(stream, access != FileAccess.Read);
            }
        }
        protected override void DeleteStream(object name)
        {
            // выполнить преобразование типа
            System.IO.MemoryStream stream = (System.IO.MemoryStream)name; 

            // удалить содержимое
            stream.Position = 0; stream.Write(new byte[0], 0, 0);
        }
	    ///////////////////////////////////////////////////////////////////////////
        // Хранилище байтовых данных в байтовом потоке
	    ///////////////////////////////////////////////////////////////////////////
        private sealed class MemoryStream : ContainerStream
        {
		    // байтовый поток и допустимость записи
		    private System.IO.MemoryStream stream; public bool canWrite;
        
		    // конструктор
		    public MemoryStream(System.IO.MemoryStream stream, bool canWrite)
		    {
			    // сохранить переданные параметры
			    this.stream = stream; this.canWrite = canWrite; 
            }
            // имя контейнера
            public override Object Name { get { return stream; }}
            // уникальный идентификатор
            public override string UniqueID { get { return null; }}

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
			    // проверить допустимость записи
			    if (!canWrite) throw new IOException(); 

                // записать данные
                stream.Position = 0; stream.Write(buffer, 0, buffer.Length); 
		    }
        }
    }
}
