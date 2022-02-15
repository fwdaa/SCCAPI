package aladdin.capi.software;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Каталог как хранилище программных контейнеров
///////////////////////////////////////////////////////////////////////////
public class DirectoryStore extends ContainerStore
{
    // информация каталога и расширения файлов
    private final File directoryInfo; private final String[] extensions; 

	// конструктор
	public DirectoryStore(SecurityStore parent,  
            
        // сохранить переданные параметры
        String directory, String[] extensions)
	{ 
	    // сохранить переданные параметры
         super(parent); this.extensions = extensions;

	    // получить информацию каталога
        directoryInfo = new File(directory); 
    } 
    // имя хранилища
    @Override public String name() { return directoryInfo.getAbsolutePath(); }
    
    // допустимые расширения
    public final String[] extensions() { return extensions; }

	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
    @Override
	public String[] enumerateObjects()
	{
        // проверить наличие каталога
        if (!directoryInfo.exists()) return new String[0]; 
        
        // перечислить файлы с указанными расширениями
        return directoryInfo.list(new FilenameFilter() 
        {
            @Override
            public boolean accept(File dir, String name) 
            {
                // для всех расширений
                for (String extension : extensions)
                {
                    // проверить совпадение расширения
                    if (name.endsWith("." + extension)) return true;
                }
                return false; 
            }
        }); 
    }
	///////////////////////////////////////////////////////////////////////
	// Управление физическими потоками
	///////////////////////////////////////////////////////////////////////
    @Override
    protected ContainerStream createStream(Object name) throws IOException
    {
        // получить полное имя каталога
        String fileName = directoryInfo.getAbsolutePath(); 

        // при отсутствии разделителя
        if (!fileName.endsWith(File.separator))
        {
            // определить полное имя файла
            fileName = fileName + File.separator + name.toString(); 
        }
        // определить полное имя файла
        else fileName = fileName + name.toString(); 
        
        // проверить отсутствие файла
        if (new File(fileName).exists()) throw new IOException(); 

        // создать хранилище
        return new FileStream(fileName, "rw"); 
    }
    @Override
    protected ContainerStream openStream(Object name, String access) throws IOException
    {
        // получить полное имя каталога
        String fileName = directoryInfo.getAbsolutePath(); 

        // при отсутствии разделителя
        if (!fileName.endsWith(File.separator))
        {
            // определить полное имя файла
            fileName = fileName + File.separator + name.toString(); 
        }
        // определить полное имя файла
        else fileName = fileName + name.toString(); 

        // проверить наличие файла
        if (!new File(fileName).exists()) throw new IOException(); 
        
        // открыть хранилище
        return new FileStream(fileName, access); 
    }
    @Override
    protected void deleteStream(Object name) throws IOException
    {
        // получить полное имя каталога
        String fileName = directoryInfo.getAbsolutePath(); 

        // при отсутствии разделителя
        if (!fileName.endsWith(File.separator))
        {
            // определить полное имя файла
            fileName = fileName + File.separator + name.toString(); 
        }
        // определить полное имя файла
        else fileName = fileName + name.toString(); 

        // удалить хранилище
        new File(fileName).delete();
    }
	///////////////////////////////////////////////////////////////////////////
    // Хранилище байтовых данных в файле
	///////////////////////////////////////////////////////////////////////////
	private static class FileStream extends ContainerStream
	{
        // поток файла
        private final RandomAccessFile stream; private final File file; 

	    // конструктор
	    public FileStream(String path, String access) throws IOException
	    {
            // создать новый файл или открыть существующий
            stream = new RandomAccessFile(path, access); this.file = new File(path); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        {
            // освободить выделенные ресурсы
            stream.close(); super.onClose(); 
        }
        // имя контейнера
        @Override public Object name() { return file.getName(); }
        
        // уникальный идентификатор
        @Override public String uniqueID() { return file.getAbsolutePath(); }
        
        // прочитать данные
        @Override public byte[] read() throws IOException
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[(int)stream.length()]; stream.seek(0);
                
            // прочитать данные
            stream.read(buffer, 0, buffer.length); return buffer; 
        }
        // записать данные
		@Override public void write(byte[] buffer) throws IOException
		{
            // записать данные
            stream.seek(0); stream.write(buffer, 0, buffer.length);
		}
	}
}
