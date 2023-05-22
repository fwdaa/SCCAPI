package aladdin.io;
import java.io.*; 

public class Files 
{
    ///////////////////////////////////////////////////////////////////////////
    // Создать каталог
    ///////////////////////////////////////////////////////////////////////////
    public static void createDirectory(String directory) throws IOException
    {
        // при отсутствии разделителя
        if (!directory.endsWith(java.io.File.separator)) 
        {
            // добавить разделитель
            directory = directory.concat(java.io.File.separator); 
        }
        // указать объект каталога
        java.io.File dir = new java.io.File(directory); 
        
        // создать каталог
        try { if (!dir.exists()) dir.mkdirs(); } 

        // обработать возможную ошибку
        catch (SecurityException e) { throw new IOException(e); }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Удалить каталог
    ///////////////////////////////////////////////////////////////////////////
    public static void deleteDirectory(String directory) throws IOException
    {
        // при отсутствии разделителя
        if (!directory.endsWith(java.io.File.separator)) 
        {
            // добавить разделитель
            directory = directory.concat(java.io.File.separator); 
        }
        // удалить каталог
        deleteDirectory(new java.io.File(directory)); 
    }
    private static void deleteDirectory(java.io.File directory) throws IOException
    {
        try { 
            // проверить наличие каталога
            if (!directory.exists()) return; 
            
            // перечислить файлы и каталоги
            java.io.File[] childs = directory.listFiles();

            // для всех файлов
            if (childs != null) for(java.io.File child : childs) 
            {
                // удалить каталог или файл
                if (child.isDirectory()) deleteDirectory(child); else child.delete();
            }
            // удалить каталог
            directory.delete();
        }
        // обработать возможную ошибку
        catch (SecurityException e) { throw new IOException(e); }
    }    
    ///////////////////////////////////////////////////////////////////////////
    // Создать файл
    ///////////////////////////////////////////////////////////////////////////
    public static void createFile(String directory, String fileName) throws IOException
    {
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); 
        
        // создать файл
        try { if (!file.exists()) file.createNewFile(); }
        
        // обработать возможную ошибку
        catch (SecurityException e) { throw new IOException(e); }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Удалить файл
    ///////////////////////////////////////////////////////////////////////////
    public static void deleteFile(String directory, String fileName) throws IOException
    {
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); 
        
        // удалить файл
        try { if (file.exists()) file.delete(); }
        
        // обработать возможную ошибку
        catch (SecurityException e) { throw new IOException(e); }
    }
	///////////////////////////////////////////////////////////////////////////
	// Прочитать данные файла
	///////////////////////////////////////////////////////////////////////////
	public static byte[] readFile(String directory, String fileName) throws IOException
	{
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); 
        
		// определить размер файла
		long length = file.length(); if (length > Integer.MAX_VALUE) 
        {
            // при ошибке выбросить исключение
            throw new IOException("The file is too large"); 
        }
        // выделить буфер для файла
        byte[] content = new byte[(int)length]; 
        
		// указать поток чтения
		try (RandomAccessFile stream = new RandomAccessFile(file, "r"))
		{ 
			// прочитать данные из файла
			stream.read(content, 0, content.length); return content;  
		}
	}
	public static byte[] readFile(String directory, 
        String fileName, long offset, int length) throws IOException
	{
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); 
        
		// определить размер файла
		long size = file.length(); if (offset + length > size)
        {
            // указать считываемый размер
            length = (int)(size - offset); if (length < 0) length = 0; 
        }
        // выделить буфер для файла
        byte[] content = new byte[length]; if (length == 0) return content; 
        
		// указать поток чтения
		try (RandomAccessFile stream = new RandomAccessFile(file, "r"))
		{ 
			// прочитать данные из файла
			stream.seek(offset); stream.read(content, 0, content.length); return content;  
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Записать данные файла
	///////////////////////////////////////////////////////////////////////////
	public static void writeFile(String directory, 
        String fileName, byte[] content) throws IOException
	{
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); if (!file.exists())
        { 
            // создать новый файл
            file.getParentFile().mkdirs(); file.createNewFile(); 
        }
		// указать поток чтения
		try (RandomAccessFile stream = new RandomAccessFile(file, "rw")) 
		{ 
			// записать данные в файл
			stream.write(content, 0, content.length); stream.setLength(content.length);
		}
    }
	///////////////////////////////////////////////////////////////////////////
	// Добавить данные в файл
	///////////////////////////////////////////////////////////////////////////
	public static void appendFile(String directory, 
        String fileName, byte[] content) throws IOException
	{
        // при указании каталога
        if (directory != null)
        {
            // при отсутствии разделителя
            if (!directory.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directory = directory.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directory.concat(fileName); 
        }
        // указать объект файла
        java.io.File file = new java.io.File(fileName); if (!file.exists())
        { 
            // создать новый файл
            file.getParentFile().mkdirs(); file.createNewFile(); 
        }
        // определить размер файла 
        long cbFile = file.length(); 
        
		// указать поток чтения
		try (RandomAccessFile stream = new RandomAccessFile(file, "rw")) 
		{ 
			// добавить данные в файл
			stream.seek(cbFile); stream.write(content, 0, content.length); 
            
            // установить конец файла 
            stream.setLength(cbFile + content.length);
		}
    }
}
