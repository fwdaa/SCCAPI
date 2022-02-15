package aladdin.io;
import java.io.*; 
import java.util.*; 
import java.util.zip.*; 

public class Files 
{
    ///////////////////////////////////////////////////////////////////////////
    // Создать каталог
    ///////////////////////////////////////////////////////////////////////////
    public static void createDirectory(String directoryName) throws IOException
    {
        // при отсутствии разделителя
        if (!directoryName.endsWith(java.io.File.separator)) 
        {
            // добавить разделитель
            directoryName = directoryName.concat(java.io.File.separator); 
        }
        // указать объект каталога
        java.io.File directory = new java.io.File(directoryName); 
        
        // создать каталог
        try { if (!directory.exists()) directory.mkdirs(); } 

        // обработать возможную ошибку
        catch (SecurityException e) { throw new IOException(e); }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Удалить каталог
    ///////////////////////////////////////////////////////////////////////////
    public static void deleteDirectory(String directoryName) throws IOException
    {
        // при отсутствии разделителя
        if (!directoryName.endsWith(java.io.File.separator)) 
        {
            // добавить разделитель
            directoryName = directoryName.concat(java.io.File.separator); 
        }
        // удалить каталог
        deleteDirectory(new java.io.File(directoryName)); 
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
                if (child.isDirectory()) deleteDirectory(child);  else child.delete();
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
    public static void createFile(String directoryName, String fileName) throws IOException
    {
        // при указании каталога
        if (directoryName != null)
        {
            // при отсутствии разделителя
            if (!directoryName.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directoryName = directoryName.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directoryName.concat(fileName); 
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
    public static void deleteFile(String directoryName, String fileName) throws IOException
    {
        // при указании каталога
        if (directoryName != null)
        {
            // при отсутствии разделителя
            if (!directoryName.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directoryName = directoryName.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directoryName.concat(fileName); 
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
	public static byte[] readFile(String directory, String name) throws IOException
	{
		// определить используемый разделитель
		String separator = File.separator; if (directory.endsWith(separator))
        {
            // удалить лишний разделитель
            directory = directory.substring(0, directory.length() - separator.length()); 
        }
		// открыть файл
		File file = new File(directory + separator + name); 
        
		// определить размер файла
		long length = file.length(); if (length > Integer.MAX_VALUE) 
        {
            // при ошибке выбросить исключение
            throw new IOException("The file is too large"); 
        }
        // выделить буфер для файла
        byte[] content = new byte[(int)length]; 
        
		// указать поток чтения
		RandomAccessFile stream = new RandomAccessFile(file, "r"); 
		try { 
			// прочитать данные из файла
			stream.seek(0); stream.read(content, 0, content.length); 
		}
		// закрыть файл
		finally { stream.close(); } return content;  
	}
    ///////////////////////////////////////////////////////////////////////////
    // Создать Jar-файл
    ///////////////////////////////////////////////////////////////////////////
    public static void createJar(String directoryName, String fileName, 
        String manifest, List<String> names, List<byte[]> contents) throws IOException
    {
        // при указании каталога
        if (directoryName != null)
        {
            // при отсутствии разделителя
            if (!directoryName.endsWith(java.io.File.separator)) 
            {
                // добавить разделитель
                directoryName = directoryName.concat(java.io.File.separator); 
            }
            // указать полное имя файла
            fileName = directoryName.concat(fileName); 
            
            // создать каталог
            new java.io.File(directoryName).mkdirs();
        }
        // получить содержимое файла
        byte[] content = Files.createJar(manifest, 
            names.toArray(new String[0]), contents.toArray(new byte[0][])
        ); 
		// указать поток записи
		try (FileOutputStream stream = new FileOutputStream(fileName)) 
        {
  			// записать данные в файл
			stream.write(content, 0, content.length); stream.flush();
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать Jar-файл
    ///////////////////////////////////////////////////////////////////////////
    public static byte[] createJar(String manifest, 
        String[] names, byte[][] contents) throws IOException
    {
        // проверить соответствие параметров
        if (names.length != contents.length) throw new IllegalArgumentException(); 
        
        // создать динамический байтовый буфер
        ByteArrayOutputStream stream = new ByteArrayOutputStream(); 
        
        // создать буфер для архивирования
        try (ZipOutputStream out = new ZipOutputStream(stream)) 
        {
            // при наличии манифеста
            if (manifest != null)
            {
                // закодировать манифест
                byte[] encoded = manifest.getBytes("UTF-8"); 

                // добавить описание элемента
                out.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));

                // записать содержимое файла
                out.write(encoded, 0, encoded.length); out.closeEntry();
            }
            // для всех внутренних файлов
            for (int i = 0; i < names.length; i++) 
            {
                // добавить описание элемента
                out.putNextEntry(new ZipEntry(names[i]));

                // записать содержимое файла
                out.write(contents[i], 0, contents[i].length); out.closeEntry();
            }
        }
        // вернуть байтовое содержимое
        return stream.toByteArray(); 
    }
}
