package aladdin;
import java.lang.reflect.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Операционная система
///////////////////////////////////////////////////////////////////////////
public abstract class OS 
{
    // используемая операционная система
    public static final OS INSTANCE = getInstance(); 
        
    // используемая операционная система
    private static OS getInstance() 
    {
        // получить имя операционной системы
        String name = System.getProperty("os.name").toLowerCase(); 
        
        // вернуть операционную систему Windows
        if (name.contains("win")) return new Windows(name); 
        
        // вернуть операционную систему Linux
        if (!name.contains("mac")) return new Unix(name); 
            
        // операционная система Mac не поддерживается 
        throw new UnsupportedOperationException();
    }
    // конструктор
    protected OS(String name) { this.name = name; } public final String name;
    
    // каталог для всех пользователей
    public abstract String getSharedFolder(); 
    
    // каталог для текущего пользователя
    public String getUserFolder() { return System.getProperty("user.home"); } 
    
    // кодировка операционной системы
    public String getEncoding() { return System.getProperty("file.encoding"); }
    
    // запустить процесс
    public Process start(String... parameters) throws IOException
    {
        // при указании полной командной строки
        if (parameters.length == 1)
        {
            // запустить процесс
            return Runtime.getRuntime().exec(parameters[0]); 
        }
        // запустить процесс
        return Runtime.getRuntime().exec(parameters); 
    }
    // выполнить процесс
    public String[] exec(String... parameters) throws IOException
    {
        // создать список выходных строк
        List<String> lines = new ArrayList<String>(); 
        
        // запустить процесс
        Process process = start(parameters); 
        try { 
            // получить поток выходных данных
            InputStream stream = process.getInputStream(); Reader streamReader; 

            // указать используемую кодировку
            String encoding = getEncoding(); if (encoding == null) 
            {
                // указать кодировку по умолчанию
                streamReader = new InputStreamReader(stream);
            }
            else {
                // указать кодировку потока выходных данных
                try { streamReader = new InputStreamReader(stream, encoding); }

                // проверить корректность кодировки
                catch (UnsupportedEncodingException e)
                {
                    // указать кодировку потока выходных данных по умолчанию
                    streamReader = new InputStreamReader(stream); 
                }
            }
        
            // получить поток выходных данных
            try (BufferedReader output = new BufferedReader(streamReader))
            {
                // для всех строк
                for (String line = output.readLine(); line != null; 

                    // добавить строку в список
                    line = output.readLine()) lines.add(line);
            }
        }
        // освободить выделенные ресурсы и вернуть список строк
        finally { closeProcess(process); } return lines.toArray(new String[0]);
    }
    @SuppressWarnings({"try"}) 
    private void closeProcess(Process process) throws IOException
    {
        // освободить выделенные ресурсы 
        try (OutputStream stream = process.getOutputStream()) {}
        try (InputStream  stream = process.getErrorStream ()) {}
        
        // получить класс процесса
        Class<?> processClass = process.getClass(); 
        try {
            // получить описание метода 
            Method method = processClass.getDeclaredMethod("closeHandle", long.class); 
                
            // получить описание поля 
            Field field = processClass.getDeclaredField("handle"); 
            
            // изменить доступность метода и поля 
            method.setAccessible(true); field.setAccessible(true); 
            
            // вызвать метод очистки 
            method.invoke(null, field.getLong(process)); return;
        }
        catch (Throwable e) {}
        try { 
            // получить описание метода 
            Method method = processClass.getDeclaredMethod("finalize"); 

            // вызвать метод очистки 
            method.setAccessible(true); method.invoke(process); return; 
        }
        // выполнить сборку мусора 
        catch (Throwable ex) {} /*System.gc();*/
    }
    // перечислить процессы
    public abstract Map<Integer, String> listProcesses() throws IOException; 
    
    ///////////////////////////////////////////////////////////////////////
    // Операционная система Windows
    ///////////////////////////////////////////////////////////////////////
    public static class Windows extends OS
    {
        // конструктор
        private Windows(String name) { super(name); }
            
        // каталог для всех пользователей
        @Override public String getSharedFolder() { return System.getenv("ALLUSERSPROFILE"); } 
        
        // кодировка операционной системы
        @Override public String getEncoding() { return "Cp1251"; } 
        
        // перечислить процессы
        @Override public Map<Integer, String> listProcesses() throws IOException
        {
            // создать список для процессов
            Map<Integer, String> processes = new HashMap<Integer, String>(); 
        
            // перечислить процессы
            for (String line : exec("tasklist /fo csv /nh"))
            {
                // получить позицию разделителя
                int length = line.indexOf(','); if (length < 0)
                {
                    // проверить корректность формата
                    throw new IllegalStateException(); 
                }
                // извлечь имя процесса
                String process = line.substring(0, length); 
                
                // при наличии кавычек
                if (length >= 2 && process.charAt(0) == '"' && process.charAt(length - 1) == '"')
                {
                    // удалить кавычки из имени процесса
                    process = process.substring(1, length - 1); 
                }
                // извлечь оставшуюся строку
                String pid = line.substring(length + 1); length = pid.indexOf(',');
                
                // извлечь идентификатор процесса
                if (length >= 0) pid = pid.substring(0, length); else length = pid.length(); 
            
                // при наличии кавычек
                if (length >= 2 && pid.charAt(0) == '"' && pid.charAt(length - 1) == '"')
                {
                    // удалить кавычки из идентификатора
                    pid = pid.substring(1, length - 1); 
                }
                // добавить идентификатор и имя процесса в список
                processes.put(Integer.parseInt(pid), process); 
            }
            return processes; 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Операционная система Unix
    ///////////////////////////////////////////////////////////////////////
    public static class Unix extends OS
    {
        // кодировка операционной системы
        private String encoding; 
        
        // конструктор
        private Unix(String name) { super(name); encoding = null; 
        
            // указать переменные окружения
            String[] names = new String[] { "$LC_ALL", "$LC_CTYPE", "$LANG" }; 

            // для всех переменных окружения
            for (int i = 0; i < names.length; i++)
            try {
                // прочитать переменную окружения
                for (String line : exec("echo", names[i]))
                {
                    // проверить указание кодировки
                    int position = line.indexOf("."); if (position < 0) continue; 

                    // извлечь имя кодировки
                    encoding = line.substring(position + 1); return; 
                }
            }
            catch (Throwable e) {}
        }
        // каталог для всех пользователей
        @Override public String getSharedFolder() { return "/usr/share"; } 
    
        // кодировка операционной системы
        @Override public String getEncoding() 
        { 
            // вернуть кодировку OC
            return (encoding != null) ? encoding : super.getEncoding(); 
        }
        // перечислить процессы
        @Override public Map<Integer, String> listProcesses() throws IOException
        {
            // создать список для процессов
            Map<Integer, String> processes = new HashMap<Integer, String>(); 
            
            // перечислить процессы
            for (String line : exec("ps -e -o pid,cmd --no-heading"))
            {
                // удалить незначимые пробелы
                String str = line.trim(); int position = str.indexOf(" "); 
                
                // проверить корректность формата
                if (position < 0) throw new IllegalStateException();
                
                // извлечь идентификатор процесса
                String pid = str.substring(0, position); 
                
                // извлечь оставшуюся строку
                str = str.substring(position + 1).trim();
                
                // для утилиты ядра
                if (str.startsWith("[")) { position = str.indexOf("]", 1); 
                    
                    // сохранить имя с разделителями
                    if (position >= 0) str = str.substring(0, position + 1); 
                    
                    // добавить идентификатор и имя процесса
                    processes.put(Integer.parseInt(pid), str); 
                }
                else {
                    // создать строковый буфер
                    StringBuilder process = new StringBuilder(); 
                    
                    // указать начальные условия
                    int index = 0; char separator = ' '; 
                    
                    // при указании разделителя
                    if (str.startsWith("\"") || str.startsWith("'"))
                    {
                        // указать завершающий разделитель
                        index = 1; separator = str.charAt(0); 
                    }
                    // для всех символов строки
                    for (; index < str.length(); index++)
                    {
                        // при завершении имени утилиты
                        char ch = str.charAt(index); if (ch == separator) break; 
                        
                        // при наличии экранирования
                        else if (ch == '\\' && index < str.length() - 1)
                        {
                            // прочитать следующий символ
                            char next = str.charAt(index + 1); 
                        
                            // проверить наличие экранирования
                            if (next == ' ' ) { process.append(next); index++; continue; }
                            if (next == '\\') { process.append(next); index++; continue; }
                            if (next == '\'') { process.append(next); index++; continue; }
                            if (next == '"' ) { process.append(next); index++; continue; }
                        }
                        process.append(ch);
                    }
                    // добавить идентификатор и имя процесса
                    processes.put(Integer.parseInt(pid), process.toString()); 
                }
            }
            return processes; 
        }
    }
}
