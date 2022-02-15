package aladdin.io;
import java.io.*;
import java.util.*;

public class Glob 
{
    ///////////////////////////////////////////////////////////////////////////
    // Перечислить файлы
    ///////////////////////////////////////////////////////////////////////////
	public static String[] matches(String root, 
        String includes, String excludes) throws IOException
    {
        // выделить память для масок файлов
        List<String> includePaths = new ArrayList<String>(); 
        List<String> excludePaths = new ArrayList<String>(); 
        
        // при указании включаемых файлов
        if (includes != null && includes.length() != 0)
        {
            // найти позицию разделителя
            int start = 0; int index = includes.indexOf(File.pathSeparatorChar, start); 

            // пока не найдены все разделители
            for (; index >= 0; index = includes.indexOf(File.pathSeparatorChar, start = index + 1))
            {
                // извлечь отдельную часть маски
                includePaths.add(includes.substring(start, index)); 
            }{
                // извлечь отдельную часть маски
                includePaths.add(includes.substring(start)); 
            }
        }
        // при указании исключаемых файлов
        if (excludes != null && excludes.length() != 0)
        {
            // найти позицию разделителя
            int start = 0; int index = excludes.indexOf(File.pathSeparatorChar, start); 

            // пока не найдены все разделители
            for (; index >= 0; index = excludes.indexOf(File.pathSeparatorChar, start = index + 1))
            {
                // извлечь отдельную часть маски
                excludePaths.add(excludes.substring(start, index)); 
            }{
                // извлечь отдельную часть маски
                excludePaths.add(excludes.substring(start)); 
            }
        }
        // перечислить файлы
        return matches(root, 
            includePaths.toArray(new String[0]),
            excludePaths.toArray(new String[0])
        ); 
    }
	public static String[] matches(String root, 
        String[] includes, String[] excludes) throws IOException
    {
        // проверить указание корневого каталога
		if (root == null) throw new IllegalArgumentException();
        
        // указать объект каталога
        File rootDir = new File(root); if (!rootDir.exists()) return new String[0]; 
        
        // проверить тип каталога
		if (!rootDir.isDirectory()) return new String[0]; 

        // получить каноническое имя каталога
        rootDir = rootDir.getCanonicalFile(); 
        
        // проверить указание параметров
		if (includes == null) includes = new String[0];
		if (excludes == null) excludes = new String[0]; 
        
        // указать признак игнорирования регистра
        boolean ignoreCase = File.pathSeparator.equals(";"); 
    
        // создать список включаемых файлов
		List<FilePattern> includePatterns = new ArrayList<FilePattern>();
        
        // для всех включаемых файлов
		for (String include : includes)
        {
            // заполнить список включаемых файлов
            includePatterns.add(new FilePattern(include, ignoreCase));
        }
        // проверить наличие включаемых файлов
		if (includePatterns.isEmpty()) 
        {
            // указать включение всех файлов
            includePatterns.add(new FilePattern("**", ignoreCase)); 
        }
        // создать список исключаемых файлов
		List<FilePattern> excludePatterns = new ArrayList<FilePattern>();
        
        // для всех исключаемых файлов
		for (String exclude : excludes)
        {
            // заполнить список исключаемых файлов
            excludePatterns.add(new FilePattern(exclude, ignoreCase));
        }
        // создать пустой список совпавших файлов
        List<String> matches = new ArrayList<String>();
        
        // заполнить список совпавших файлов
        includeFiles(rootDir.getAbsolutePath(), null, includePatterns, matches); 
        
        // исключить отдельные файлы из списка
        return excludeFiles(matches, excludePatterns); 
	}
    private static void includeFiles(String root, 
        String directory, List<FilePattern> includes, List<String> matches)
    {
        // проверить возможность совпадений
        if (includes.isEmpty()) return; 
        
        // указать имя каталога
        File dir = new File(directory != null ? root + File.separator + directory : root); 
        
        // прочитать содержимое каталога
        String[] names = dir.canRead() ? dir.list() : new String[0]; 
        
		// для всех файлов и подкаталогов
		for (String name : names) 
        {
            // проверить наличие каталога
            File file = new File(dir, name); if (!file.isDirectory()) continue;
            
            // создать список включаемых файлов для указанного уровня
            List<FilePattern> nextIncludes = new ArrayList<FilePattern>();
            
            // для всех масок включаемых файлов
            for (FilePattern include : includes) 
            {
                // перейти на следующий уровень совпадений
                FilePattern nextInclude = include.nextMatch(name); 
            
                // добавить следующий уровень в список
                if (nextInclude != null) nextIncludes.add(nextInclude); 
            }
            // указать вложенный путь
            String nextDir = (directory != null) ? directory + File.separator + name : name; 
            
            // обработать нижние уровни вложенности
			includeFiles(root, nextDir, nextIncludes, matches);
		}
		// для всех файлов
		for (String name : names) 
        {
            // проверить наличие файла
            File file = new File(dir, name); if (!file.isFile()) continue;
            
            // указать вложенный путь
            String fileName = (directory != null) ? directory + File.separator + name : name;  
            
            // скорректировать имя файла (указать пустое расширение)
            String matchName = (name.contains(".")) ? name : name + "."; 

            // для всех масок включаемых файлов
            for (FilePattern include : includes) 
            {
                // перейти на следующий уровень совпадений
                FilePattern nextInclude = include.nextMatch(matchName); 
                
                // при наличии полного совпадения
                if (nextInclude != null && nextInclude.isFinal()) matches.add(fileName);
            }
        }
    }
	private static String[] excludeFiles(List<String> matches, List<FilePattern> excludes) 
    {
        // проверить наличие исключений
        if (excludes.isEmpty()) return matches.toArray(new String[0]); 
            
        // создать список совпадений
        List<String> list = new ArrayList<String>(); 
        
        // для всех совпадений
        for (String match : matches)
        {
            // для всех исключаемых масок
			boolean find = false; for (FilePattern exclude : excludes) 
            {
                // проверить совпадение
                if (find = exclude.isFinalMatch(match)) break;  
            }
            // указать неисключенное совпадение
            if (!find) list.add(match); 
        }
        // вернуть список неисключенных совпадений
        return list.toArray(new String[0]); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Фильтр поиска файла
    ////////////////////////////////////////////////////////////////////////////
    private static class FilePattern 
    {
        // признак игнорирования регистра и отдельные части маски
        private final boolean ignoreCase; private final String[] parts; 

        // отдельные части маски и текущий уровень
        private final int levelMatch; private final int level; 

        // конструктор
        public FilePattern(String pattern, boolean ignoreCase)
        {
            // указать признак игнорирования регистра
            this.ignoreCase = ignoreCase; levelMatch = -1; level = 0;

            // заменить \ на /
            pattern = pattern.replace('\\', '/');

            // преобразовать в нижний регистр
            if (ignoreCase) pattern = pattern.toLowerCase();

            // создать список отдельных частей
            List<String> list = new ArrayList<String>(); int size = 0; 

            // найти позицию разделителя
            int start = 0; int index = pattern.indexOf('/', start); 

            // пока не найдены все разделители
            for (; index >= 0; index = pattern.indexOf('/', start = index + 1))
            {
                // извлечь отдельную часть маски
                list.add(pattern.substring(start, index)); size++; 
            }{
                // извлечь отдельную часть маски
                list.add(pattern.substring(start)); size++;
            }
            // при завершении символами *.*
            if (size >= 2 && list.get(size - 1).equals("*.*")) 
            {
                // удалить последнюю *.* при предпоследней **
                if (list.get(size - 2).equals("**")) list.remove(size - 1); 
            }    
            // сохранить отдельные части маски
            this.parts = list.toArray(new String[0]); 
        }
        // конструктор
        private FilePattern(FilePattern pattern, int levelMatch, int level) 
        {
            // сохранить переданные параметры
            this.ignoreCase = pattern.ignoreCase; this.parts = pattern.parts;

            // сохранить переданные параметры
            this.levelMatch = levelMatch; this.level = level; 
        }
        // признак полного совпадения
        public final boolean isFinal()
        {
            // проверить наличие полного совпадения
            if (level == parts.length) return true; 

            // проверить завершение **
            return (level == parts.length - 1 && parts[level].equals("**")); 
        }
        // перейти на следующую часть при совпадении
        public final FilePattern nextMatch(String name) 
        { 
            // проверить возможность перехода
            if (level >= parts.length)
            {
                // совпадений не найдено
                if (levelMatch < 0) return null; 

                // перейти на предыдущий **
                else return new FilePattern(this, -1, levelMatch); 
            }
            // для нерекурсивной маски
            else if (!parts[level].equals("**")) 
            {
                // при наличии совпадения
                if (matches(level, name))
                {
                    // перейти на следующий уровень
                    return new FilePattern(this, levelMatch, level + 1); 
                }
                // совпадений не найдено
                else if (levelMatch < 0) return null; 

                // перейти на предыдущий **
                else return new FilePattern(this, -1, levelMatch); 
            }
            else {
                // совпадение при завершении **
                if (level == parts.length - 1) return this; 

                // проверить наличие совпадения
                if (!matches(level + 1, name)) return this; 

                // перейти на следующий уровень
                return new FilePattern(this, level, level + 2); 
            }
        }
        public final boolean isFinalMatch(String fileName)
        {
            // указать начальные условия
            FilePattern pattern = this; 

            // найти позицию разделителя
            int start = 0; int index = fileName.indexOf(File.separatorChar, start); 

            // пока не найдены все разделители
            for (; index >= 0; index = fileName.indexOf(File.separatorChar, start = index + 1))
            {
                // извлечь отдельную часть
                String name = fileName.substring(start, index); 

                // проверить наличие совпадения
                if ((pattern = pattern.nextMatch(name)) == null) return false; 
            }{
                // извлечь отдельную часть
                String name = fileName.substring(start); 

                // проверить наличие совпадения
                if ((pattern = pattern.nextMatch(name)) == null) return false; 
            }
            // проверить наличие полного совпадения
            return pattern.isFinal(); 
        }
        private boolean matches(int level, String name) 
        {
            // обработать допустимость любых имен
            if (parts[level].equals("**")) return true; 

            // преобразовать имя в нижний регистр
            if (ignoreCase) name = name.toLowerCase();

            // при отсутствии * и ?
            if (parts[level].indexOf('*') < 0 && parts[level].indexOf('?') < 0) 
            {
                // проверить полное совпадение имени
                return name.equals(parts[level]);
            }
            // сравнить имя и маску
            return FilePattern.matches(name, 0, parts[level], 0); 
        }
        private static boolean matches(String name, int i, String mask, int j) 
        {
            // для всех сравниваемых символов
            for (; j != mask.length(); i++, j++)
            {
                // в зависимости от символа маски
                switch (mask.charAt(j))
                {
                case '*': 
                {   
                    // проверить завершение маски символом *
                    if (mask.length() == j + 1) return true;  

                    // для всех подстрок
                    for (int k = i; k < name.length(); k++)
                    {
                        // проверить совпадение с подмаской
                        if (matches(name, k, mask, j + 1)) return true; 
                    }
                    return false; 
                }
                case '?': 
                {
                    // проверить наличие символа для сравнения
                    if (name.length() == i) return false; break; 
                }
                default: 
                {
                    // проверить наличие символа для сравнения
                    if (name.length() == i) return false; 

                    // проверить совпадение символа
                    if (name.charAt(i) != mask.charAt(j)) return false; break; 
                }}
            }
            return i == name.length(); 
        }
    }
}
