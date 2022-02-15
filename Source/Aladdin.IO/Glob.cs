using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.IO
{
    public static class Glob 
    {
        ///////////////////////////////////////////////////////////////////////////
        // Перечислить файлы
        ///////////////////////////////////////////////////////////////////////////
	    public static string[] Matches(string root, string includes, string excludes)
        {
            // указать начальные условия
            string[] includePaths = null; string[] excludePaths = null; 

            // разбить строки на части
            if (!String.IsNullOrEmpty(includes)) includePaths = includes.Split(';'); 
            if (!String.IsNullOrEmpty(excludes)) excludePaths = excludes.Split(';'); 

            // перечислить файлы
            return Matches(root, includePaths, excludePaths); 
        }
	    public static string[] Matches(string root, string[] includes, string[] excludes) 
        {
            // проверить указание корневого каталога
		    if (root == null) throw new ArgumentException();
        
            // проверить наличие каталога
		    if (!Directory.Exists(root)) return new String[0]; 

            // при указании не только имени диска
            if (!root.EndsWith(":\\") && !root.EndsWith(":"))
            {
                // добавить разделитель (для Path.GetDirectoryName)
                if (!root.EndsWith("\\")) root += "\\"; 

                // получить абсолютное имя каталога (без разделителя)
                root = Path.GetDirectoryName(root); 
            }
            // проверить указание параметров
		    if (includes == null) includes = new String[0];
		    if (excludes == null) excludes = new String[0]; 
        
            // создать список включаемых файлов
		    List<FilePattern> includePatterns = new List<FilePattern>();
        
            // для всех включаемых файлов
		    foreach (String include in includes)
            {
                // заполнить список включаемых файлов
                includePatterns.Add(new FilePattern(include, true));
            }
            // проверить наличие включаемых файлов
		    if (includePatterns.Count == 0) 
            {
                // указать включение всех файлов
                includePatterns.Add(new FilePattern("**", true)); 
            }
            // создать список исключаемых файлов
		    List<FilePattern> excludePatterns = new List<FilePattern>();
        
            // для всех исключаемых файлов
		    foreach (String exclude in excludes)
            {
                // заполнить список исключаемых файлов
                excludePatterns.Add(new FilePattern(exclude, true));
            }
            // создать пустой список совпавших файлов
            List<String> matches = new List<String>();
        
            // заполнить список совпавших файлов
            IncludeFiles(root, null, includePatterns, matches); 
        
            // исключить отдельные файлы из списка
            return ExcludeFiles(matches, excludePatterns); 
	    }
        private static void IncludeFiles(string root, 
            string directory, List<FilePattern> includes, List<String> matches)
        {
            // проверить возможность совпадений
            if (includes.Count == 0) return; 

            // указать имя каталога
            string path = (directory != null) ? root + "\\" + directory : root; 

		    // для всех подкаталогов
		    foreach (string name in Directory.GetDirectories(path)) 
            {
                // определить имя каталога
                string nextDir = name.Substring(path.Length + 1); 

                // создать список включаемых файлов для указанного уровня
                List<FilePattern> nextIncludes = new List<FilePattern>();
            
                // для всех масок включаемых файлов
                foreach (FilePattern include in includes) 
                {
                    // перейти на следующий уровень совпадений
                    FilePattern nextInclude = include.NextMatch(nextDir); 
            
                    // добавить следующий уровень в список
                    if (nextInclude != null) nextIncludes.Add(nextInclude); 
                }
                // указать вложенный путь
                nextDir = (directory != null) ? directory + "\\" + nextDir : nextDir; 

                // обработать нижние уровни вложенности
			    IncludeFiles(root, nextDir, nextIncludes, matches);
		    }
		    // для всех файлов
		    foreach (string name in Directory.GetFiles(path)) 
            {
                // определить имя каталога
                string fileName = name.Substring(path.Length + 1); 

                // скорректировать имя файла (указать пустое расширение)
                String matchName = (fileName.Contains(".")) ? fileName : fileName + "."; 

                // для всех масок включаемых файлов
                foreach (FilePattern include in includes) 
                {
                    // перейти на следующий уровень совпадений
                    FilePattern nextInclude = include.NextMatch(matchName); 
                
                    // при наличии полного совпадения добавить имя совпавшего файла
                    if (nextInclude != null && nextInclude.IsFinal) 
                    {
                        // указать вложенный путь
                        matches.Add(directory != null ? directory + "\\" + fileName : fileName);  
                    }
                }
            }
        }
	    private static String[] ExcludeFiles(List<String> matches, List<FilePattern> excludes) 
        {
            // проверить наличие исключений
            if (excludes.Count == 0) return matches.ToArray(); 

            // создать список совпадений
            List<String> list = new List<String>(); 
        
            // для всех совпадений
            foreach (String match in matches)
            {
                // для всех исключаемых масок
			    bool find = false; foreach (FilePattern exclude in excludes) 
                {
                    // проверить совпадение
                    if (find = exclude.IsFinalMatch(match)) break;  
                }
                // указать неисключенное совпадение
                if (!find) list.Add(match); 
            }
            // вернуть список неисключенных совпадений
            return list.ToArray(); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Фильтр поиска файла
        ////////////////////////////////////////////////////////////////////////////
        private class FilePattern 
        {
            // признак игнорирования регистра и отдельные части маски
            private readonly bool ignoreCase; private readonly string[] parts; 

            // уровень наличия ** и текущий уровень
            private readonly int levelMatch; private readonly int level; 

            // конструктор
            public FilePattern(string pattern, bool ignoreCase)
            {
                // указать признак игнорирования регистра
                this.ignoreCase = ignoreCase; levelMatch = -1; level = 0;

                // заменить \ на /
                pattern = pattern.Replace('\\', '/');

                // преобразовать в нижний регистр
                if (ignoreCase) pattern = pattern.ToLower();

                // сохранить отдельные части маски
                parts = pattern.Split('/'); int size = parts.Length; 

                // при завершении символами *.*
                if (size >= 2 && parts[size - 1] == "*.*") 
                {
                    // удалить последнюю *.* при предпоследней **
                    if (parts[size - 2] == "**") Array.Resize(ref parts, size - 1); 
                }    
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
            public bool IsFinal { get 
            {
                // проверить наличие полного совпадения
                if (level == parts.Length) return true; 

                // проверить завершение **
                return (level == parts.Length - 1 && parts[level] == "**"); 
            }}
            // перейти на следующую часть при совпадении
            public FilePattern NextMatch(string name) 
            { 
                // проверить возможность перехода
                if (level >= parts.Length)
                {
                    // совпадений не найдено
                    if (levelMatch < 0) return null; 

                    // перейти на предыдущий **
                    else return new FilePattern(this, -1, levelMatch); 
                }
                // для нерекурсивной маски
                else if (parts[level] != "**") 
                {
                    // при наличии совпадения
                    if (Matches(level, name))
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
                    if (level == parts.Length - 1) return this; 

                    // проверить наличие совпадения
                    if (!Matches(level + 1, name)) return this; 

                    // перейти на следующий уровень
                    return new FilePattern(this, level, level + 2); 
                }
            }
            public bool IsFinalMatch(String fileName)
            {
                // указать начальные условия
                FilePattern pattern = this; char sep = '\\'; 

                // найти позицию разделителя
                int start = 0; int index = fileName.IndexOf(sep, start); 

                // пока не найдены все разделители
                for (; index >= 0; index = fileName.IndexOf(sep, start = index + 1))
                {
                    // извлечь отдельную часть
                    String name = fileName.Substring(start, index - start); 

                    // проверить наличие совпадения
                    if ((pattern = pattern.NextMatch(name)) == null) return false; 
                }{
                    // извлечь отдельную часть
                    String name = fileName.Substring(start); 

                    // проверить наличие совпадения
                    if ((pattern = pattern.NextMatch(name)) == null) return false; 
                }
                // проверить наличие полного совпадения
                return pattern.IsFinal; 
            }
            private bool Matches(int level, string name) 
            {
                // обработать допустимость любых имен
                if (parts[level] == "**") return true; 

                // преобразовать имя в нижний регистр
                if (ignoreCase) name = name.ToLower();

                // при отсутствии * и ?
                if (parts[level].IndexOf('*') < 0 && parts[level].IndexOf('?') < 0) 
                {
                    // проверить полное совпадение имени
                    return name == parts[level];
                }
                // сравнить имя и маску
                return FilePattern.Matches(name, 0, parts[level], 0); 
            }
            private static bool Matches(string name, int i, string mask, int j) 
            {
                // для всех сравниваемых символов
                for (; j != mask.Length; i++, j++)
                {
                    // в зависимости от символа маски
                    switch (mask[j])
                    {
                    case '*': 
                    {   
                        // проверить завершение маски символом *
                        if (mask.Length == j + 1) return true;  

                        // для всех подстрок
                        for (int k = i; k < name.Length; k++)
                        {
                            // проверить совпадение с подмаской
                            if (Matches(name, k, mask, j + 1)) return true; 
                        }
                        return false; 
                    }
                    case '?': 
                    {
                        // проверить наличие символа для сравнения
                        if (name.Length == i) return false; break; 
                    }
                    default: 
                    {
                        // проверить наличие символа для сравнения
                        if (name.Length == i) return false; 

                        // проверить совпадение символа
                        if (name[i] != mask[j]) return false; break; 
                    }}
                }
                return i == name.Length; 
            }
        }
    }
}
