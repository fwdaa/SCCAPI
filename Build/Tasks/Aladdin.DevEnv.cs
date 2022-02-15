using System; 
using System.Text; 
using System.IO; 
using Microsoft.Build.Framework; 
using Microsoft.Build.Tasks; 
using Microsoft.Build.Utilities; 
using Microsoft.Build.Evaluation; 
using Microsoft.Win32; 

///////////////////////////////////////////////////////////////////////////////
// Сборка решений и проектов в Visual Studio
///////////////////////////////////////////////////////////////////////////////
public class DevEnv : ToolTask 
{
    // конструктор
    public DevEnv() { LogStandardErrorAsError = true; }

	///////////////////////////////////////////////////////////////////////////
    // Устанавливаемые свойства
	///////////////////////////////////////////////////////////////////////////
               public string Version       { get; set; } // номер версии DevEnv
    [Required] public string Solution      { get; set; } // собираемое решение 
               public string Project       { get; set; } // собираемый проект
    [Required] public string Configuration { get; set; } // конфигурация решения/проекта 
	[Required] public string Platform      { get; set; } // платформа решения/проекта 
    [Required] public string Target        { get; set; } // выполняемое действие 
               public string Options       { get; set; } // параметры командной строки
               public string OutputFile    { get; set; } // имя выходного файла 
      
	///////////////////////////////////////////////////////////////////////
    // Управление выводом 
    ///////////////////////////////////////////////////////////////////////
    public string OutputImportance { get { return StandardOutputImportance; }

        // установить уровень вывода
        set { StandardOutputImportance = value; }
    } 
    protected override void LogToolCommand(string message)
    {
        // вывести сообщение
        Log.LogMessage(MessageImportance.High, message);
    }
	protected override MessageImportance StandardOutputLoggingImportance 
	{ 
		// уровень вывода потока stdout по умолчанию
        get { return MessageImportance.High; } 
	}
	protected override MessageImportance StandardErrorLoggingImportance 
	{ 
		// уровень вывода потока stderr по умолчанию 
        get { return MessageImportance.High; } 
	}
	///////////////////////////////////////////////////////////////////////////
    // Переопределяемые методы
	///////////////////////////////////////////////////////////////////////////

    // имя выполняемой утилиты
    protected override string ToolName { get { return "devenv.com"; } }

    // полный путь к выполняемой утилите
    protected override string GenerateFullPathToTool() 
    {
        // получить каталог Visual Studio
        string path = GetDevEnvDir(Version); if (path == null) return ToolName;

        // указать полный путь
        return Path.Combine(path, ToolName);
    }
    // командная строка для выполняемой утилиты
    protected override string GenerateCommandLineCommands() 
    {
    	// создать пустую командную строку
      	StringBuilder commands = new StringBuilder(); 

	    // добавить в командную строку имя решения
      	commands.AppendFormat(" \"{0}\"", Solution); 

      	// добавить в командную строку выполняемое действие
      	commands.AppendFormat(" /{0}", Target); 

      	// добавить в командную строку конфигурацию решения
      	commands.AppendFormat(" \"{0}|{1}\"", Configuration, Platform); 

      	// при указании имени проекта
      	if (!String.IsNullOrEmpty(Project)) 
      	{
        	// добавить в командную строку имя проекта
      		commands.AppendFormat(" /Project \"{0}\"", Project); 
        }
      	// при указании имени выходного файла
      	if (!String.IsNullOrEmpty(OutputFile)) 
        {
      	 	// добавить в командную строку имя выходного файла
      		commands.AppendFormat(" /Out \"{0}\"", OutputFile); 
        }
        // при указании дополнительных опций
        if (!String.IsNullOrEmpty(Options))
        {
            // добавить дополнительные опции
            commands.AppendFormat(" {0}", Options);
        }
        // вернуть командную строку
        return commands.ToString(); 
	}
    ///////////////////////////////////////////////////////////////////////////
    // Определить каталог Visual Studio
    ///////////////////////////////////////////////////////////////////////////
    private string GetDevEnvDir(string version)
    { 
        // раскодировать номер версии
        int intVersion = Int32.Parse(version.Replace(".", ""));

        // определить путь к Visual Studio
        return (intVersion >= 150) ? WhereDevEnv(version) : LegacyDevEnv(version);
    }
    ///////////////////////////////////////////////////////////////////////////
    // Определить каталог Visual Studio через реестр
    ///////////////////////////////////////////////////////////////////////////
    private string LegacyDevEnv(string version) 
    {
        // открыть раздел реестра
		using (RegistryKey node = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))        
        {
    		// указать раздел реестра
        	string regKey = String.Format(@"SOFTWARE\Microsoft\VisualStudio\{0}", version);

        	// открыть раздел реестра
        	using (RegistryKey key = node.OpenSubKey(regKey))
        	{
        		// прочитать значение из раздела реестра
           		if (key != null) { string path = (string)key.GetValue("InstallDir");

               		// проверить наличие значения в разделе реестра
               		if (!String.IsNullOrEmpty(path)) return path;
           		}
			}
        	// указать раздел реестра
        	regKey = String.Format(@"SOFTWARE\Microsoft\VisualStudio\{0}\Setup\VS", version);

        	// открыть раздел реестра
        	using (RegistryKey key = node.OpenSubKey(regKey))
        	{
	       		// прочитать значение из раздела реестра
           		if (key != null) { string path = (string)key.GetValue("EnvironmentDirectory");

               		// проверить наличие значения в разделе реестра
               		if (!String.IsNullOrEmpty(path)) return path;
           		}
        	}
		}
        return null; 
	}
    ///////////////////////////////////////////////////////////////////////////
    // Определить каталог Visual Studio через утилиту vswhere
    ///////////////////////////////////////////////////////////////////////////
    private string WhereDevEnv(string version)
    {
        // получить путь к утилите определения
        string path = WhereDevEnvPath(); if (path == null) return null;

        // указать командную строку запуска
        string commandLine = String.Format("\"{0}\" -Version {1}", path, version);

        // выполнить команду
        string[] lines = ExecuteProgram(commandLine);

        // для всех выходных строк
        for (int i = 0; i < lines.Length; i++)
        {
            // проверить начало строки
            if (!lines[i].StartsWith("productPath:")) continue;

            // извлечь результат
            return Path.GetDirectoryName(lines[i].Substring(12).Trim());
        }
        return null;
    }
    private string WhereDevEnvPath() 
    {
        // получить переменную окружения
        string path = Environment.GetEnvironmentVariable("ProgramFiles(x86)"); 

        // получить переменную окружения
        if (path == null) path = Environment.GetEnvironmentVariable("ProgramFiles");

        // проверить наличие переменной окружения
        if (path == null) return null; 

        // указать полный путь утилиты
        path = Path.Combine(path, @"Microsoft Visual Studio\Installer\vswhere.exe"); 

        // проверить наличие файла
        return (File.Exists(path)) ? path : null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Выполнить программу или скрипт через командную строку
    ///////////////////////////////////////////////////////////////////////////
    private string[] ExecuteProgram(string commandLine)
    {
        // создать задачу
        Exec task = new Exec(); task.BuildEngine = BuildEngine;

        // указать способ запуска
        task.YieldDuringToolExecution = false;
        task.UseCommandProcessor      = false;

        // указать уровни вывода информации
        task.StandardErrorImportance  = "high";
        task.StandardOutputImportance = "low";

        // указать приемник для выходных данных
        task.EchoOff = true; task.ConsoleToMSBuild = true;

        // указать командную строку
        task.Command = commandLine; task.Execute();

        // создать список строк
        string[] lines = new string[task.ConsoleOutput.Length]; 

        // для всех выходных строк
        for (int i = 0; i < task.ConsoleOutput.Length; i++)
        {
            // извлечь результат
            ITaskItem outputItem = task.ConsoleOutput[i];

            // сохранить вывод
            lines[i] = ProjectCollection.Unescape(outputItem.ToString());
        }
        return lines;
    }
}
