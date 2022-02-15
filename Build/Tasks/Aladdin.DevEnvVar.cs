﻿using System;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Build.Tasks;
using Microsoft.Build.Utilities;
using Microsoft.Build.Evaluation;
using Microsoft.Win32;

///////////////////////////////////////////////////////////////////////////////
// Получить переменную окружения Visual Studio
///////////////////////////////////////////////////////////////////////////////
public class DevEnvVariable : Task 
{
	///////////////////////////////////////////////////////////////////////////
    // Устанавливаемые свойства
	///////////////////////////////////////////////////////////////////////////
               public string DevEnvDir { get; set; } // каталог Visual Studio
               public string Version   { get; set; } // номер версии Visual Studio
	           public string Platform  { get; set; } // аппаратная платформа 
    [Required] public string Name      { get; set; } // имя переменной окружения
    [Output  ] public string Value     { get; set; } // значение переменной окружения

	///////////////////////////////////////////////////////////////////////////
    // Выполнение задачи
	///////////////////////////////////////////////////////////////////////////
	public override bool Execute()
    {
        // при отсутствии каталога Visual Studio
        string devEnvDir = DevEnvDir; if (String.IsNullOrEmpty(devEnvDir))
        {
            // при указании номера версии
            if (!String.IsNullOrEmpty(Version))
            {
                // получить каталог Visual Studio
                devEnvDir = GetDevEnvDir(Version); 

                // проверить наличие каталога
                if (devEnvDir == null) return false; 
            }
        }
        // при наличии каталога Visual Studio
        if (!String.IsNullOrEmpty(devEnvDir))
        {
            // получить переменную окружения 
            Value = GetDevEnvVariable(devEnvDir, Name); 
            
            // проверить наличие переменной
            return (Value != null); 
        }
        else {
            // получить переменную окружения 
            Value = Environment.GetEnvironmentVariable(Name);

            // сохранить результат
            if (Value == null) Value = String.Empty; return true; 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Получить переменную окружения Visual Studio
    ///////////////////////////////////////////////////////////////////////////
    private string GetDevEnvVariable(string devEnvDir, string name)
    {
        // получить путь скрипта установки переменных окружения
        string callScript = GetDevEnvScript(devEnvDir);

        // проверить наличие скрипта
        if (callScript == null) return null;

        // указать командную строку запуска
        string commandLine = String.Format(
            "{0}{1}echo {2}=%{2}%", callScript, Environment.NewLine, name
        );
        // выполнить скрипт
        string[] lines = ExecuteProgram(commandLine);

        // для всех выходных строк
        for (int i = 0; i < lines.Length; i++)
        {
            // проверить начало строки
            if (!lines[i].StartsWith(name + "=")) continue;

            // извлечь результат
            return lines[i].Substring(name.Length + 1);
        }
        return null;
    }
    private string GetDevEnvScript(string devEnvDir) 
    {
		// указать тип аппаратной платформы
		string platform = Platform; if (String.IsNullOrEmpty(platform))
		{
   			// указать тип аппаратной платформы
       		platform = (IntPtr.Size == 4) ? "x86" : "x64"; 
		}
        // указать имя файла
        string path = Path.Combine(devEnvDir, @"..\..\VC\vcvarsall.bat");

        // проверить наличие файла
        if (!File.Exists(path)) 
        {
            // указать имя файла
            path = Path.Combine(devEnvDir, @"..\..\VC\Auxiliary\Build\vcvarsall.bat");
        }
        // проверить наличие файла
        if (!File.Exists(path)) return null; 
        
        // указать команду установки переменных окружения
        return String.Format("call \"{0}\" {1}", path, platform); 
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
