using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using Microsoft.Build.Framework;
using Microsoft.Build.Tasks;
using Microsoft.Build.Utilities;
using Microsoft.Win32;

///////////////////////////////////////////////////////////////////////////////
// Получить каталоги среды .NET
///////////////////////////////////////////////////////////////////////////////
public class TargetFrameworkDirs : Task 
{
    ///////////////////////////////////////////////////////////////////////////
    // Устанавливаемые свойства
	///////////////////////////////////////////////////////////////////////////
    [Required] public string Version   { get; set; } // версия платформы .NET
    [Output  ] public string ToolsDir  { get; set; } // каталог утилит .NET

	///////////////////////////////////////////////////////////////////////////
    // Выполнение задачи
	///////////////////////////////////////////////////////////////////////////
	public override bool Execute()
    {
        // обработать специальные версии
        if (Version == "v4.8"  ) ToolsDir = GetToolsDir48 (); else 
        if (Version == "v4.7.2") ToolsDir = GetToolsDir472(); else 
        if (Version == "v4.7.1") ToolsDir = GetToolsDir471(); else 
        if (Version == "v4.6.2") ToolsDir = GetToolsDir462(); else 
        if (Version == "v4.6.1") ToolsDir = GetToolsDir461(); else 
        if (Version == "v4.6"  ) ToolsDir = GetToolsDir46 (); else 
        if (Version == "v4.5.2") ToolsDir = GetToolsDir452(); else 
        if (Version == "v4.5.1") ToolsDir = GetToolsDir451(); else 
        if (Version == "v4.5"  ) ToolsDir = GetToolsDir45 (); else 
        if (Version == "v4.0"  ) ToolsDir = GetToolsDir40 (); else 
        if (Version == "v3.5"  ) ToolsDir = GetToolsDir35 (); else 
        if (Version == "v3.0"  ) ToolsDir = GetToolsDir20 (); else 
        if (Version == "v2.0"  ) ToolsDir = GetToolsDir20 (); else 
        
        // выполнить обработку по умолчанию
        ToolsDir = GetFrameworkToolsDir(Version, null); return (ToolsDir != null);
    }
	///////////////////////////////////////////////////////////////////////////
    // Получить каталог через встроенную задачу
	///////////////////////////////////////////////////////////////////////////
    private string GetFrameworkToolsDir(string version, string relativePath)
    {
        // удалить первый символ при необходимости
        if (version.StartsWith("v")) version = version.Substring(1);

        // указать относительный путь по умолчанию
        if (relativePath == null) relativePath = String.Format(@"bin\NETFX {0} Tools", version); 
            
        // создать список имен свойств
        List<String> propertyNames = new List<String>(); 

        // удалить разделители
        string str = version.Replace(".", ""); 

        // до базовой версии
        for (; str.Length >= 2; str = str.Substring(0, str.Length - 1))
        {
            // указать имя свойства
            string propertyName = String.Format("FrameworkSdkVersion{0}Path", str); 

            // сохранить имя свойства
            propertyNames.Add(propertyName);
        }
        // создать встроенную задачу
        GetFrameworkSdkPath task = new GetFrameworkSdkPath(); 

        // выполнить задачу
        task.BuildEngine = BuildEngine; if (!task.Execute()) return null;  

        // для всех распознаваемых свойств
        foreach (string propertyName in propertyNames)
        {
            // получить свойство типа
            PropertyInfo property = task.GetType().GetProperty(propertyName); 

            // проверить наличие свойства
            if (property == null) continue; 

            // получить значение свойства
            string directory = (string)property.GetValue(task, null); 

     	    // проверить наличие значения в разделе реестра
       	    if (String.IsNullOrEmpty(directory)) continue; 

            // указать полный путь 
            directory = Path.Combine(directory, relativePath); 

            // проверить наличие каталога
            if (Directory.Exists(directory)) return directory; 
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////////
    // Получить каталог через реестр
	///////////////////////////////////////////////////////////////////////////
    private string GetRegistryToolsDir(
        string[] registryKeys, string relativePath)
    {
        // для всех разделов реестра
        foreach (string registryKey in registryKeys)
        {
            // открыть раздел реестра
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey))
            {
        	    // проверить наличие раздела реестра
                if (key == null) continue; 

        	    // прочитать значение из раздела реестра
                string directory = (string)key.GetValue("InstallationFolder");

         	    // проверить наличие значения в разделе реестра
          	    if (String.IsNullOrEmpty(directory)) continue; 

                // указать полный путь 
                directory = Path.Combine(directory, relativePath); 

                // проверить наличие каталога
                if (Directory.Exists(directory)) return directory; 
		    }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Получить каталоги для первых целевых версий
    ///////////////////////////////////////////////////////////////////////////
    private string GetToolsDir20()
    {
        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v2.0", @"bin"); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v6.0A"
        }; 
        // получить значение через реестр
        return GetRegistryToolsDir(registryKeys, @"bin"); 
    }
    private string GetToolsDir35()
    {
        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v3.5", @"bin"); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v7.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v7.0A"
        }; 
        // получить значение через реестр
        directory = GetRegistryToolsDir(registryKeys, @"bin"); 

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir20(); 
    }
    private string GetToolsDir40()
    {
        // указать относительный путь
        string relativePath = @"bin\NETFX 4.0 Tools"; 

        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v4.0", relativePath); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.0A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v7.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v7.0A"
        }; 
        // получить значение через реестр
        directory = GetRegistryToolsDir(registryKeys, relativePath); 

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir35(); 
    }
    private string GetToolsDir45()
    {
        // указать относительный путь
        string relativePath = @"bin\NETFX 4.5 Tools"; 

        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v4.5", relativePath); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.0A"
        }; 
        // получить значение через реестр
        directory = GetRegistryToolsDir(registryKeys, relativePath); 

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir40(); 
    }
    private string GetToolsDir451()
    {
        // указать относительный путь
        string relativePath = @"bin\NETFX 4.5.1 Tools"; 

        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v4.5.1", relativePath); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.0A"
        }; 
        // получить значение через реестр
        directory = GetRegistryToolsDir(registryKeys, relativePath); 

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir45(); 
    }
    private string GetToolsDir452()
    {
        // указать относительный путь
        string relativePath = @"bin\NETFX 4.5.2 Tools"; 

        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v4.5.2", relativePath); 

        // проверить наличие свойства
        if (directory != null) return directory; 

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1A",
            @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.0A"
        }; 
        // получить значение через реестр
        directory = GetRegistryToolsDir(registryKeys, relativePath); 

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir451(); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Получить каталоги для последних целевых версий
    ///////////////////////////////////////////////////////////////////////////
    private string GetToolsDir(string version)
    {
        // удалить первый символ при необходимости
        if (version.StartsWith("v")) version = version.Substring(1);

        // указать относительный путь
        string relativePath = String.Format(@"bin\NETFX {0} Tools", version);

        // получить значение встроенного свойства
        string directory = GetFrameworkToolsDir("v" + version, relativePath);

        // проверить наличие свойства
        if (directory != null) return directory;

        // указать разделы реестра
        string[] registryKeys = new string[] {
            @"SOFTWARE\Microsoft\Microsoft SDKs\NETFXSDK\" + version
        };
        // получить значение через реестр
        return GetRegistryToolsDir(registryKeys, relativePath);
    }
    private string GetToolsDir46()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.6");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir452();
    }
    private string GetToolsDir461()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.6.1");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir46();
    }
    private string GetToolsDir462()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.6.2");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir461();
    }
    private string GetToolsDir471()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.7.1");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir462();
    }
    private string GetToolsDir472()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.7.2");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir471();
    }
    private string GetToolsDir48()
    {
        // получить требуемый путь
        string directory = GetToolsDir("v4.8");

        // проверить наличие значения
        return (directory != null) ? directory : GetToolsDir472();
    }
}
