using System;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Build.Tasks;
using Microsoft.Build.Utilities;
using Microsoft.Build.Evaluation;
using Microsoft.Win32;

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ � �������������� ����������� ��������� Visual Studio
///////////////////////////////////////////////////////////////////////////////
public class DevEnvExec : Task 
{
	///////////////////////////////////////////////////////////////////////////
    // ��������������� ��������
	///////////////////////////////////////////////////////////////////////////
               public string   DevEnvDir            { get; set; } // ������� Visual Studio
               public string   Version              { get; set; } // ����� ������ Visual Studio
	           public string   Platform             { get; set; } // ���������� ��������� 
               public string[] EnvironmentVariables { get; set; } // ���������� ���������
               public string   WorkingDirectory     { get; set; } // ������� �������
    [Required] public string   Command              { get; set; } // ����������� �������

	///////////////////////////////////////////////////////////////////////////
    // ���������� ������
	///////////////////////////////////////////////////////////////////////////
	public override bool Execute()
    {
        // ��� ���������� �������� Visual Studio
        string devEnvDir = DevEnvDir; if (String.IsNullOrEmpty(devEnvDir))
        {
            // ��� �������� ������ ������
            if (!String.IsNullOrEmpty(Version))
            {
                // �������� ������� Visual Studio
                devEnvDir = GetDevEnvDir(Version); 

                // ��������� ������� ��������
                if (devEnvDir == null) return false; 
            }
        }
        // ��������� ������� �������� Visual Studio
        if (String.IsNullOrEmpty(devEnvDir)) return false; 

        // �������� ���� ������� ��������� ���������� ���������
        string callScript = GetDevEnvScript(devEnvDir);

        // ��������� ������� �������
        if (callScript == null) return false;

        // ������� ��������� ������ �������
        string commandLine = String.Format(
            "{0}{1}{2}", callScript, Environment.NewLine, Command
        );
        // ��������� ������
        ExecuteProgram(commandLine, false, 
			EnvironmentVariables, WorkingDirectory); return true; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // ��������� ������� 
    ///////////////////////////////////////////////////////////////////////////
    private string GetDevEnvScript(string devEnvDir) 
    {
		// ������� ��� ���������� ���������
		string platform = Platform; if (String.IsNullOrEmpty(platform))
		{
   			// ������� ��� ���������� ���������
       		platform = (IntPtr.Size == 4) ? "x86" : "x64"; 
		}
        // ������� ��� �����
        string path = Path.Combine(devEnvDir, @"..\..\VC\vcvarsall.bat");

        // ��������� ������� �����
        if (!File.Exists(path)) 
        {
            // ������� ��� �����
            path = Path.Combine(devEnvDir, @"..\..\VC\Auxiliary\Build\vcvarsall.bat");
        }
        // ��������� ������� �����
        if (!File.Exists(path)) return null; 
        
        // ������� ������� ��������� ���������� ���������
        return String.Format("call \"{0}\" {1}", path, platform); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // ���������� ������� Visual Studio
    ///////////////////////////////////////////////////////////////////////////
    private string GetDevEnvDir(string version)
    { 
        // ������������� ����� ������
        int intVersion = Int32.Parse(version.Replace(".", ""));

        // ���������� ���� � Visual Studio
        return (intVersion >= 150) ? WhereDevEnv(version) : LegacyDevEnv(version);
    }
    ///////////////////////////////////////////////////////////////////////////
    // ���������� ������� Visual Studio ����� ������
    ///////////////////////////////////////////////////////////////////////////
    private string LegacyDevEnv(string version) 
    {
        // ������� ������ �������
		using (RegistryKey node = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))        
        {
    		// ������� ������ �������
        	string regKey = String.Format(@"SOFTWARE\Microsoft\VisualStudio\{0}", version);

        	// ������� ������ �������
        	using (RegistryKey key = node.OpenSubKey(regKey))
        	{
        		// ��������� �������� �� ������� �������
           		if (key != null) { string path = (string)key.GetValue("InstallDir");

               		// ��������� ������� �������� � ������� �������
               		if (!String.IsNullOrEmpty(path)) return path;
           		}
			}
        	// ������� ������ �������
        	regKey = String.Format(@"SOFTWARE\Microsoft\VisualStudio\{0}\Setup\VS", version);

        	// ������� ������ �������
        	using (RegistryKey key = node.OpenSubKey(regKey))
        	{
	       		// ��������� �������� �� ������� �������
           		if (key != null) { string path = (string)key.GetValue("EnvironmentDirectory");

               		// ��������� ������� �������� � ������� �������
               		if (!String.IsNullOrEmpty(path)) return path;
           		}
        	}
		}
        return null; 
	}
    ///////////////////////////////////////////////////////////////////////////
    // ���������� ������� Visual Studio ����� ������� vswhere
    ///////////////////////////////////////////////////////////////////////////
    private string WhereDevEnv(string version)
    {
        // �������� ���� � ������� �����������
        string path = WhereDevEnvPath(); if (path == null) return null;

        // ������� ��������� ������ �������
        string commandLine = String.Format("\"{0}\" -Version {1}", path, version);

        // ��������� �������
        string[] lines = ExecuteProgram(commandLine, true, null, null);

        // ��� ���� �������� �����
        for (int i = 0; i < lines.Length; i++)
        {
            // ��������� ������ ������
            if (!lines[i].StartsWith("productPath:")) continue;

            // ������� ���������
            return Path.GetDirectoryName(lines[i].Substring(12).Trim());
        }
        return null;
    }
    private string WhereDevEnvPath() 
    {
        // �������� ���������� ���������
        string path = Environment.GetEnvironmentVariable("ProgramFiles(x86)"); 

        // �������� ���������� ���������
        if (path == null) path = Environment.GetEnvironmentVariable("ProgramFiles");

        // ��������� ������� ���������� ���������
        if (path == null) return null; 

        // ������� ������ ���� �������
        path = Path.Combine(path, @"Microsoft Visual Studio\Installer\vswhere.exe"); 

        // ��������� ������� �����
        return (File.Exists(path)) ? path : null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // ��������� ��������� ��� ������ ����� ��������� ������
    ///////////////////////////////////////////////////////////////////////////
    private string[] ExecuteProgram(string commandLine, bool consoleToMSBuild, 
		string[] environmentVariables, string workingDirectory)
    {
        // ������� ������
        Exec task = new Exec(); task.BuildEngine = BuildEngine;

        // ������� ������ �������
        task.YieldDuringToolExecution = false;
        task.UseCommandProcessor      = false;

        // ������� ������ ������ ����������
        task.StandardErrorImportance = "high";
	
		// ��� ��������������� ������
		if (consoleToMSBuild)
		{
	        // ������� �������� ��� �������� ������
	        task.EchoOff = true; task.ConsoleToMSBuild = true;

	        // ������� ������ ������ ����������
	        task.StandardOutputImportance = "low";
		}
        // ������� ������ ������ ����������
		else task.StandardOutputImportance = "high";

		// ��� �������� ���������� ���������
		if (environmentVariables != null)
		{
			// ������� ���������� ���������
			task.EnvironmentVariables = environmentVariables; 
		}
		// ��� �������� �������� ��������
		if (!String.IsNullOrEmpty(workingDirectory))
		{
			// ������� ������� �������
			task.WorkingDirectory = workingDirectory; 
		}
        // ������� ��������� ������
        task.Command = commandLine; task.Execute();

		// ��������� ������� ���������������
		if (!consoleToMSBuild) return new string[0]; 

        // ������� ������ �����
        string[] lines = new string[task.ConsoleOutput.Length]; 

        // ��� ���� �������� �����
        for (int i = 0; i < task.ConsoleOutput.Length; i++)
        {
            // ������� ���������
            ITaskItem outputItem = task.ConsoleOutput[i];

            // ��������� �����
            lines[i] = ProjectCollection.Unescape(outputItem.ToString());
        }
        return lines;
    }
}
