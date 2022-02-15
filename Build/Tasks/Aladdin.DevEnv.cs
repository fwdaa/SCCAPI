using System; 
using System.Text; 
using System.IO; 
using Microsoft.Build.Framework; 
using Microsoft.Build.Tasks; 
using Microsoft.Build.Utilities; 
using Microsoft.Build.Evaluation; 
using Microsoft.Win32; 

///////////////////////////////////////////////////////////////////////////////
// ������ ������� � �������� � Visual Studio
///////////////////////////////////////////////////////////////////////////////
public class DevEnv : ToolTask 
{
    // �����������
    public DevEnv() { LogStandardErrorAsError = true; }

	///////////////////////////////////////////////////////////////////////////
    // ��������������� ��������
	///////////////////////////////////////////////////////////////////////////
               public string Version       { get; set; } // ����� ������ DevEnv
    [Required] public string Solution      { get; set; } // ���������� ������� 
               public string Project       { get; set; } // ���������� ������
    [Required] public string Configuration { get; set; } // ������������ �������/������� 
	[Required] public string Platform      { get; set; } // ��������� �������/������� 
    [Required] public string Target        { get; set; } // ����������� �������� 
               public string Options       { get; set; } // ��������� ��������� ������
               public string OutputFile    { get; set; } // ��� ��������� ����� 
      
	///////////////////////////////////////////////////////////////////////
    // ���������� ������� 
    ///////////////////////////////////////////////////////////////////////
    public string OutputImportance { get { return StandardOutputImportance; }

        // ���������� ������� ������
        set { StandardOutputImportance = value; }
    } 
    protected override void LogToolCommand(string message)
    {
        // ������� ���������
        Log.LogMessage(MessageImportance.High, message);
    }
	protected override MessageImportance StandardOutputLoggingImportance 
	{ 
		// ������� ������ ������ stdout �� ���������
        get { return MessageImportance.High; } 
	}
	protected override MessageImportance StandardErrorLoggingImportance 
	{ 
		// ������� ������ ������ stderr �� ��������� 
        get { return MessageImportance.High; } 
	}
	///////////////////////////////////////////////////////////////////////////
    // ���������������� ������
	///////////////////////////////////////////////////////////////////////////

    // ��� ����������� �������
    protected override string ToolName { get { return "devenv.com"; } }

    // ������ ���� � ����������� �������
    protected override string GenerateFullPathToTool() 
    {
        // �������� ������� Visual Studio
        string path = GetDevEnvDir(Version); if (path == null) return ToolName;

        // ������� ������ ����
        return Path.Combine(path, ToolName);
    }
    // ��������� ������ ��� ����������� �������
    protected override string GenerateCommandLineCommands() 
    {
    	// ������� ������ ��������� ������
      	StringBuilder commands = new StringBuilder(); 

	    // �������� � ��������� ������ ��� �������
      	commands.AppendFormat(" \"{0}\"", Solution); 

      	// �������� � ��������� ������ ����������� ��������
      	commands.AppendFormat(" /{0}", Target); 

      	// �������� � ��������� ������ ������������ �������
      	commands.AppendFormat(" \"{0}|{1}\"", Configuration, Platform); 

      	// ��� �������� ����� �������
      	if (!String.IsNullOrEmpty(Project)) 
      	{
        	// �������� � ��������� ������ ��� �������
      		commands.AppendFormat(" /Project \"{0}\"", Project); 
        }
      	// ��� �������� ����� ��������� �����
      	if (!String.IsNullOrEmpty(OutputFile)) 
        {
      	 	// �������� � ��������� ������ ��� ��������� �����
      		commands.AppendFormat(" /Out \"{0}\"", OutputFile); 
        }
        // ��� �������� �������������� �����
        if (!String.IsNullOrEmpty(Options))
        {
            // �������� �������������� �����
            commands.AppendFormat(" {0}", Options);
        }
        // ������� ��������� ������
        return commands.ToString(); 
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
        string[] lines = ExecuteProgram(commandLine);

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
    private string[] ExecuteProgram(string commandLine)
    {
        // ������� ������
        Exec task = new Exec(); task.BuildEngine = BuildEngine;

        // ������� ������ �������
        task.YieldDuringToolExecution = false;
        task.UseCommandProcessor      = false;

        // ������� ������ ������ ����������
        task.StandardErrorImportance  = "high";
        task.StandardOutputImportance = "low";

        // ������� �������� ��� �������� ������
        task.EchoOff = true; task.ConsoleToMSBuild = true;

        // ������� ��������� ������
        task.Command = commandLine; task.Execute();

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
