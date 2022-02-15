using System;
using System.Text;
using System.Threading;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ����� � �� ��������
///////////////////////////////////////////////////////////////////////////////
public class SignTool : ToolTask
{
    // ������� ���������� �������
    private bool sign = true;

    // �����������
    public SignTool() { Retries = 1; RetryDelay = 1000; ContinueOnError = false; Verbose = false; }

    ///////////////////////////////////////////////////////////////////////
    // ��������������� ��������
    ///////////////////////////////////////////////////////////////////////
    [Required] public string TargetPath       { get; set; } // ���� � �������������� �����
    [Required] public string HashType         { get; set; } // ��� ��������� ����������� 
      		   public string PfxPath          { get; set; } // ���� � ���������� ������� �����
      		   public string Password         { get; set; } // ������ ����� ����������
      		   public string Thumbprint       { get; set; } // ��������� ����������� �����
      		   public string CrossCertificate { get; set; } // �����-���������� ��� �������
      		   public string TimestampServer  { get; set; } // ������ ������� �������
               public int    Retries          { get; set; } // ����� �������
               public int    RetryDelay       { get; set; } // ����� ����� ���������
      		   public string SignOptions      { get; set; } // �������������� ����� ��� �������
      		   public string VerifyOptions    { get; set; } // �������������� ����� ��� �������� �������
               public bool   ContinueOnError  { get; set; } // ������������� ������
      		   public bool   Verbose          { get; set; } // ��������� ����� ����������
      
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
	///////////////////////////////////////////////////////////////////////
    // ���������� ������
    ///////////////////////////////////////////////////////////////////////
	public override bool Execute()
    {
        // ��� ��� �������
        for (int i = 0; i < Retries; i++)
        {
            // ��������� ��������
            if (i != 0) Thread.Sleep(RetryDelay);

		    // ��������� ������� �����
            if (Execute(i == Retries - 1)) return true; 
        }
        return ContinueOnError; 
    }
	private bool Execute(bool logErrors)
    {
        // ������� ������ ��������� ������
        LogStandardErrorAsError = logErrors; 

		// ��������� ������� �����
        if (!base.Execute()) return false; sign = false;

		// ��������� ������� �����
        try { return base.Execute(); } finally { sign = true; }
    }
    ///////////////////////////////////////////////////////////////////////
    // ���������� ��������� ������ � ����������
    ///////////////////////////////////////////////////////////////////////

    // ��� ����������� �������
    protected override string ToolName { get { return "signtool.exe"; } }

    // ������ ���� � ����������� �������
    protected override string GenerateFullPathToTool() { return ToolName; }

    // ��������� ������ ��� ����������� �������
	protected override string GenerateCommandLineCommands() 
    {
		// ������� ������ ��������� ������
      	StringBuilder commands = new StringBuilder(sign ? "sign" : "verify");

        // ��� ������� ���� � ���������� �����
        if (sign && !String.IsNullOrEmpty(PfxPath))
        {
            // ������� ���� � ���������� �����
            commands.AppendFormat(" /f \"{0}\"", PfxPath); 
        }
        // ��� ������� ������ � ����������
        if (sign && !String.IsNullOrEmpty(Password))
        {
            // ������� ������ � ����������
            commands.AppendFormat(" /p \"{0}\"", Password);
        }
        // ��� ������� ��������� �����������
        if (sign && !String.IsNullOrEmpty(Thumbprint))
        {
            // ������� ��������� �����������
            commands.AppendFormat(" /sha1 {0}", Thumbprint);
        }
        // ��� ������������� ������������ ���-���������
        if (String.Compare(HashType, "sha1", true) != 0)
		{
	        // ������� ��� ��������� �����������
    	    if (sign) commands.AppendFormat(" /fd {0}", HashType); 
		}
        // ��� ������� �����-�����������
        if (!String.IsNullOrEmpty(CrossCertificate))
        {
            // ������� �����-����������
            if (sign) commands.AppendFormat(" /ac \"{0}\"", CrossCertificate);

			// ������� �������� ������� ��������
			else if (!sign) commands.Append(" /kp");
        }
		// ������� Authenticode-�������� �������
		else if (!sign) commands.Append(" /pa");

        // ��� ������� ������� ������� �������
        if (!String.IsNullOrEmpty(TimestampServer))
        {
			// ������� �������� ������� ������� �������
			if (!sign) commands.Append(" /tw");

            // ��� ������� ������� ������� Authenticode
            else if (String.Compare(HashType, "sha1", true) == 0)
            {
            	// ������� ������ ������� �������
            	commands.AppendFormat(" /t \"{0}\"", TimestampServer);
			}
            // ������� ������ ������� �������
            else commands.AppendFormat(" /tr \"{0}\" /td {1}", TimestampServer, HashType);
        }
        // ��� ������� �������������� �����
        if (sign && !String.IsNullOrEmpty(SignOptions))
        {
            // ������� �������������� �����
            commands.AppendFormat(" {0}", SignOptions);
        }
        // ��� ������� �������������� �����
        if (!sign && !String.IsNullOrEmpty(VerifyOptions))
        {
            // ������� �������������� �����
            commands.AppendFormat(" {0}", VerifyOptions);
        }
		// ������� ���������������� �����
        if (Verbose) commands.Append(" /v");

        // ������� ��� �������������� ����� 
        commands.AppendFormat(" \"{0}\"", TargetPath); return commands.ToString(); 
    }
}
