using System;
using System.Text;
using System.Threading;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

///////////////////////////////////////////////////////////////////////////////
// Цифровая подпись файла и ее проверка
///////////////////////////////////////////////////////////////////////////////
public class SignTool : ToolTask
{
    // признак выполнения подписи
    private bool sign = true;

    // конструктор
    public SignTool() { Retries = 1; RetryDelay = 1000; ContinueOnError = false; Verbose = false; }

    ///////////////////////////////////////////////////////////////////////
    // Устанавливаемые свойства
    ///////////////////////////////////////////////////////////////////////
    [Required] public string TargetPath       { get; set; } // путь к подписываемому файлу
    [Required] public string HashType         { get; set; } // тип алгоритма хэширования 
      		   public string PfxPath          { get; set; } // путь к контейнеру личного ключа
      		   public string Password         { get; set; } // пароль файла контейнера
      		   public string Thumbprint       { get; set; } // отпечаток сертификата ключа
      		   public string CrossCertificate { get; set; } // кросс-сертификат для подписи
      		   public string TimestampServer  { get; set; } // сервер отметок времени
               public int    Retries          { get; set; } // число попыток
               public int    RetryDelay       { get; set; } // пауза между попытками
      		   public string SignOptions      { get; set; } // дополнительные опции для подписи
      		   public string VerifyOptions    { get; set; } // дополнительные опции для проверки подписи
               public bool   ContinueOnError  { get; set; } // игнорирование ошибок
      		   public bool   Verbose          { get; set; } // детальный вывод информации
      
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
	///////////////////////////////////////////////////////////////////////
    // Выполнение задачи
    ///////////////////////////////////////////////////////////////////////
	public override bool Execute()
    {
        // для вех попыток
        for (int i = 0; i < Retries; i++)
        {
            // выполнить задержку
            if (i != 0) Thread.Sleep(RetryDelay);

		    // выполнить подпись файла
            if (Execute(i == Retries - 1)) return true; 
        }
        return ContinueOnError; 
    }
	private bool Execute(bool logErrors)
    {
        // указать способ обработки ошибок
        LogStandardErrorAsError = logErrors; 

		// выполнить подпись файла
        if (!base.Execute()) return false; sign = false;

		// проверить подпись файла
        try { return base.Execute(); } finally { sign = true; }
    }
    ///////////////////////////////////////////////////////////////////////
    // Вычисление командной строки и параметров
    ///////////////////////////////////////////////////////////////////////

    // имя выполняемой утилиты
    protected override string ToolName { get { return "signtool.exe"; } }

    // полный путь к выполняемой утилите
    protected override string GenerateFullPathToTool() { return ToolName; }

    // командная строка для выполняемой утилиты
	protected override string GenerateCommandLineCommands() 
    {
		// создать пустую командную строку
      	StringBuilder commands = new StringBuilder(sign ? "sign" : "verify");

        // при наличии пути к контейнеру ключа
        if (sign && !String.IsNullOrEmpty(PfxPath))
        {
            // указать путь к контейнеру ключа
            commands.AppendFormat(" /f \"{0}\"", PfxPath); 
        }
        // при наличии пароля к контейнеру
        if (sign && !String.IsNullOrEmpty(Password))
        {
            // указать пароль к контейнеру
            commands.AppendFormat(" /p \"{0}\"", Password);
        }
        // при наличии отпечатка сертификата
        if (sign && !String.IsNullOrEmpty(Thumbprint))
        {
            // указать отпечаток сертификата
            commands.AppendFormat(" /sha1 {0}", Thumbprint);
        }
        // при использовании специального хэш-алгоритма
        if (String.Compare(HashType, "sha1", true) != 0)
		{
	        // указать тип алгоритма хэширования
    	    if (sign) commands.AppendFormat(" /fd {0}", HashType); 
		}
        // при наличии кросс-сертификата
        if (!String.IsNullOrEmpty(CrossCertificate))
        {
            // указать кросс-сертификат
            if (sign) commands.AppendFormat(" /ac \"{0}\"", CrossCertificate);

			// указать проверку подписи драйвера
			else if (!sign) commands.Append(" /kp");
        }
		// указать Authenticode-проверку подписи
		else if (!sign) commands.Append(" /pa");

        // при наличии сервера отметок времени
        if (!String.IsNullOrEmpty(TimestampServer))
        {
			// указать проверку наличия отметок времени
			if (!sign) commands.Append(" /tw");

            // для сервера отметок времени Authenticode
            else if (String.Compare(HashType, "sha1", true) == 0)
            {
            	// указать сервер отметок времени
            	commands.AppendFormat(" /t \"{0}\"", TimestampServer);
			}
            // указать сервер отметок времени
            else commands.AppendFormat(" /tr \"{0}\" /td {1}", TimestampServer, HashType);
        }
        // при наличии дополнительных опций
        if (sign && !String.IsNullOrEmpty(SignOptions))
        {
            // указать дополнительные опции
            commands.AppendFormat(" {0}", SignOptions);
        }
        // при наличии дополнительных опций
        if (!sign && !String.IsNullOrEmpty(VerifyOptions))
        {
            // указать дополнительные опции
            commands.AppendFormat(" {0}", VerifyOptions);
        }
		// указать детализированный вывод
        if (Verbose) commands.Append(" /v");

        // указать имя подписываемого файла 
        commands.AppendFormat(" \"{0}\"", TargetPath); return commands.ToString(); 
    }
}
