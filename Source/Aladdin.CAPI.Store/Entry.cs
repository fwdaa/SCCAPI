using System;
using System.Windows.Forms;
using Aladdin.GUI; 

namespace Aladdin.CAPI
{
	internal static class Entry
	{
		///////////////////////////////////////////////////////////////////////
		// Точка входа приложения
		///////////////////////////////////////////////////////////////////////
		[STAThread] 
		static void Main()
		{
            try { 
                // установить стиль отображения
		        Application.EnableVisualStyles(); 

			    // создать среду окружения
			    using (CryptoEnvironment environment = new CryptoEnvironment("Aladdin.CAPI.Store.config")) 
                {
			        // запустить приложение
			        Application.Run(new GUI.ContainersForm(environment));
                }
			}
			// обработать ошибку
			catch (Exception ex) { ErrorDialog.Show("CAPI", ex); }
		}
	}
}

