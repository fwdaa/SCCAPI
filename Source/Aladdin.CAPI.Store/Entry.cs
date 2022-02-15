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
                    // перечислить фабрики алгоритмов
                    using (Factories factories = environment.EnumerateFactories())
                    {
				        // запустить приложение
				        Application.Run(new GUI.ContainersForm(environment, factories.Providers));
                    }
                }
			}
			// обработать ошибку
			catch (Exception ex) { ErrorDialog.Show("CAPI", ex); }
		}
	}
}

