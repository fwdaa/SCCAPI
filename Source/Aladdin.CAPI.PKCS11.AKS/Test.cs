using System;
using System.IO;
using System.Security;

namespace Aladdin.CAPI.PKCS11.AKS
{
	public static class Test
	{
		public static void TestContainerLaser(
            AuthenticationSelector selector, Provider provider, SecurityInfo info)
        {
    	    // указать размер ключей RSA в битах
            int[] rsaBits = new int[] { 512, 1024 }; 
        
			// указать используемый контейнер
			using (CAPI.Container container = (CAPI.Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite))
			{ 
				container.DeleteKeys(); 

                // указать генератор случайных данных
                using (IRand rand = container.Provider.CreateRand(container, null))
                {
    		        // для всех размеров ключей
			        for (int i = 0; i < rsaBits.Length; i++)
        	        {
                        // выполнить тестирование
                        ANSI.Test.TestRSA(provider, container, rand, 
                            true, KeyFlags.None, rsaBits[i], KeySizes.Range(8, 24, 8)
                        ); 
                        ANSI.Test.TestRSA(provider, container, rand, 
                            false, KeyFlags.None, rsaBits[i], KeySizes.Range(16, 24, 8)
                        ); 
                    }
                }
            }
        }
		public static void Entry()
		{
            // указать способ выбора аутентификации
            AuthenticationSelector selector = new AuthenticationSelector("USER");

			// указать провайдер
			using (Provider provider = new Provider()) 
			{
				// перечислить контейнеры
				SecurityInfo[] containersA = provider.EnumerateAllObjects(Scope.Any   ); 
				SecurityInfo[] containersS = provider.EnumerateAllObjects(Scope.System); 
				SecurityInfo[] containersU = provider.EnumerateAllObjects(Scope.User  ); 
				
				// найти смарт-карту (Laser)
				using (SecurityStore store = (SecurityStore)selector.OpenObject(
					provider, Scope.System, "AKS ifdh 0\\eToken", FileAccess.ReadWrite
				)) { 
                    // получить список алгоритмов
                    ulong[] algIDs = ((Applet)store).Algorithms; 

                    // указать способ аутентификации
                    store.Authentication = new Auth.PasswordCredentials("USER", "Qq1234567890");

				    // выполнить аутентификацию
				    string storeName = store.FullName; store.Authenticate(); 

                    // выполнить общие тесты
                    ANSI.PKCS11.Test.TestAlgorithms((Applet)store); 

				    // указать имя контейнера
				    SecurityInfo info = new SecurityInfo(store.Scope, storeName, "CAPI-TEST"); 

				    // выполнить тест
				    TestContainerLaser(selector, provider, info); 
                }
            }
		}
    }
}
