using System;
using System.IO;

namespace Aladdin.CAPI.PKCS11.Athena
{
	public static class Test
	{
		public static void TestContainerLaser(
            AuthenticationSelector selector, Provider provider, SecurityInfo info)
        {
    	    // указать размер ключей RSA в битах
            int[] rsaBits = new int[] { 512, 1024, 1536, 2048 }; 
        
			// указать идентификаторы параметров
			string[] ecOIDs = new string[] { 
                ASN1.ANSI.OID.x962_curves_prime192v1,
                ASN1.ANSI.OID.x962_curves_prime192v2,
                ASN1.ANSI.OID.x962_curves_prime192v3,
                ASN1.ANSI.OID.x962_curves_prime256v1,
				ASN1.ANSI.OID.certicom_curves_secp160k1, 
				ASN1.ANSI.OID.certicom_curves_secp160r1, 
				ASN1.ANSI.OID.certicom_curves_secp160r2, 
				ASN1.ANSI.OID.certicom_curves_secp192k1, 
				ASN1.ANSI.OID.certicom_curves_secp224k1, 
				ASN1.ANSI.OID.certicom_curves_secp224r1, 
				ASN1.ANSI.OID.certicom_curves_secp256k1, 
				ASN1.ANSI.OID.certicom_curves_secp384r1, 
				ASN1.ANSI.OID.certicom_curves_secp521r1, 
			}; 
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
        			try {
						// выполнить тестирование
						ANSI.Test.TestRSA(provider, container, rand, 
							true, KeyFlags.None, rsaBits[i], KeySizes.Range(8, 32, 8)
						); 
						ANSI.Test.TestRSA(provider, container, rand, 
							false, KeyFlags.None, rsaBits[i], KeySizes.Range(8, 32, 8)
						); 
					}
					catch (System.Exception ex) { System.Console.WriteLine(ex); }
					
 					// для всех наборов параметров
					for (int i = 0; i < ecOIDs.Length; i++)
					try {
						// выполнить тестирование
						ANSI.Test.TestEC(provider, container, rand, true,  KeyFlags.None, ecOIDs[i]); // CKR_DOMAIN_PARAMS_INVALID ?
						ANSI.Test.TestEC(provider, container, rand, false, KeyFlags.None, ecOIDs[i]); // CKR_DOMAIN_PARAMS_INVALID ?
					}
					catch (System.Exception ex) { System.Console.WriteLine(ex); }
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
					provider, Scope.System,  
					"Athena IDProtect Key 0\\JaCarta", FileAccess.ReadWrite		// "Qq12345678" 
					// "ARDS JaCarta 0\\CNS", FileAccess.ReadWrite				// "1234567890" 
					// "ARDS JaCarta 0\\JaCarta Laser", FileAccess.ReadWrite	// "1234567890" 
				)) { 
                    // получить список алгоритмов
                    ulong[] algIDs = ((Applet)store).Algorithms; 

                    // указать способ аутентификации
                    store.Authentication = new Auth.PasswordCredentials("USER", "Qq12345678");
                    // store.Authentication = new Auth.PasswordCredentials("USER", "1234567890");

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
