using System;
using System.IO;
using System.Security;

namespace Aladdin.CAPI.PKCS11.JaCarta
{
    //////////////////////////////////////////////////////////////////////////////////////////////////////
	// 					              [JaCarta Laser] [eToken GOST] [JaCarta GOST 2.0]
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // CKM_RSA_PKCS_KEY_PAIR_GEN				+				-				-		0x0000000000000000
    // CKM_RSA_PKCS							    +				-				-		0x0000000000000001
    // CKM_SHA1_RSA_PKCS						+				-				-		0x0000000000000006
    // CKM_RSA_PKCS_OAEP						+				-				-		0x0000000000000009
    // CKM_SHA256_RSA_PKCS						+				-				-		0x0000000000000040
    // CKM_SHA384_RSA_PKCS						+				-				-		0x0000000000000041
    // CKM_SHA512_RSA_PKCS						+				-				-		0x0000000000000042
    // CKM_DES2_KEY_GEN						    +				+				+		0x0000000000000130
    // CKM_DES3_KEY_GEN						    +				+				+		0x0000000000000131
    // CKM_DES3_ECB							    +				+				+		0x0000000000000132
    // CKM_DES3_CBC							    +				+				+		0x0000000000000133
    // CKM_DES3_MAC							    +				+				+		0x0000000000000134
    // CKM_DES3_MAC_GENERAL					    +				+				+		0x0000000000000135
    // CKM_MD5									+				+				+		0x0000000000000210
    // CKM_MD5_HMAC							    +				+				+		0x0000000000000211
    // CKM_SHA_1								+				+				+		0x0000000000000220
    // CKM_SHA_1_HMAC							+				+				+		0x0000000000000221
    // CKM_SHA256								+				+				+		0x0000000000000250
    // CKM_SHA256_HMAC							+				+				+		0x0000000000000251
    // CKM_SHA224								+				+				+		0x0000000000000255
    // CKM_SHA384								+				+				+		0x0000000000000260
    // CKM_SHA384_HMAC							+				+				+		0x0000000000000261
    // CKM_SHA512								+				+				+		0x0000000000000270
    // CKM_SHA512_HMAC							+				+				+		0x0000000000000271
    // CKM_EC_KEY_PAIR_GEN						+				-				-		0x0000000000001040
    // CKM_ECDSA								+				-				-		0x0000000000001041
    // CKM_ECDSA_SHA1							+				-				-		0x0000000000001042
    // CKM_AES_KEY_GEN							+				+				+		0x0000000000001080
    // CKM_AES_ECB								+				+				+		0x0000000000001081
    // CKM_AES_CBC								+				+				+		0x0000000000001082
    // CKM_AES_MAC								+				+				+		0x0000000000001083
    // CKM_AES_MAC_GENERAL						+				+				+		0x0000000000001084
    // CKM_GOSTR3410_KEY_PAIR_GEN				-				+				+		0x0000000000001200
    // CKM_GOSTR3410							-				+				+		0x0000000000001201
    // CKM_GOSTR3410_WITH_GOSTR3411			    - 				+				+		0x0000000000001202
    // CKM_GOSTR3410_KEY_WRAP					+ [?]			+				+		0x0000000000001203
    // CKM_GOSTR3410_DERIVE					    -				-				+		0x0000000000001204
    // CKM_GOSTR3411							+				+				+		0x0000000000001210
    // CKM_GOSTR3411_HMAC						+				+				+		0x0000000000001211
    // CKM_GOST28147_KEY_GEN					+				+				+		0x0000000000001220
    // CKM_GOST28147_ECB						+				+				+		0x0000000000001221
    // CKM_GOST28147							+				+				+		0x0000000000001222
    // CKM_GOST28147_MAC						+				+				+		0x0000000000001223
    // CKM_GOST28147_KEY_WRAP					+				+				+		0x0000000000001224
    // 0x00000000c4900001						+				+				+		0x00000000c4900001
    // 0x00000000c4900002						-               -				+		0x00000000c4900002
    // CKM_GOSTR3410_12_DERIVE					-               -               +		0x00000000d4321007
    // CKM_GOSTR3410_WITH_GOSTR3411_2012_256	-               - 				+		0x00000000d4321008
    // CKM_GOSTR3411_2012_256					+				+				+		0x00000000d4321012
    // CKM_GOSTR3411_2012_512					+				+				+		0x00000000d4321013
    // CKM_GOSTR3411_2012_256_HMAC				+				+				+		0x00000000d4321014
    // CKM_GOSTR3411_2012_512_HMAC				+				+				+		0x00000000d4321015
    // 0x00000000d4321030						+				+				+		0x00000000d4321030
    // 0x00000000d4321031						+				+				+		0x00000000d4321031
    // 0x00000000d4321032						+				+				+		0x00000000d4321032
    // 0x00000000d4321033						+				+				+		0x00000000d4321033
    //////////////////////////////////////////////////////////////////////////////////////////////////////
	public static class Test
	{
		public static void TestContainerLaser(
            AuthenticationSelector selector, Provider provider, SecurityInfo info)
        {
    	    // указать размер ключей RSA в битах
            int[] rsaBits = new int[] { 1024, 2048 }; 
        
			// указать идентификаторы параметров
			string[] ecOIDs = new string[] { 
                ASN1.ANSI.OID.x962_curves_prime192v1,
                ASN1.ANSI.OID.x962_curves_prime192v2,
                ASN1.ANSI.OID.x962_curves_prime192v3,
                ASN1.ANSI.OID.x962_curves_prime256v1,
				ASN1.ANSI.OID.certicom_curves_secp192k1, 
				ASN1.ANSI.OID.certicom_curves_secp224k1, 
				ASN1.ANSI.OID.certicom_curves_secp224r1, 
				ASN1.ANSI.OID.certicom_curves_secp256k1, 
				ASN1.ANSI.OID.certicom_curves_secp384r1, 
				ASN1.ANSI.OID.certicom_curves_secp521r1 
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
        			{
						// выполнить тестирование
						ANSI.Test.TestRSA(provider, container, rand, 
							true, KeyFlags.None, rsaBits[i], KeySizes.Range(16, 32, 8)
						); 
						ANSI.Test.TestRSA(provider, container, rand, 
							false, KeyFlags.None, rsaBits[i], KeySizes.Range(16, 32, 8)
						); 
					}
					// для всех наборов параметров
					for (int i = 0; i < ecOIDs.Length; i++)
					try {
						// выполнить тестирование
						ANSI.Test.TestEC(provider, container, rand, true,  KeyFlags.None, ecOIDs[i]); 
						ANSI.Test.TestEC(provider, container, rand, false, KeyFlags.None, ecOIDs[i]); 
					}
					catch (System.Exception ex) { System.Console.WriteLine(ex); }
				}
            }
        }
		public static void TestContainerCryptotoken(
            AuthenticationSelector selector, Provider provider, SecurityInfo info)
        {
			// указать способ шифрования ключа
            int wrapFlags  = 
                CAPI.GOST.Wrap.RFC4357.NoneSBoxA | CAPI.GOST.Wrap.RFC4357.NoneSBoxB | 
                CAPI.GOST.Wrap.RFC4357.NoneSBoxC | CAPI.GOST.Wrap.RFC4357.NoneSBoxD |
                CAPI.GOST.Wrap.RFC4357.CProSBoxA | CAPI.GOST.Wrap.RFC4357.CProSBoxB | 
                CAPI.GOST.Wrap.RFC4357.CProSBoxC | CAPI.GOST.Wrap.RFC4357.CProSBoxD ;  
                
			// указать используемый контейнер
			using (CAPI.Container container = (CAPI.Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite))
			{ 
				container.DeleteKeys(); 

                // указать генератор случайных данных
                using (IRand rand = container.Provider.CreateRand(container, null))
				{ 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_signs_A, ASN1.GOST.OID.hashes_cryptopro, null, 0
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_A, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_B, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_C, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_D, wrapFlags
					); 
					try {
						// некоторые модели не поддерживают наборы
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_signs_B, ASN1.GOST.OID.hashes_cryptopro, null, 0
						); 
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_signs_C, ASN1.GOST.OID.hashes_cryptopro, null, 0
						); 
					}
					// при возникновении ошибки
					catch (System.Exception ex) { System.Console.WriteLine(ex); 

						// вывести описание ошибки
						System.Console.WriteLine(ex.StackTrace); System.Console.ReadKey(); 
					}
					try { 
						// некоторые модели не поддерживают наборы
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
							ASN1.GOST.OID.encrypts_A, wrapFlags
						); 
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
							ASN1.GOST.OID.encrypts_B, wrapFlags
						); 
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
							ASN1.GOST.OID.encrypts_C, wrapFlags
						); 
						GOST.Test.TestGOSTR3410_2001(
							provider, container, rand, true, KeyFlags.None, 
							ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
							ASN1.GOST.OID.encrypts_D, wrapFlags
						); 
					}
					// при возникновении ошибки
					catch (System.Exception ex) { System.Console.WriteLine(ex); 

						// вывести описание ошибки
						System.Console.WriteLine(ex.StackTrace); System.Console.ReadKey(); 
					}
				}
			}
		}
		public static void TestContainerCryptotoken2(
            AuthenticationSelector selector, Provider provider, SecurityInfo info)
        {
			// указать размеры ключей шифрования
		    int[] keySizes = new int[] { 32 }; 

			// указать способ шифрования ключа
            int wrapFlags  = 
                CAPI.GOST.Wrap.RFC4357.NoneSBoxA | CAPI.GOST.Wrap.RFC4357.NoneSBoxB | 
                CAPI.GOST.Wrap.RFC4357.NoneSBoxC | CAPI.GOST.Wrap.RFC4357.NoneSBoxD |
                CAPI.GOST.Wrap.RFC4357.CProSBoxA | CAPI.GOST.Wrap.RFC4357.CProSBoxB | 
                CAPI.GOST.Wrap.RFC4357.CProSBoxC | CAPI.GOST.Wrap.RFC4357.CProSBoxD |  
				CAPI.GOST.Wrap.RFC4357.NoneSBoxZ | CAPI.GOST.Wrap.RFC4357.CProSBoxZ; 
                
			// указать используемый контейнер
			using (CAPI.Container container = (CAPI.Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite))
			{ 
				container.DeleteKeys(); 

                // указать генератор случайных данных
                using (IRand rand = container.Provider.CreateRand(container, null))
				{ 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_signs_A, ASN1.GOST.OID.hashes_cryptopro, null, 0
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_A, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_B, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_C, wrapFlags
					); 
					GOST.Test.TestGOSTR3410_2001(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
						ASN1.GOST.OID.encrypts_D, wrapFlags
					); 

					GOST.Test.TestGOSTR3410_2012_256(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_signs_A, null, 0
					); 
					GOST.Test.TestGOSTR3410_2012_256(
						provider, container, rand, true, KeyFlags.None, 
						ASN1.GOST.OID.ecc_exchanges_A, keySizes, wrapFlags
					); 
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
					"Aladdin R.D. JaCarta 0\\JaCarta Laser", FileAccess.ReadWrite
				)) { 
                    // получить список алгоритмов
                    ulong[] algIDs = ((Applet)store).Algorithms; 

                    // указать способ аутентификации
                    store.Authentication = new Auth.PasswordCredentials("USER", "1234567890");

				    // выполнить аутентификацию
				    string storeName = store.FullName; store.Authenticate(); 

                    // выполнить общие тесты
                    // ANSI.PKCS11.Test.TestAlgorithms((Applet)store); 

                    // идентификаторы наборов параметров
                    string[] hashOIDs = new string[] { ASN1.GOST.OID.hashes_cryptopro}; 

                    // идентификаторы наборов параметров
                    string[] sboxOIDs = new string[] {
                        ASN1.GOST.OID.encrypts_A, ASN1.GOST.OID.encrypts_B, 
                        ASN1.GOST.OID.encrypts_C, ASN1.GOST.OID.encrypts_D    
                    }; 
                    // выполнить общие тесты
                    // GOST.PKCS11.Test.TestAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

				    // указать имя контейнера
				    SecurityInfo info = new SecurityInfo(store.Scope, storeName, "CAPI-TEST"); 

				    // выполнить тест
				    TestContainerLaser(selector, provider, info); 
                }
				// найти смарт-карту (CryptoToken)
				using (SecurityStore store = (SecurityStore)selector.OpenObject(
					provider, Scope.System,  
					"Aladdin R.D. JaCarta 0\\eToken GOST", FileAccess.ReadWrite
				)) { 
                    // получить список алгоритмов
                    ulong[] algIDs = ((Applet)store).Algorithms; 

                    // указать способ аутентификации
                    store.Authentication = new Auth.PasswordCredentials("USER", "1234567890");

				    // выполнить аутентификацию
				    string storeName = store.FullName; store.Authenticate(); 

                    // выполнить общие тесты
                    // ANSI.PKCS11.Test.TestAlgorithms((Applet)store); 

                    // идентификаторы наборов параметров
                    string[] hashOIDs = new string[] { ASN1.GOST.OID.hashes_cryptopro}; 

                    // идентификаторы наборов параметров
                    string[] sboxOIDs = new string[] {
                        ASN1.GOST.OID.encrypts_A, ASN1.GOST.OID.encrypts_B, 
                        ASN1.GOST.OID.encrypts_C, ASN1.GOST.OID.encrypts_D    
                    }; 
                    // выполнить общие тесты
                    // GOST.PKCS11.Test.TestAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

				    // указать имя контейнера
				    SecurityInfo info = new SecurityInfo(store.Scope, storeName, "CAPI-TEST"); 

				    // выполнить тест
				    TestContainerCryptotoken(selector, provider, info); 
                }
				// найти смарт-карту (CryptoToken2)
				using (SecurityStore store = (SecurityStore)selector.OpenObject(
					provider, Scope.System, 
					"Aladdin R.D. JaCarta 0\\JaCarta GOST 2.0", FileAccess.ReadWrite
				)) { 
                    // получить список алгоритмов
                    ulong[] algIDs = ((Applet)store).Algorithms; 

                    // указать способ аутентификации
                    store.Authentication = new Auth.PasswordCredentials("USER", "1234567890");

					// выполнить аутентификацию
					string storeName = store.FullName; store.Authenticate(); 

                    // выполнить общие тесты
                    ANSI.PKCS11.Test.TestAlgorithms((Applet)store); 

                    // идентификаторы наборов параметров
                    string[] hashOIDs = new string[] { ASN1.GOST.OID.hashes_cryptopro}; 

                    // идентификаторы наборов параметров
                    string[] sboxOIDs = new string[] {
                        ASN1.GOST.OID.encrypts_A, ASN1.GOST.OID.encrypts_B, 
                        ASN1.GOST.OID.encrypts_C, ASN1.GOST.OID.encrypts_D, ASN1.GOST.OID.encrypts_tc26_z
                    }; 
                    // выполнить общие тесты
                    GOST.PKCS11.Test.TestAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

					// указать имя контейнера
					SecurityInfo info = new SecurityInfo(store.Scope, storeName, "CAPI-TEST"); 

					// выполнить тест
					TestContainerCryptotoken2(selector, provider, info); 
				}
			}
		}
    }
}
