package aladdin.capi.pkcs11.jacarta;
import aladdin.capi.*; 
import aladdin.capi.auth.*; 
import aladdin.capi.pkcs11.*; 

public class Test
{
	public static void testContainerLaser(
        AuthenticationSelector selector, Provider provider, SecurityInfo info) throws Exception
    {
    	// указать размер ключей RSA в битах
        int[] rsaBits = new int[] { 1024, 2048 }; 
        
    	// указать идентификаторы параметров
		String[] ecOIDs = new String[] { 
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V1,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V2,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V3,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME256V1,
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP192K1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP224K1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP224R1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP256K1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP384R1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP521R1 
        }; 
        // указать используемый контейнер
        try (aladdin.capi.Container container = (aladdin.capi.Container)
            selector.openObject(provider, info.scope, info.fullName(), "rw")) 
        { 
            container.deleteKeys(); 
            
            // указать генератор случайных данных
            try (IRand rand = container.provider().createRand(container, null))
            {
                // для всех размеров ключей
                for (int i = 0; i < rsaBits.length; i++)
                {
                    // выполнить тестирование
                    aladdin.capi.ansi.Test.testRSA(provider, container, rand, 
                        true, KeyFlags.NONE, rsaBits[i], KeySizes.range(16, 32, 8)
                    ); 
                    aladdin.capi.ansi.Test.testRSA(provider, container, rand,
                        false, KeyFlags.NONE, rsaBits[i], KeySizes.range(16, 32, 8)
                    ); 
                }
                // для всех наборов параметров
                for (int i = 0; i < ecOIDs.length; i++)
                {
                    // выполнить тестирование
                    aladdin.capi.ansi.Test.testEC(provider, container, rand, true,  KeyFlags.NONE, ecOIDs[i]); 
                    aladdin.capi.ansi.Test.testEC(provider, container, rand, false, KeyFlags.NONE, ecOIDs[i]); 
                }
            }
        }
    }
	public static void testContainerCryptotoken(
        AuthenticationSelector selector, Provider provider, SecurityInfo info) throws Exception
    {
		// указать способ шифрования ключа
        int wrapFlags = 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_A | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_B | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_C | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_D | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_A | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_B | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_C | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_D; 
                
        // указать используемый контейнер
        try (aladdin.capi.Container container = (aladdin.capi.Container)
            selector.openObject(provider, info.scope, info.fullName(), "rw")) 
        { 
            container.deleteKeys(); 

            // указать генератор случайных данных
            try (IRand rand = container.provider().createRand(container, null))
            {
                aladdin.capi.gost.Test.testGOSTR3410_2001(
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_SIGNS_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, null, 0
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_A, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_B, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_C, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_D, wrapFlags
                ); 
                try {
                    // некоторые модели не поддерживают наборы
                    aladdin.capi.gost.Test.testGOSTR3410_2001(
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_SIGNS_B, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, null, 0
                    ); 
                    aladdin.capi.gost.Test.testGOSTR3410_2001(
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_SIGNS_C, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, null, 0
                    ); 
                }
                // при возникновении ошибки вывести описание ошибки
                catch (Throwable ex) { System.out.println(ex.toString()); System.in.read(); }
                try { 
                    // некоторые модели не поддерживают наборы
                    aladdin.capi.gost.Test.testGOSTR3410_2001(  
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_EXCHANGES_B, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                        aladdin.asn1.gost.OID.ENCRYPTS_A, wrapFlags
                    ); 
                    aladdin.capi.gost.Test.testGOSTR3410_2001(  
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_EXCHANGES_B, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                        aladdin.asn1.gost.OID.ENCRYPTS_B, wrapFlags
                    ); 
                    aladdin.capi.gost.Test.testGOSTR3410_2001(  
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_EXCHANGES_B, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                        aladdin.asn1.gost.OID.ENCRYPTS_C, wrapFlags
                    ); 
                    aladdin.capi.gost.Test.testGOSTR3410_2001(  
                        provider, container, rand, true, KeyFlags.NONE, 
                        aladdin.asn1.gost.OID.ECC_EXCHANGES_B, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                        aladdin.asn1.gost.OID.ENCRYPTS_D, wrapFlags
                    ); 
                }
                // при возникновении ошибки вывести описание ошибки
                catch (Throwable ex) { System.out.println(ex.toString()); System.in.read(); }
            }
        }
	}
	public static void testContainerCryptotoken2(
        AuthenticationSelector selector, Provider provider, SecurityInfo info) throws Exception
    {
		// указать способ шифрования ключа
        int wrapFlags = 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_A | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_B | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_C | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_D | 
            aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_Z | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_A | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_B | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_C | 
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_D |  
            aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_Z; 
                
		// указать используемый контейнер
        try (aladdin.capi.Container container = (aladdin.capi.Container)
            selector.openObject(provider, info.scope, info.fullName(), "rw")) 
		{ 
			container.deleteKeys(); int[] keySizes = new int[] {32}; 

            // указать генератор случайных данных
            try (IRand rand = container.provider().createRand(container, null))
            {
                aladdin.capi.gost.Test.testGOSTR3410_2001(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_SIGNS_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, null, 0
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_A, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_B, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_C, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2001(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO, 
                    aladdin.asn1.gost.OID.ENCRYPTS_D, wrapFlags
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2012_256(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_SIGNS_A, null, 0 
                ); 
                aladdin.capi.gost.Test.testGOSTR3410_2012_256(  
                    provider, container, rand, true, KeyFlags.NONE, 
                    aladdin.asn1.gost.OID.ECC_EXCHANGES_A, keySizes, wrapFlags
                ); 
            }
		}
	}
    public static void main(String[] parameters) throws Exception
    {
        AuthenticationSelector selector = new AuthenticationSelector("USER");

    	// указать провайдер
		try (Provider provider = new Provider("C:\\Windows\\system32\\jcPKCS11-2.dll")) 
		{
			// перечислить контейнеры
			SecurityInfo[] containersA = provider.enumerateAllObjects(Scope.ANY   ); 
			SecurityInfo[] containersS = provider.enumerateAllObjects(Scope.SYSTEM); 
			SecurityInfo[] containersU = provider.enumerateAllObjects(Scope.USER  ); 

			// найти смарт-карту (Laser)
			try (SecurityStore store = (SecurityStore)selector.openObject(
				provider, Scope.SYSTEM,  
                "ARDS JaCarta 0\\JaCarta Laser", "rw"
			)) { 
                // получить список алгоритмов
                long[] algIDs = ((Applet)store).algorithms(); 

                // указать способ аутентификации
                store.setAuthentication(new PasswordCredentials("USER", "1234567890"));
                
				// выполнить аутентификацию
				String storeName = store.fullName(); store.authenticate(); 
                
                // выполнить общие тесты
                // aladdin.capi.ansi.pkcs11.Test.testAlgorithms((Applet)store); 

                // идентификаторы наборов параметров
                String[] hashOIDs = new String[] { aladdin.asn1.gost.OID.HASHES_CRYPTOPRO }; 

                // идентификаторы наборов параметров
                String[] sboxOIDs = new String[] {
                    aladdin.asn1.gost.OID.ENCRYPTS_A, aladdin.asn1.gost.OID.ENCRYPTS_B, 
                    aladdin.asn1.gost.OID.ENCRYPTS_C, aladdin.asn1.gost.OID.ENCRYPTS_D    
                }; 
                // выполнить общие тесты
                // aladdin.capi.gost.pkcs11.Test.testAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

				// указать имя контейнера
				SecurityInfo info = new SecurityInfo(store.scope(), storeName, "CAPI-TEST"); 
				
                // выполнить тест
                testContainerLaser(selector, provider, info); 
			}
			// найти смарт-карту (CryptoToken)
			try (SecurityStore store = (SecurityStore)selector.openObject(
				provider, Scope.SYSTEM,  
                // "Aladdin R.D. JaCarta 0\\eToken GOST", "rw"
				"ARDS JaCarta 0\\eToken GOST", "rw"
			)) { 
                // получить список алгоритмов
                long[] algIDs = ((Applet)store).algorithms(); 

                // указать способ аутентификации
                store.setAuthentication(new PasswordCredentials("USER", "1234567890"));
                
				// выполнить аутентификацию
				String storeName = store.fullName(); store.authenticate(); 
                
                // выполнить общие тесты
                aladdin.capi.ansi.pkcs11.Test.testAlgorithms((Applet)store); 

                // идентификаторы наборов параметров
                String[] hashOIDs = new String[] { aladdin.asn1.gost.OID.HASHES_CRYPTOPRO }; 

                // идентификаторы наборов параметров
                String[] sboxOIDs = new String[] {
                    aladdin.asn1.gost.OID.ENCRYPTS_A, aladdin.asn1.gost.OID.ENCRYPTS_B, 
                    aladdin.asn1.gost.OID.ENCRYPTS_C, aladdin.asn1.gost.OID.ENCRYPTS_D 
                }; 
                // выполнить общие тесты
                aladdin.capi.gost.pkcs11.Test.testAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

				// указать имя контейнера
				SecurityInfo info = new SecurityInfo(store.scope(), storeName, "CAPI-TEST"); 
				
                // выполнить тест
                testContainerCryptotoken(selector, provider, info); 
			}
			// найти смарт-карту (CryptoToken2)
			try (SecurityStore store = (SecurityStore)selector.openObject(
				provider, Scope.SYSTEM, "Aladdin R.D. JaCarta 0\\JaCarta GOST 2.0", "rw"
			)) {
                // получить список алгоритмов
                long[] algIDs = ((Applet)store).algorithms(); 

                // указать способ аутентификации
                store.setAuthentication(new PasswordCredentials("USER", "1234567890"));
                
				// выполнить аутентификацию
				String storeName = store.fullName(); store.authenticate(); 

                // выполнить общие тесты
                aladdin.capi.ansi.pkcs11.Test.testAlgorithms((Applet)store); 

                // идентификаторы наборов параметров
                String[] hashOIDs = new String[] { aladdin.asn1.gost.OID.HASHES_CRYPTOPRO }; 

                // идентификаторы наборов параметров
                String[] sboxOIDs = new String[] {
                    aladdin.asn1.gost.OID.ENCRYPTS_A, aladdin.asn1.gost.OID.ENCRYPTS_B, 
                    aladdin.asn1.gost.OID.ENCRYPTS_C, aladdin.asn1.gost.OID.ENCRYPTS_D, 
                    aladdin.asn1.gost.OID.ENCRYPTS_TC26_Z
                }; 
                // выполнить общие тесты
                aladdin.capi.gost.pkcs11.Test.testAlgorithms((Applet)store, hashOIDs, sboxOIDs); 

				// указать имя контейнера
				SecurityInfo info = new SecurityInfo(store.scope(), storeName, "CAPI-TEST"); 

				// выполнить тест
				testContainerCryptotoken2(selector, provider, info); 
			}
		}
	}
}
