package aladdin.capi.pkcs11.athena;
import aladdin.capi.*; 
import aladdin.capi.auth.*; 
import aladdin.capi.pkcs11.*; 

public class Test
{
	public static void testContainerLaser(
        AuthenticationSelector selector, Provider provider, SecurityInfo info) throws Exception
    {
    	// указать размер ключей RSA в битах
        int[] rsaBits = new int[] { 512, 1024, 1536, 2048 }; 
        
    	// указать идентификаторы параметров
		String[] ecOIDs = new String[] { 
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V1,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V2,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME192V3,
            aladdin.asn1.ansi.OID.X962_CURVES_PRIME256V1,

            aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP160K1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP160R1, 
			aladdin.asn1.ansi.OID.CERTICOM_CURVES_SECP160R2, 
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
                        true, KeyFlags.NONE, rsaBits[i], KeySizes.range(8, 32, 8)
                    ); 
                    aladdin.capi.ansi.Test.testRSA(provider, container, rand,
                        false, KeyFlags.NONE, rsaBits[i], KeySizes.range(8, 32, 8)
                    ); 
                }
                // для всех наборов параметров
                for (int i = 0; i < ecOIDs.length; i++)
                try {
                    // выполнить тестирование
                    aladdin.capi.ansi.Test.testEC(provider, container, rand, true,  KeyFlags.NONE, ecOIDs[i]); 
                    aladdin.capi.ansi.Test.testEC(provider, container, rand, false, KeyFlags.NONE, ecOIDs[i]); 
                }
                // при возникновении ошибки вывести описание ошибки
                catch (Throwable ex) { System.out.println(ex.toString()); }
            }
        }
    }
    public static void main(String[] parameters) throws Exception
    {
        AuthenticationSelector selector = new AuthenticationSelector("USER");

    	// указать провайдер
		try (Provider provider = new Provider("C:\\Windows\\system32\\asepkcs.dll")) 
		{
			// перечислить контейнеры
			SecurityInfo[] containersA = provider.enumerateAllObjects(Scope.ANY   ); 
			SecurityInfo[] containersS = provider.enumerateAllObjects(Scope.SYSTEM); 
			SecurityInfo[] containersU = provider.enumerateAllObjects(Scope.USER  ); 

			// найти смарт-карту (Laser)
			try (SecurityStore store = (SecurityStore)selector.openObject(
				provider, Scope.SYSTEM,  
                "ARDS JaCarta 0\\CNS", "rw"
                // "ARDS JaCarta 0\\JaCarta Laser", "rw"
			)) { 
                // получить список алгоритмов
                long[] algIDs = ((Applet)store).algorithms(); 

                // указать способ аутентификации
                store.setAuthentication(new PasswordCredentials("USER", "1234567890"));
                
				// выполнить аутентификацию
				String storeName = store.fullName(); store.authenticate(); 
                
                // выполнить общие тесты
                aladdin.capi.ansi.pkcs11.Test.testAlgorithms((Applet)store); 

				// указать имя контейнера
				SecurityInfo info = new SecurityInfo(store.scope(), storeName, "CAPI-TEST"); 
				
                // выполнить тест
                testContainerLaser(selector, provider, info); 
			}
		}
	}
}
