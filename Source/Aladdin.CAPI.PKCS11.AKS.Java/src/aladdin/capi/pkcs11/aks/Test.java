package aladdin.capi.pkcs11.aks;
import aladdin.capi.*; 
import aladdin.capi.auth.*; 
import aladdin.capi.pkcs11.*; 

public class Test
{
	public static void testContainerLaser(
        AuthenticationSelector selector, Provider provider, SecurityInfo info) throws Exception
    {
    	// указать размер ключей RSA в битах
        int[] rsaBits = new int[] { 512, 1024 }; 
        
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
                        true, KeyFlags.NONE, rsaBits[i], KeySizes.range(8, 24, 8)
                    ); 
                    aladdin.capi.ansi.Test.testRSA(provider, container, rand,
                        false, KeyFlags.NONE, rsaBits[i], KeySizes.range(8, 24, 8)
                    ); 
                }
            }
        }
    }
    public static void main(String[] parameters) throws Exception
    {
        AuthenticationSelector selector = new AuthenticationSelector("USER");

    	// указать провайдер
		try (Provider provider = new Provider("C:\\Windows\\system32\\etpkcs11.dll")) 
		{
			// перечислить контейнеры
			SecurityInfo[] containersA = provider.enumerateAllObjects(Scope.ANY   ); 
			SecurityInfo[] containersS = provider.enumerateAllObjects(Scope.SYSTEM); 
			SecurityInfo[] containersU = provider.enumerateAllObjects(Scope.USER  ); 

			// найти смарт-карту (Laser)
			try (SecurityStore store = (SecurityStore)selector.openObject(
				provider, Scope.SYSTEM, "AKS ifdh 0\\eToken", "rw"
			)) { 
                // получить список алгоритмов
                long[] algIDs = ((Applet)store).algorithms(); 

                // указать способ аутентификации
                store.setAuthentication(new PasswordCredentials("USER", "Qq1234567890"));
                
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
