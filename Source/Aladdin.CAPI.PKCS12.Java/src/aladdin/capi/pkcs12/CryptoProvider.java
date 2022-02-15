package aladdin.capi.pkcs12; 
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import aladdin.capi.*; 
import aladdin.capi.software.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 
        
///////////////////////////////////////////////////////////////////////////
// Провайдер контейнеров PKCS12
///////////////////////////////////////////////////////////////////////////
public class CryptoProvider extends aladdin.capi.software.CryptoProvider
{
    // расширения файлов контейнеров
    private static final String[] EXTENSIONS = { "p12", "pfx" }; 
    
    // парольная защита
    private final IPBECultureFactory cultureFactory; 
    
	// конструктор
	public CryptoProvider(IPBECultureFactory cultureFactory, Factories factories) 
    { 
        // сохранить переданные параметры
        super(factories, "PKCS12", EXTENSIONS); 
        
        // сохранить парольную защиту
        this.cultureFactory = RefObject.addRef(cultureFactory); 
    }
	// конструктор
	public CryptoProvider(IPBECultureFactory cultureFactory, Iterable<Factory> factories) 
    { 
        // сохранить переданные параметры
        super(factories, "PKCS12", EXTENSIONS); 
        
        // сохранить парольную защиту
        this.cultureFactory = RefObject.addRef(cultureFactory); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(cultureFactory); super.onClose(); 
    }
	///////////////////////////////////////////////////////////////////////
    // Генерация случайных данных
	///////////////////////////////////////////////////////////////////////
        
    // фабрика генераторов случайных данных
    @Override public IRandFactory createRandFactory(SecurityObject scope, boolean strong) 
    { 
        // проверить наличие контекста выполнения
        if (cultureFactory instanceof IRandFactory) return RefObject.addRef(this); 

        // вызвать базовую функцию
        return super.createRandFactory(scope, strong); 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    { 
        // проверить наличие контекста выполнения
        if (cultureFactory instanceof IRandFactory) 
        {
            // создать генератор случайных данных
            return ((IRandFactory)cultureFactory).createRand(window); 
        }
        // вызвать базовую функцию
        return super.createRand(window); 
    } 
	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
	@Override public Container createContainer(IRand rand, 
        aladdin.capi.software.ContainerStore store, 
        ContainerStream stream, String password, String keyOID) throws IOException
	{
        // проверить наличие параметров
        if (password == null || cultureFactory == null) throw new IllegalStateException(); 
        
        // выполнить преобразование типа
        PBECulture culture = cultureFactory.getCulture(rand.window(), keyOID); 
        
        // проверить поддержку защиты
        if (culture == null) throw new UnsupportedOperationException(); 

        // создать пустое содержимое
        AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe();
        
        // получить параметры шифрования по паролю
        PBEParameters pbeParameters = culture.pbeParameters(); 
            
        // выделить память для salt-значения
        byte[] salt = new byte[pbeParameters.pbmSaltLength()]; 
                
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashAlgorithm = culture.hashAlgorithm(rand); 
                
        // сгенерировать salt-значение
        rand.generate(salt, 0, salt.length); 
                
        // создать пустой контейнер
        PFX pfx = Pfx.createAuthenticatedContainer(this, 
            authenticatedSafe, hashAlgorithm, 
            salt, pbeParameters.pbmIterations(), password
        );
        // создать объект контейнера
        try (Container container = new Container(
            cultureFactory, rand, store, stream, pfx))
        {
            // установить пароль контейнера
            container.setPassword(password); 
                    
            // вернуть объект контейнера
            container.addRef(); return container; 
        }
	}
	@Override public aladdin.capi.software.Container openContainer(
        aladdin.capi.software.ContainerStore store, 
        ContainerStream stream) throws IOException
	{
		// раскодировать данные
		PFX pfx = new PFX(Encodable.decode(stream.read()));
        
        // указать генератор случайных данных
        try (IRand rand = createRand(null))
        { 
            // вернуть объект контейнера
            return new Container(cultureFactory, rand, store, stream, pfx); 
        }
	}
}
