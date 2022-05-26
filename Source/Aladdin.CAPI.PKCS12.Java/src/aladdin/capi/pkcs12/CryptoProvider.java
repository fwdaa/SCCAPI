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
    
    // провайдер только для чтения
    public static CryptoProvider readonly(
        Iterable<Factory> factories, IRand rand) throws IOException
    {
        // вернуть провайдер
        return new CryptoProvider(factories, rand); 
    }
    // провайдер только для чтения
    public static CryptoProvider readonly(Iterable<Factory> factories)
    {
        // указать генератор случайных данных
        try (IRand rand = new Rand(null))
        { 
            // вернуть провайдер только для чтения
            return readonly(factories, rand); 
        }
        // обработать неожидаемое исключение
        catch (IOException e) { throw new RuntimeException(e); }
    }
	// конструктор
	public CryptoProvider(ExecutionContext executionContext) 
    { 
        // сохранить переданные параметры
        super(executionContext, "PKCS12", EXTENSIONS); 
        
        // сохранить парольную защиту
        this.cultureFactory = executionContext; 
    }
	// конструктор
	public CryptoProvider(Iterable<Factory> factories, IRandFactory randFactory) 
    { 
        // сохранить переданные параметры
        super(factories, randFactory, "PKCS12", EXTENSIONS); this.cultureFactory = null; 
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
        ContainerStream stream, String password, Object parameter) throws IOException
	{
        // проверить наличие параметров
        if (password == null) throw new IllegalStateException(); 
        
        // при указании идентификатора ключа
        PBECulture culture = null; if (parameter instanceof String)
        {
            // проверить наличие параметров
            if (cultureFactory == null) throw new IllegalStateException(); 
            
            // получить парольную защиту
            culture = cultureFactory.getPBECulture(rand.window(), (String)parameter); 
        }
        // выполнить преобразование типа
        else culture = (PBECulture)parameter; 
            
        // проверить поддержку защиты
        if (culture == null) throw new UnsupportedOperationException(); 

        // создать пустое содержимое
        AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe();
        
        // получить параметры шифрования по паролю
        PBEParameters pbeParameters = culture.pbeParameters(); 
            
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashAlgorithm = culture.hashAlgorithm(rand); 

        // выделить память для salt-значения 
        byte[] salt = new byte[pbeParameters.pbmSaltLength()]; 
        
        // сгенерировать salt-значение
        rand.generate(salt, 0, salt.length); 
        
        // создать пустой контейнер
        PFX pfx = Pfx.createAuthenticatedContainer(this, 
            authenticatedSafe, hashAlgorithm, 
            salt, pbeParameters.pbmIterations(), password
        );
        // создать объект контейнера
        try (Container container = new Container(
            culture, rand, store, stream, pfx))
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
