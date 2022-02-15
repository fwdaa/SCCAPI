package aladdin.capi.gost.pkcs11.keyx.gostr3410;
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.gost.gostr3410.*; 
import aladdin.capi.gost.pkcs11.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа RFC 4357 (2001)
///////////////////////////////////////////////////////////////////////////////
public class KeyAgreement2001 extends aladdin.capi.pkcs11.KeyAgreement
{
    // указать способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // конструктор
	public KeyAgreement2001(Applet applet, long kdf) 
    
        // сохранить переданные параметры
        { super(applet); this.kdf = kdf; } private final long kdf;
    
    // создать программный алгоритм
    @Override protected aladdin.capi.KeyAgreement createSoftwareAlgorithm(
        IParameters parameters) throws IOException
    {
        // создать программный алгоритм
        if (kdf == API.CKD_NULL) return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2001(); 
        
        // при наличии диверсификации ключа
        if (kdf == API.CKD_CPDIVERSIFY_KDF)
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.INamedParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.INamedParameters)parameters; 
            
            // определить идентификатор таблицы подстановок
            String sboxOID = gostParameters.sboxOID(); 
            
            // создать алгоритм диверсификации
            try (aladdin.capi.KeyDerive keyDerive = 
                Creator.createDeriveRFC4357(applet().provider(), applet(), sboxOID))
            {
                // проверить поддержку алгоритма
                if (keyDerive == null) throw new UnsupportedOperationException(); 
                
                // создать программный алгоритм наследования ключа
                return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2001(keyDerive); 
            }
        }
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
	// получить параметры
    @Override
	protected Mechanism getParameters(Session session, 
		IPublicKey publicKey, byte[] random, int keySize)
    {
        // преобразовать тип параметров
        IECParameters gostParameters = (IECParameters)publicKey.parameters(); 
        
        // преобразовать тип ключа
        IECPublicKey gostPublicKey = (IECPublicKey)publicKey;

        // определить размер открытого ключа в байтах
        int cbPublicKey = (gostParameters.getOrder().bitLength() + 7) / 8 * 2; 
        
        // выделить буфер требуемого размера
        byte[] publicData = new byte[cbPublicKey]; 

        // получить координаты точки
        byte[] qx = Convert.fromBigInteger(gostPublicKey.getW().getAffineX(), ENDIAN, cbPublicKey / 2);
        byte[] qy = Convert.fromBigInteger(gostPublicKey.getW().getAffineY(), ENDIAN, cbPublicKey / 2);
        
        // скопировать координаты точки
        System.arraycopy(qx, 0, publicData,               0, cbPublicKey / 2);
        System.arraycopy(qy, 0, publicData, cbPublicKey / 2, cbPublicKey / 2);
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_GOSTR3410_DERIVE, 
            new CK_GOSTR3410_DERIVE_PARAMS(kdf, publicData, random) 
        ); 
    }
	// сгенерировать случайные данные
    @Override
	public byte[] generate(IParameters parameters, IRand rand) throws IOException
	{
		// сгенерировать случайные данные
		byte[] random = new byte[8]; rand.generate(random, 0, random.length); return random; 
	}
} 

