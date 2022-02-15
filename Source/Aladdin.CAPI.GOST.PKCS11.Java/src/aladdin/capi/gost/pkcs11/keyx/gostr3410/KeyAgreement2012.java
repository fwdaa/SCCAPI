package aladdin.capi.gost.pkcs11.keyx.gostr3410;
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.gost.gostr3410.*; 
import aladdin.capi.gost.pkcs11.*;
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа RFC 4357 (2012)
///////////////////////////////////////////////////////////////////////////////
public class KeyAgreement2012 extends aladdin.capi.pkcs11.KeyAgreement
{
    // указать способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // способ диверсификации
    private final long kdf; 
    
    // конструктор
	public KeyAgreement2012(Applet applet, long kdf)
	{ 
		// сохранить переданные параметры
		super(applet); this.kdf = kdf;
    } 
    // размер случайных данных
    protected int randomSize() { return 8; }
    
    // создать программный алгоритм
    @Override protected aladdin.capi.KeyAgreement createSoftwareAlgorithm(
        IParameters parameters) throws IOException
    {
        // создать программный алгоритм
        if (kdf == API.CKD_NULL) return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2012(); 
        
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
                return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2012(keyDerive); 
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
        IECPublicKey gostPublicKey = (IECPublicKey)publicKey; int offset = 0; 

        // определить размер открытого ключа в байтах
        int cbPublicKey = (gostParameters.getOrder().bitLength() + 7) / 8 * 2; 
        
        // получить координаты точки
        byte[] qx = Convert.fromBigInteger(gostPublicKey.getW().getAffineX(), ENDIAN, cbPublicKey / 2);
        byte[] qy = Convert.fromBigInteger(gostPublicKey.getW().getAffineY(), ENDIAN, cbPublicKey / 2);
        
        // выделить буфер требуемого размера
        byte[] buffer = new byte[4 + 4 + cbPublicKey + 4 + random.length]; 
        
        // указать тип диверсификации
        Convert.fromInt32((int)kdf, ENDIAN, buffer, offset); offset += 4; 
        
        // указать размер открытого ключа
        Convert.fromInt32(cbPublicKey, ENDIAN, buffer, offset); offset += 4;
        
        // скопировать координаты точки
        System.arraycopy(qx, 0, buffer, offset, cbPublicKey / 2); offset += cbPublicKey / 2; 
        System.arraycopy(qy, 0, buffer, offset, cbPublicKey / 2); offset += cbPublicKey / 2; 
        
        // указать размер случайных данных
        Convert.fromInt32(random.length, ENDIAN, buffer, offset); offset += 4; 
        
        // скопировать случайные данные
        System.arraycopy(random, 0, buffer, offset, random.length); offset += random.length; 
        
        // вернуть параметры механизма
        return new Mechanism(API.CKM_GOSTR3410_2012_DERIVE, buffer); 
    }
	// сгенерировать случайные данные
    @Override
	public byte[] generate(IParameters parameters, IRand rand) throws IOException
	{
		// выделить память для случайных данных
		byte[] random = new byte[randomSize()]; 
        
		// сгенерировать случайные данные
        rand.generate(random, 0, random.length); return random; 
	}
}
