package aladdin.capi.gost.pkcs11.wrap;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.derive.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.gost.keys.*; 
import aladdin.capi.gost.pkcs11.*;
import aladdin.pkcs11.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа с выработкой имитовставки
///////////////////////////////////////////////////////////////////////////////
public class RFC4357 extends aladdin.capi.pkcs11.KeyWrap
{
    // указать способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм диверсификации ключа
    private final aladdin.capi.KeyDerive keyDerive; 
	// параметры ключа и случайные данные
	private final byte[] encodedOID; private final byte[] ukm; 

	// конструктор
	public RFC4357(Applet applet, long kdf, String sboxOID, byte[] ukm) throws IOException
	{
        // сохранить переданные параметры
		super(applet); if (kdf == API.CKD_NULL) keyDerive = new NOKDF(ENDIAN);
        
        else if (kdf == API.CKD_CPDIVERSIFY_KDF)
        {
            // указать алгоритм наследования ключа
            keyDerive = Creator.createDeriveRFC4357(applet.provider(), applet, sboxOID); 
            
            // при ошибке выбросить исключение
            if (keyDerive == null) throw new UnsupportedOperationException(); 
        }
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
        
		// закодировать параметры алгоритма
		encodedOID = new ObjectIdentifier(sboxOID).encoded(); this.ukm = ukm; 
	}
	// конструктор
	public RFC4357(Applet applet, String sboxOID, byte[] ukm) 
	{
        // сохранить переданные параметры
		super(applet); this.keyDerive = new NOKDF(ENDIAN); 
        
		// закодировать параметры алгоритма
		encodedOID = new ObjectIdentifier(sboxOID).encoded(); this.ukm = ukm; 
	}
    // деструктор
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(keyDerive); super.onClose();
    }
	// параметры алгоритма
    @Override
	protected Mechanism getParameters(Session session, IRand rand)
	{ 
        // параметры алгоритма
		return new Mechanism(API.CKM_GOST28147_KEY_WRAP, ukm); 
	}
	// атрибуты ключа
    @Override public Attribute[] getKeyAttributes(int keySize)
	{ 
		// выделить память для атрибутов
		return new Attribute[] { 

            // указать требуемые атрибуты
            new Attribute(API.CKA_KEY_TYPE, API.CKK_GOST28147), 

            // указать требуемые атрибуты
            new Attribute(API.CKA_GOST28147_PARAMS, encodedOID)
        }; 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return GOST.INSTANCE; } 
    
    @Override
	public byte[] wrap(IRand rand, ISecretKey KEK, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // выполнить диверсификацию ключа
        try (ISecretKey key = keyDerive.deriveKey(KEK, ukm, keyFactory(), 32))
        {
            // вызвать базовую функцию
            return super.wrap(rand, key, CEK); 
        }
    }
    @Override
	public ISecretKey unwrap(ISecretKey KEK, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
    {
        // выполнить диверсификацию ключа
        try (ISecretKey key = keyDerive.deriveKey(KEK, ukm, keyFactory(), 32))
        {
            // вызвать базовую функцию
            return super.unwrap(key, wrappedCEK, keyFactory); 
        }
    }
}
