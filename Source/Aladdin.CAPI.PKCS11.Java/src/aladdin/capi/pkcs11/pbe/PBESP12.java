package aladdin.capi.pkcs11.pbe;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PKCS12
///////////////////////////////////////////////////////////////////////////
public abstract class PBESP12 extends aladdin.capi.Cipher
{
    // физическое устройство и идентификатор алгоритма
    private final Applet applet; private final long algID; 
    // алгоритм наследования ключа
    private final aladdin.capi.KeyDerive keyDerive; 
    
	// конструктор
	protected PBESP12(Applet applet, long algID, byte[] salt, int iterations)
    { 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); this.algID = algID; 
        
        // создать алгоритм наследования ключа
        this.keyDerive = new PBKDFP12(this, salt, iterations); 
    }
    // деструктор
    @Override protected void onClose() throws IOException   
    { 
        // освободить выделенные ресурсы
        keyDerive.close(); RefObject.release(applet); super.onClose();
    } 
	// используемое устройство 
	public final Applet applet() { return applet; } 
    
    // идентификатор алгоритма
    public final long algID() { return algID; }
    
	// создать алгоритм шифрования
	protected abstract aladdin.capi.Cipher createCipher(byte[] iv) throws IOException; 
	// фабрика ключа
	protected abstract SecretKeyFactory deriveKeyFactory();  
    
	// алгоритм зашифрования данных
	@Override 
    protected Transform createEncryption(ISecretKey password) throws IOException
	{
        // выделить память для синхропосылки
        byte[] iv = new byte[8]; SecretKeyFactory deriveKeyFactory = deriveKeyFactory(); 
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = keyDerive.deriveKey(
            password, iv, deriveKeyFactory, deriveKeyFactory.keySizes()[0])) 
        {
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(iv))
            {
                // вернуть преобразование зашифрования
                return cipher.createEncryption(key, PaddingMode.PKCS5); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); }
	}
	// алгоритм расшифрования данных
	@Override 
    protected Transform createDecryption(ISecretKey password) throws IOException
	{
        // выделить память для синхропосылки
        byte[] iv = new byte[8]; SecretKeyFactory deriveKeyFactory = deriveKeyFactory();  
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = keyDerive.deriveKey(
            password, iv, deriveKeyFactory, deriveKeyFactory.keySizes()[0])) 
        {
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(iv))
            {
                // вернуть преобразование расшифрования
                return cipher.createDecryption(key, PaddingMode.PKCS5); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); }
	}
	// атрибуты ключа
	public Attribute[] getKeyAttributes() 
    { 
        // указать фабрику ключа
        SecretKeyFactory deriveKeyFactory = deriveKeyFactory();  
        
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(
            deriveKeyFactory, deriveKeyFactory.keySizes()[0], false
        ); 
    } 
}
