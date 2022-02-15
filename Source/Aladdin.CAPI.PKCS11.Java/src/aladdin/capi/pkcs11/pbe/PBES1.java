package aladdin.capi.pkcs11.pbe;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PBES1
///////////////////////////////////////////////////////////////////////////
public abstract class PBES1 extends aladdin.capi.Cipher
{
    // физическое устройство и идентификатор алгоритма
    private final Applet applet; private final long algID; 
    
    // алгоритм наследования ключа
    private final aladdin.capi.KeyDerive keyDerive; private final SecretKeyFactory keyFactory; 
    
	// конструктор
	protected PBES1(Applet applet, long algID, byte[] salt, int iterations, SecretKeyFactory keyFactory)
    { 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); this.algID = algID; 
        
        // создать алгоритм наследования ключа
        this.keyDerive = new PBKDF1(this, salt, iterations); this.keyFactory = keyFactory; 
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
    
    // размер блока алгоритма
    @Override public int blockSize() { return ivLength(); }

	// создать алгоритм шифрования
	protected abstract aladdin.capi.Cipher createCipher(byte[] iv) throws IOException; 
	// размер ключа и синхропосылки
	protected abstract int keyLength();  
	// размер синхропосылки
    protected abstract int ivLength();
    
	// алгоритм зашифрования данных
	@Override 
    protected Transform createEncryption(ISecretKey password) throws IOException
	{
        // выделить память для синхропосылки
        byte[] iv = new byte[ivLength()]; 
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = keyDerive.deriveKey(password, iv, keyFactory, keyLength())) 
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
        byte[] iv = new byte[ivLength()];  
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = keyDerive.deriveKey(password, iv, keyFactory, keyLength())) 
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
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(keyFactory, keyLength(), false); 
    } 
}
