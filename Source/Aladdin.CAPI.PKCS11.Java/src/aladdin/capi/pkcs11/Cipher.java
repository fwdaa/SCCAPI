package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public abstract class Cipher extends aladdin.capi.Cipher 
{
    // физическое устройство 
    private final Applet applet;
    
	// конструктор
	protected Cipher(Applet applet)
    { 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); 
    } 
	// деструктор
    @Override protected void onClose() throws IOException   
    { 
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
    } 
	// используемое устройство 
	public final Applet applet() { return applet; } 
	// параметры алгоритма
	public abstract Mechanism getParameters(Session sesssion); 
    
    // атрибуты ключа
    public Attribute[] getKeyAttributes(int keySize)
    {
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(keyFactory(), keySize, true); 
    }
	// алгоритм зашифрования данных
    @Override
	protected Transform createEncryption(ISecretKey key) throws IOException
	{
		// создать алгоритм зашифрования данных
		return new Encryption(this, PaddingMode.NONE, key); 
	}
	// алгоритм расшифрования данных
    @Override
	protected Transform createDecryption(ISecretKey key) throws IOException
	{
		// создать алгоритм расшифрования данных
		return new Decryption(this, PaddingMode.NONE, key); 
	}
    // создать алгоритм шифрования ключа
    @Override public aladdin.capi.KeyWrap createKeyWrap(PaddingMode padding)
    {
        // создать алгоритм шифрования ключа
        return new KeyWrap(this); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа на основе алгоритма шифрования
    ///////////////////////////////////////////////////////////////////////////
    private static class KeyWrap extends aladdin.capi.pkcs11.KeyWrap
    {
        // используемый алгоритм шифрования
        private final Cipher cipher; 

        // конструктор
        public KeyWrap(Cipher cipher)
        {	
            // сохранить переданные параметры
            super(cipher.applet()); this.cipher = RefObject.addRef(cipher); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException   
        { 
            // освободить выделенные ресурсы
            RefObject.release(cipher); super.onClose(); 
        }
        // параметры алгоритма
        @Override protected Mechanism getParameters(Session sesssion, IRand rand)
        {
            // параметры алгоритма
            return cipher.getParameters(sesssion); 
        }
        // атрибуты ключа
        @Override protected Attribute[] getKeyAttributes(int keySize)
        {
            // атрибуты ключа
            return cipher.getKeyAttributes(keySize); 
        }
        // тип ключа
        @Override public final SecretKeyFactory keyFactory() { return cipher.keyFactory(); } 
        // размер ключей
        @Override public final int[] keySizes() { return cipher.keySizes(); } 
    }
};
