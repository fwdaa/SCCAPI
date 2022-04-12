package aladdin.capi.pkcs11;
import aladdin.capi.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Режим блочного алгоритма шифрования
///////////////////////////////////////////////////////////////////////////////
public abstract class BlockMode extends Cipher
{
    // способ дополнения
    private PaddingMode padding; 
    
	// конструктор
	protected BlockMode(Applet applet, PaddingMode padding)
    { 
		// сохранить переданные параметры
		super(applet); this.padding = padding; 
    } 
    // алгоритм зашифрования данных
	@Override public Transform createEncryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException
	{
        // указать режим дополнения
        if (this.padding != PaddingMode.ANY) padding = this.padding; 
        
        // сохранить способ дополнения
        PaddingMode oldPadding = this.padding; this.padding = padding; 
        
        // получить режим зашифрования 
        try (Transform encryption = createEncryption(key))
        {
            // указать требуемое дополнение
            return getPadding().createEncryption(encryption, mode()); 
        }
        // восстановить способ дополнения
        finally { this.padding = oldPadding; }
    }
	// алгоритм расшифрования данных
	@Override public Transform createDecryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException 
	{
        // указать режим дополнения
        if (this.padding != PaddingMode.ANY) padding = this.padding; 
        
        // сохранить способ дополнения
        PaddingMode oldPadding = this.padding; this.padding = padding; 
        
        // получить режим расшифрования 
        try (Transform decryption = createDecryption(key))
        {
            // указать требуемое дополнение
            return getPadding().createDecryption(decryption, mode()); 
        }
        // восстановить способ дополнения
        finally { this.padding = oldPadding; }
    }
	// алгоритм зашифрования данных
    @Override protected Transform createEncryption(ISecretKey key) 
	{
		// создать алгоритм зашифрования данных
		return new Encryption(this, padding, key); 
	}
	// алгоритм расшифрования данных
    @Override protected Transform createDecryption(ISecretKey key) 
	{
		// создать алгоритм расшифрования данных
		return new Decryption(this, padding, key); 
	}
    // указать режим дополнения
	protected BlockPadding getPadding() 
	{
        // вернуть отсутствие дополнения
        if (padding == PaddingMode.NONE) return new aladdin.capi.pad.None();
        
        // вернуть дополнение нулями
        if (padding == PaddingMode.ZERO) return new aladdin.capi.pad.Zero();

        // вернуть дополнение PKCS
        if (padding == PaddingMode.PKCS5) return new aladdin.capi.pad.PKCS5(); 

        // вернуть дополнение ISO
        if (padding == PaddingMode.ISO9797) return new aladdin.capi.pad.ISO9797(); 

        // для режима дополнения CTS
        if (padding == PaddingMode.CTS) return new aladdin.capi.pad.CTS(); 

        // при ошибке выбросить исключение
        throw new UnsupportedOperationException();
    }
};
