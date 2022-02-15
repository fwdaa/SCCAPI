package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES в режиме ECB
///////////////////////////////////////////////////////////////////////////////
public class TDES_ECB extends aladdin.capi.pkcs11.BlockMode
{
    // размер ключей
    private final int[] keySizes;
    
	// конструктор
	public TDES_ECB(Applet applet, int[] keySizes) 
    { 
        // сохранить переданные параметры
        super(applet, PaddingMode.NONE); this.keySizes = keySizes; 
    }
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_DES3_ECB); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return TDES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
} 
