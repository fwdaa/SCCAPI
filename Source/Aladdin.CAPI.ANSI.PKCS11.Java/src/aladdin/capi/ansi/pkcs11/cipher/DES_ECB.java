package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES в режиме ECB
///////////////////////////////////////////////////////////////////////////////
public class DES_ECB extends aladdin.capi.pkcs11.BlockMode
{
	// конструктор
	public DES_ECB(Applet applet) { super(applet, PaddingMode.NONE); }

	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_DES_ECB); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return DES.INSTANCE; } 
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
} 
