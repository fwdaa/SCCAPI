package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES в режиме CBC
///////////////////////////////////////////////////////////////////////////////
public class DES_CBC extends aladdin.capi.pkcs11.BlockMode
{
	// параметры алгоритма
	private final CipherMode.CBC parameters;  

	// конструктор
	public DES_CBC(Applet applet, CipherMode.CBC parameters)
	{
		// указать параметры алгоритма
		super(applet, PaddingMode.NONE); this.parameters = parameters; 
        
        // проверить размер блока
        if (parameters.blockSize() != 8) throw new UnsupportedOperationException(); 
	} 
	// параметры алгоритма
    @Override public Mechanism getParameters(Session sesssion)
	{
        // параметры алгоритма
        return new Mechanism(API.CKM_DES_CBC, parameters.iv()); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return DES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return new int[] {8}; }
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
