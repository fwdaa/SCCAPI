package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES в режиме CBC
///////////////////////////////////////////////////////////////////////////////
public class TDES_CBC extends aladdin.capi.pkcs11.BlockMode
{
    // размер ключей и параметры алгоритма
    private final int[] keySizes; private final CipherMode.CBC parameters;

	// конструктор
	public TDES_CBC(Applet applet, int[] keySizes, CipherMode.CBC parameters)
	{
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); 
        
        // проверить размер блока
        if (parameters.blockSize() != 8) throw new UnsupportedOperationException(); 
        
        // сохранить переданные параметры
        this.keySizes = keySizes; this.parameters = parameters; 
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // параметры алгоритма
        return new Mechanism(API.CKM_DES3_CBC, parameters.iv()); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return TDES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
