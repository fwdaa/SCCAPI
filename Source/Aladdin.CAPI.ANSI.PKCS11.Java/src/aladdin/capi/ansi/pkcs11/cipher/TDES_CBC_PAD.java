package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES в режиме CBC с дополнением PKCS5
///////////////////////////////////////////////////////////////////////////////
public class TDES_CBC_PAD extends aladdin.capi.pkcs11.BlockMode
{
    // размер ключей и параметры алгоритма
    private final int[] keySizes; private final CipherMode.CBC parameters;

	// конструктор
	public TDES_CBC_PAD(Applet applet, int[] keySizes, CipherMode.CBC parameters)
	{
		// сохранить переданные параметры
		super(applet, PaddingMode.PKCS5); 
        
        // проверить размер блока
        if (parameters.blockSize() != 8) throw new UnsupportedOperationException(); 
        
        // сохранить переданные параметры
        this.keySizes = keySizes; this.parameters = parameters; 
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // параметры алгоритма
        return new Mechanism(API.CKM_DES3_CBC_PAD, parameters.iv()); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new TDES(keySizes); } 
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
