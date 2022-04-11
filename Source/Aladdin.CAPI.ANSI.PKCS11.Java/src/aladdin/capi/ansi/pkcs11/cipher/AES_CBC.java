package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES в режиме CBC
///////////////////////////////////////////////////////////////////////////////
public class AES_CBC extends aladdin.capi.pkcs11.BlockMode
{
	// размер ключей и параметры алгоритма
	private final int[] keySizes; private final CipherMode.CBC parameters;  

	// конструктор
	public AES_CBC(Applet applet, int[] keySizes, CipherMode.CBC parameters) throws IOException
	{
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.parameters = parameters; 
        
        // проверить размер блока
        if (parameters.blockSize() != 16) throw new UnsupportedOperationException(); 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_CBC); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // параметры алгоритма
        return new Mechanism(API.CKM_AES_CBC, parameters.iv()); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new AES(keySizes); } 
	// размер блока
	@Override public final int blockSize() { return 16; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
