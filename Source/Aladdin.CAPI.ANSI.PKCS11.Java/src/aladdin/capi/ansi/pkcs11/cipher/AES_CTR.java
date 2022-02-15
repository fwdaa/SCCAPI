package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES в режиме CTR
///////////////////////////////////////////////////////////////////////////////
public class AES_CTR extends aladdin.capi.pkcs11.BlockMode
{
	// размер ключей и число битов счетчика
	private final int[] keySizes; private final int counterBits; 
    // параметры алгоритма
    private final CipherMode.CTR parameters;  

	// конструктор
	public AES_CTR(Applet applet, int[] keySizes, byte[] iv, int counterBits) throws IOException
	{
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.counterBits = counterBits; 
        
		// сохранить переданные параметры
        this.parameters = new CipherMode.CTR(iv, 16); 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_CTR); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // указать параметры алгоритма
        CK_AES_CTR_PARAMS aesParameters = new CK_AES_CTR_PARAMS(
            parameters.iv(), counterBits
        ); 
		// параметры алгоритма
		return new Mechanism(API.CKM_AES_CTR, aesParameters); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return AES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
	// размер блока
	@Override public final int blockSize() { return 16; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
