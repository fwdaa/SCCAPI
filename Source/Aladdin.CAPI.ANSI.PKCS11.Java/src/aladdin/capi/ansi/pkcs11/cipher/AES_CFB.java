package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES в режиме CFB
///////////////////////////////////////////////////////////////////////////////
public class AES_CFB extends aladdin.capi.pkcs11.BlockMode
{
	// идентификатор алгоритма и размер ключей
	private final long algID; private final int[] keySizes; 
    // параметры алгоритма
    private final CipherMode.CFB parameters;  

	// конструктор
	public AES_CFB(Applet applet, int[] keySizes, CipherMode.CFB parameters) throws IOException
	{
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.parameters = parameters; 
        
        // в зависимости от размера блока
        switch (parameters.blockSize()) 
        {
        // указать идентификатор алгоритма
        case 16: algID = API.CKM_AES_CFB128; break;
        case  8: algID = API.CKM_AES_CFB64 ; break;
        case  1: algID = API.CKM_AES_CFB8  ; break;
            
        // при ошибке выбросить исключение
        default: throw new UnsupportedOperationException();
        }
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(algID); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
    {
        // параметры алгоритма
        return new Mechanism(algID, parameters.iv()); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new AES(keySizes); } 
	// размер блока
	@Override public final int blockSize() { return 16; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
