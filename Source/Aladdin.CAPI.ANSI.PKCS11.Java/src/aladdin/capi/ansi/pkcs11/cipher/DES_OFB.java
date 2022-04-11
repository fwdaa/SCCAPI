package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES в режиме OFB
///////////////////////////////////////////////////////////////////////////////
public class DES_OFB extends aladdin.capi.pkcs11.BlockMode
{
	// идентификатор алгоритма и параметры алгоритма
	private final long algID; private final CipherMode.OFB parameters;  

	// конструктор
	public DES_OFB(Applet applet, CipherMode.OFB parameters)
	{
		// указать параметры алгоритма
		super(applet, PaddingMode.NONE); this.parameters = parameters; 
        
        // в зависимости от размера блока
        switch (parameters.blockSize()) 
        {
        // указать идентификатор алгоритма
        case 8: algID = API.CKM_DES_OFB64; break;
        case 1: algID = API.CKM_DES_OFB8;  break;
            
        // при ошибке выбросить исключение
        default: throw new UnsupportedOperationException();
        }
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // параметры алгоритма
        return new Mechanism(algID, parameters.iv()); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return DES.INSTANCE; } 
	// размер блока
	@Override public final int blockSize() { return 8; } 
    
	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
