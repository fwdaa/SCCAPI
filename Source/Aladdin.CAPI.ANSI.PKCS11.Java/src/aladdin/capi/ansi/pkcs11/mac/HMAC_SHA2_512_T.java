package aladdin.capi.ansi.pkcs11.mac;
import aladdin.*;
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA2-512/t
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA2_512_T extends HMAC
{
    // число битов и алгоритм хэширования
    private final int bits; private final aladdin.capi.Hash hashAlgorithm;
    
    // конструктор
    public HMAC_SHA2_512_T(Applet applet, int bits) throws IOException
    {      
        // сохранить переданные параметры
        this(applet, bits, (bits + 7) / 8); 
    } 
    // конструктор
    public HMAC_SHA2_512_T(Applet applet, int bits, int macSize) throws IOException
    {             
        // сохранить переданные параметры
        super(applet, API.CKM_SHA512_T_HMAC, API.CKM_SHA512_T, macSize); this.bits = bits;

        // указать параметры алгоритма
        Mechanism parameters = new Mechanism(API.CKM_SHA512_T, bits); 

        // создать алгоритм хэширования
        hashAlgorithm = Creator.createHash(applet.provider(), applet, parameters);
        
        // проверить поддержку алгоритма
        if (hashAlgorithm == null) throw new UnsupportedOperationException();
    }        
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); super.onClose();
    }
    // получить алгоритм хэширования
    @Override protected aladdin.capi.Hash getHashAlgorithm() { return hashAlgorithm; } 
    
    // параметры алгоритма
    @Override protected Mechanism getParameters(Session session)
    { 
	    // выделить память для параметров
	    return new Mechanism(API.CKM_SHA512_T_HMAC, bits); 
    }
}
