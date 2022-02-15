package aladdin.capi.ansi.pkcs11.mac;
import aladdin.*;
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC
///////////////////////////////////////////////////////////////////////////////
public class HMAC_GENERAL extends aladdin.capi.pkcs11.mac.HMAC
{
    // идентификатор HMAC-алгоритма и алгоритм хэширования
    private final long hmacID; private final aladdin.capi.Hash hashAlgorithm;

    // конструктор
    public HMAC_GENERAL(Applet applet, long hmacID, long hashID, int macSize) throws IOException 
    {        
        // сохранить переданные параметры
        this(applet, hmacID, hashID, API.CKK_GENERIC_SECRET, macSize); 
    }
    // конструктор
    public HMAC_GENERAL(Applet applet, long hmacID, long hashID, long keyType, int macSize) throws IOException
    {        
        // сохранить переданные параметры
        super(applet, keyType, macSize); this.hmacID = hmacID; 

        // указать параметры алгоритма
        Mechanism parameters = new Mechanism(hashID); 

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
	    return new Mechanism(hmacID, macSize()); 
    }
}
