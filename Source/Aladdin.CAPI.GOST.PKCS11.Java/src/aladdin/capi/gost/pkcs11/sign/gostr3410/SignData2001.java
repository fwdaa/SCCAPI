package aladdin.capi.gost.pkcs11.sign.gostr3410;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.gost.pkcs11.*;
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Подпись данных ГОСТ Р 34.10-2001
///////////////////////////////////////////////////////////////////////
public class SignData2001 extends aladdin.capi.gost.sign.gostr3410.SignData2001
{
    // используемый провайдер и апплет
    private final aladdin.capi.pkcs11.Provider provider; private final Applet applet; 
    
    // конструктор
    public SignData2001(aladdin.capi.pkcs11.Provider provider, 
        Applet applet, aladdin.capi.SignHash signAlgorithm) 
    { 
        // сохранить переданные параметры
        super(signAlgorithm); this.provider = RefObject.addRef(provider); 
        
        // сохранить переданные параметры
        this.applet = RefObject.addRef(applet); 
    } 
    // деструктор
    @Override protected void onClose() throws IOException 
    {
        // освободить выделенные ресурсы
        RefObject.release(applet); RefObject.release(provider); super.onClose();
    }
    // получить алгоритм хэширования
    @Override protected aladdin.capi.Hash createHashAlgorithm(String hashOID) throws IOException
    {
        // извлечь идентификатор таблицы подстановок
        ObjectIdentifier oid = new ObjectIdentifier(hashOID); 
        
        // указать параметры алгоритма
        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411, oid.encoded()); 
            
        // создать алгоритм хэширования
        aladdin.capi.Hash hashAlgorithm = Creator.createHash(provider, applet, mechanism); 
        
        // проверить поддержку алгоритма
        if (hashAlgorithm == null) throw new UnsupportedOperationException(); return hashAlgorithm; 
    }
}
