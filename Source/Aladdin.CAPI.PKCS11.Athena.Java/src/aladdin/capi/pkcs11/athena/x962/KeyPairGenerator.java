package aladdin.capi.pkcs11.athena.x962;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей EC/ECDSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.ansi.pkcs11.x962.KeyPairGenerator
{
    // конструктор
    public KeyPairGenerator(Applet applet, SecurityObject scope, 

        // сохранить переданные параметры
        IRand rand, aladdin.capi.ansi.x962.Parameters parameters) throws IOException
    {
        // сохранить переданные параметры
        super(applet, scope, rand, parameters); 
    }
}
