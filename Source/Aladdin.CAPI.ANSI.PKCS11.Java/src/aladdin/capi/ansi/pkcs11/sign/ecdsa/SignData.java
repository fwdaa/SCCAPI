package aladdin.capi.ansi.pkcs11.sign.ecdsa;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.pkcs11.x962.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи DSA
///////////////////////////////////////////////////////////////////////////
public class SignData extends aladdin.capi.pkcs11.SignData
{
    // идентификатор и параметры алгоритма
    private final long algID; private aladdin.capi.ansi.x962.IParameters parameters; 
    
    // конструктор
	public SignData(Applet applet, long algID) 
    
        // сохранить переданные параметры
        { super(applet); this.algID = algID; } 

	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(
        Session sesssion, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(algID); 
	}
	// инициализировать алгоритм
    @Override
	public void init(IPrivateKey privateKey, IRand rand) throws IOException
    {
        // инициализировать алгоритм
        super.init(privateKey, rand); 

        // преобразовать параметры алгоритма
        parameters = (aladdin.capi.ansi.x962.IParameters)privateKey.parameters(); 
    }
	// получить подпись данных
    @Override public byte[] finish(IRand rand) throws IOException
    {
        // получить подпись данных
        byte[] signature = super.finish(rand); 
        
        // закодировать подпись
        return Encoding.decodeSignature(parameters, signature).encoded(); 
    }
}
