package aladdin.capi.gost.sign.gostr3410;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Проверка подписи данных ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////
public class VerifyData1994 extends VerifyData
{
    // алгоритм проверки подписи и алгоритм хэширования
    private final VerifyHash verifyAlgorithm; private Hash hashAlgorithm; 
    
    // конструктор
    public VerifyData1994(VerifyHash verifyAlgorithm) 
    { 
        // сохранить переданные параметры
        this.verifyAlgorithm = RefObject.addRef(verifyAlgorithm); hashAlgorithm = null;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(verifyAlgorithm); super.onClose();
    }
	// инициализировать алгоритм
	@Override public void init(IPublicKey publicKey, byte[] signature) 
        throws SignatureException, IOException
	{ 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // выполнить преобразование типа
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)publicKey.parameters(); 
        
        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(parameters.hashOID()); 
            
        // проверить наличие алгоритма хэширования
        if (hashAlgorithm == null) throw new UnsupportedOperationException();
        
		// инициализировать алгоритм хэширования
		super.init(publicKey, signature); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public void finish() throws IOException, SignatureException
	{
        // выполнить преобразование типа
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)publicKey().parameters(); 

        // указать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
            new ObjectIdentifier(parameters.hashOID())
        ); 
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0); 
        
		// проверить подпись хэш-значения
		try { verifyAlgorithm.verify(publicKey(), hashParameters, hash, signature()); }
        
        // освободить выделенные ресурсы
        finally { RefObject.release(hashAlgorithm); hashAlgorithm = null; }
	}
    // получить алгоритм хэширования
    protected Hash createHashAlgorithm(String hashOID)
    {
        // получить именованные параметры алгоритма
        GOSTR3411ParamSet1994 namedParameters = 
            GOSTR3411ParamSet1994.parameters(hashOID);

        // раскодировать таблицу подстановок
        byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.huz()); 

        // создать алгоритм хэширования
        return new aladdin.capi.gost.hash.GOSTR3411_1994(
            sbox, namedParameters.h0().value(), false
        );
    }
}
