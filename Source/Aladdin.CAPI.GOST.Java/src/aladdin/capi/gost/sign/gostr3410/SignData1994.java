package aladdin.capi.gost.sign.gostr3410;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Подпись данных ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////
public class SignData1994 extends SignData
{
    // алгоритм выработки подписи и алгоритм хэширования
    private final SignHash signAlgorithm; private Hash hashAlgorithm;
    
    // конструктор
    public SignData1994(SignHash signAlgorithm) 
    { 
        // сохранить переданные параметры
        this.signAlgorithm = RefObject.addRef(signAlgorithm); hashAlgorithm = null;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(signAlgorithm); super.onClose();         
    } 
	// инициализировать алгоритм
	@Override public void init(IPrivateKey privateKey, IRand rand) throws IOException 
	{ 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // выполнить преобразование типа
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey.parameters(); 
        
        // создать алгоритм хэширования
        hashAlgorithm = createHashAlgorithm(parameters.hashOID()); 
        
        // проверить наличие алгоритма хэширования
        if (hashAlgorithm == null) throw new UnsupportedOperationException(); 

		// инициализировать алгоритм хэширования
		super.init(privateKey, rand); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException 
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public byte[] finish(IRand rand) throws IOException
    {
        // выполнить преобразование типа
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey().parameters(); 

        // указать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
            new ObjectIdentifier(parameters.hashOID())
        ); 
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0);  
        
        // подписать хэш-значение
        byte[] signature = signAlgorithm.sign(privateKey(), rand, hashParameters, hash); 
            
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); hashAlgorithm = null; 
        
        // вернуть вычисленную подпись
        super.finish(rand); return signature;
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