package aladdin.capi.pbe;
import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import aladdin.capi.derive.*;
import aladdin.util.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PBKDF2
///////////////////////////////////////////////////////////////////////////
public class PBKDF2 extends KeyDerive
{
	private final PRF    prf;           // псевдослучайная функция
    private final int    blockSize;     // размер генерируемого блока
	private final byte[] salt;          // salt-значение
	private final int	 iterations;	// число итераций
	private final int	 keySize;       // размер генерируемого ключа
    
	// конструктор 
	public PBKDF2(Mac macAlgorithm, byte[] salt, int iterations, int keySize)
	{
        // сохранить переданные параметры
		this.prf = new MACPRF(macAlgorithm); this.blockSize = macAlgorithm.macSize(); 
        
        // сохранить переданные параметры
		this.salt = salt; this.iterations = iterations; this.keySize = keySize;
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        prf.close(); super.onClose();
    } 
    private void deriveBlock(byte[] password, byte[] key, int ofs, int cb) 
        throws IOException, InvalidKeyException
	{
		// закодировать номер блока
		byte[] number = Convert.fromInt32(ofs / blockSize + 1, Endian.BIG_ENDIAN);

		// объединить salt-значение с номером блока
		byte[] data = Array.concat(salt, number); byte[] mac = new byte[blockSize]; 

		// сгенерировать псевдослучайное значение
		prf.generate(password, data, mac, 0, blockSize);  
        
		// инициализировать сумму значений
		data = mac; System.arraycopy(data, 0, key, ofs, cb); 
 
		// для всех итераций
		for (int j = 1; j < iterations; j++)
		{
            // сгенерировать псевдослучайное значение
            prf.generate(password, data, mac, 0, blockSize); data = mac;  
            
            // скорректировать сумму значений
			for (int k = 0; k < cb; k++) key[ofs + k] ^= data[k];
		}
	}
	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey password, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
            throws IOException, InvalidKeyException
	{
        // при отсутствии размера
        if (deriveSize < 0) { deriveSize = keySize; 
        
            // проверить корректность параметров
            if (keySize < 0) throw new IllegalArgumentException();
        } 
        // проверить размер ключа
        else if (keySize >= 0 && keySize != deriveSize) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // проверить наличие значения
        byte[] pswd = password.value(); if (pswd == null)
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException(); 
        }
		// выделить память для результата
		byte[] key = new byte[deriveSize]; int ofs = 0;  

		// для всех полных блоков
		for (; ofs < key.length - blockSize; ofs += blockSize)
		{
			// вычислить часть ключа
			deriveBlock(pswd, key, ofs, blockSize); 
		}
		// вычислить последнюю часть ключа
		deriveBlock(pswd, key, ofs, key.length - ofs); 
        
        // вернуть ключ
        return keyFactory.create(key); 
 	}
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier prf, String password, 
        byte[] salt, int iterations, byte[] result) throws Exception
    {
		// закодировать параметры
		IEncodable kdfParameters = new aladdin.asn1.iso.pkcs.pkcs5.PBKDF2Parameter(
			new OctetString(salt), new Integer(iterations), 
            new Integer(result.length), prf
		);
        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2), kdfParameters
        ); 
        // вывести сообщение
        Test.dump("Salt", salt); Test.println("Iterations = %1$d", iterations); 
        
        // создать алгоритм наследования ключа
        try (KeyDerive algorithm = (KeyDerive)factory.createAlgorithm(
            scope, parameters, KeyDerive.class))
        {
            // выполнить тест
            KeyDerive.knownTest(algorithm, password.getBytes("UTF-8"), null, result);
        }
    }
}
