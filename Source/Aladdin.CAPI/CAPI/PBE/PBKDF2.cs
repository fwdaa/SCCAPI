using System;
using System.Text;

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм наследования ключа PBKDF2
    ///////////////////////////////////////////////////////////////////////////
    public class PBKDF2 : KeyDerive
    {
	    private PRF     prf;		// псевдослучайная функция
	    private int     blockSize;	// размер генерируемых блоков
	    private byte[]	salt;		// salt-значение
	    private int		iterations;	// число итераций
	    private int		keySize;	// размер генерируемого ключа

	    // конструктор 
	    public PBKDF2(Mac macAlgorithm, byte[] salt, int iterations, int keySize)
	    {
            // сохранить переданные параметры
		    this.prf = new Derive.MACPRF(macAlgorithm); this.blockSize = macAlgorithm.MacSize;

            // сохранить переданные параметры
            this.salt = salt; this.iterations = iterations;	this.keySize = keySize;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            prf.Dispose(); base.OnDispose();
        }
	    private void DeriveBlock(byte[] password, byte[] key, int ofs, int cb) 
	    {
		    // закодировать номер блока
            byte[] number = Math.Convert.FromInt32(ofs / blockSize + 1, Math.Endian.BigEndian);
        
		    // объединить salt-значение с номером блока
		    byte[] data = Arrays.Concat(salt, number); byte[] mac = new byte[blockSize]; 

		    // сгенерировать псевдослучайное значение
            prf.Generate(password, data, mac, 0, blockSize); 
				
		    // инициализировать сумму значений
		    data = mac; Array.Copy(data, 0, key, ofs, cb); 
 
		    // для всех итераций
		    for (int j = 1; j < iterations; j++)
		    {
			    // сгенерировать псевдослучайное значение
                prf.Generate(password, data, mac, 0, blockSize); data = mac;

                // скорректировать сумму значений
			    for (int k = 0; k < cb; k++) key[ofs + k] ^= data[k];
		    }
	    }
	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey password, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
	    {
            // при отсутствии размера
            if (deriveSize < 0) { deriveSize = keySize; 
        
                // проверить корректность параметров
                if (keySize < 0) throw new ArgumentException();
            } 
            // проверить размер ключа
            else if (keySize >= 0 && keySize != deriveSize) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException(); 
            }
            // проверить наличие значения
            byte[] pswd = password.Value; if (pswd == null)
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException(); 
            }
		    // выделить память для результата
		    byte[] key = new byte[deriveSize]; int ofs = 0;

		    // для всех полных блоков
            for (; ofs < key.Length - blockSize; ofs += blockSize)
		    {
			    // вычислить часть ключа
                DeriveBlock(pswd, key, ofs, blockSize); 
		    }
		    // вычислить последнюю часть ключа
            DeriveBlock(pswd, key, ofs, key.Length - ofs); 
            
            // вернуть вычисленный ключ
            return keyFactory.Create(key); 
 	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier prf, String password, 
            byte[] salt, int iterations, byte[] result)
        {
		    // закодировать параметры
		    ASN1.IEncodable kdfParameters = new ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter(
			    new ASN1.OctetString(salt), new ASN1.Integer(iterations), 
                new ASN1.Integer(result.Length), prf
		    );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS5.OID.pbkdf2), kdfParameters
            ); 
            // вывести сообщение
            CAPI.Test.Dump("Salt", salt); CAPI.Test.WriteLine("Iterations = {0}", iterations); 

            // создать алгоритм наследования ключа
            using (KeyDerive algorithm = factory.CreateAlgorithm<KeyDerive>(scope, parameters))
            {
                // выполнить тест
                KnownTest(algorithm, Encoding.UTF8.GetBytes(password), null, result);
            }
        }
    }
}
