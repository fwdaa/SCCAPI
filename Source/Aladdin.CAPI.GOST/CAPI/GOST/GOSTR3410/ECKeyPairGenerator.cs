using System; 

///////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public class ECKeyPairGenerator : Software.KeyPairGenerator
    {
        // параметры ключей
		private IECParameters parameters;

		// конструктор
		public ECKeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IECParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

	    public override KeyPair Generate(string keyOID)
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // получить параметры алгоритма
		    EC.Curve ec = parameters.Curve; Math.BigInteger d = null; 
        
		    // получить параметры алгоритма
            Math.BigInteger n = parameters.Order; int bitsN = n.BitLength; 
        
            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do { 
		        // сгенерировать случайное число
                d = new Math.BigInteger(bitsN, random);
            }
            // проверить выполнение требуемых условий
            while (d.Signum == 0 || d.CompareTo(n) >= 0); 

		    // умножить базовую точку на число
		    EC.Point Q = ec.Multiply(parameters.Generator, d); 

		    // создать открытый ключ 
		    IECPublicKey publicKey = new ECPublicKey(keyFactory, parameters, Q);

            // создать личный ключ 
            using (IECPrivateKey privateKey = new ECPrivateKey(
                Factory, Scope, keyOID, parameters, d))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}