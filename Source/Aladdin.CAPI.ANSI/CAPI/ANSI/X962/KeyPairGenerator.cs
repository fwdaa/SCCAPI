using System; 

namespace Aladdin.CAPI.ANSI.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей 
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator : Software.KeyPairGenerator
    {
        // фабрика алгоритмов и параметры ключей
		private IParameters parameters;

		// конструктор
		public KeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IParameters parameters) 
            
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
		    IPublicKey publicKey = new PublicKey(keyFactory, parameters, Q);

            // создать личный ключ 
            using (IPrivateKey privateKey = new PrivateKey(
                Factory, Scope, keyOID, parameters, d))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}
