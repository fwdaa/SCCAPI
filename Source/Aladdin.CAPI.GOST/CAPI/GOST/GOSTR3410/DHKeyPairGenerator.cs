using System;

namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////
    public class DHKeyPairGenerator : Software.KeyPairGenerator
    {
        // фабрика алгоритмов и параметры ключей
		private IDHParameters parameters;

		// конструктор
		public DHKeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IDHParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

	    public override KeyPair Generate(string keyOID) 
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // получить параметры алгоритма
		    Math.BigInteger p = parameters.P; Math.BigInteger x = null;
            
		    // получить параметры алгоритма
            Math.BigInteger q = parameters.Q; int bitsQ = q.BitLength; 
        
            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do { 
		        // сгенерировать случайное число
                x = new Math.BigInteger(bitsQ, random);
            }
            // проверить выполнение требуемых условий
            while (x.Signum == 0 || x.CompareTo(q) >= 0); 

		    // умножить базовую точку на число
		    Math.BigInteger y = parameters.G.ModPow(x, p); 

		    // создать открытый ключ 
		    IDHPublicKey publicKey = new DHPublicKey(keyFactory, parameters, y);

            // создать личный ключ 
            using (IDHPrivateKey privateKey = new DHPrivateKey(
                Factory, Scope, keyOID, parameters, x))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}
