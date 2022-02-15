using System;

namespace Aladdin.CAPI.ANSI.X942
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей Diffie-Hellman
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

			// определить параметры алгоритма
			Math.BigInteger P = parameters.P; Math.BigInteger Q = parameters.Q;
			Math.BigInteger G = parameters.G; Math.BigInteger X = null; 

            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            { 
			    // сгенерировать случайное число
			    if (Q.Signum == 0) X = new Math.BigInteger((P.BitLength - 1) / 2, random);  
			    else {
				    // вычислить предел генерации
				    Math.BigInteger max = Q - Math.BigInteger.Two; 
                    
    			    // сгенерировать случайное число
                    int N = Q.BitLength; do { X = new Math.BigInteger(N, random); }

				    // проверить условие генерации
				    while (X.CompareTo(max) >= 0); X = X + Math.BigInteger.One; 
			    }
            }
			// вычислить открытый ключ
			Math.BigInteger Y = G.ModPow(X, P);

			// создать открытый ключ 
			IPublicKey publicKey = new PublicKey(keyFactory, parameters, Y);

            // создать личный ключ 
            using (IPrivateKey privateKey = new PrivateKey(
                Factory, Scope, keyOID, parameters, X))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
		}
	}
}
