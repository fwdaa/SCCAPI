using System; 

namespace Aladdin.CAPI.ANSI.KEA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей KEA
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator :  Software.KeyPairGenerator
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

	        // вычислить предел генерации
	        Math.BigInteger max = Q.Subtract(Math.BigInteger.ValueOf(2)); int N = Q.BitLength; 

            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do { 
			    // сгенерировать случайное число
                X = new Math.BigInteger(N, random); 
            }
            // проверить условие генерации
	        while (X.CompareTo(max) >= 0); X = X.Add(Math.BigInteger.One); 

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
