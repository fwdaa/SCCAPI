using System;

namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей RSA
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

			// используемые константы
			Math.BigInteger E = parameters.PublicExponent;

            // определить размер модуля в битах
			int bits = parameters.KeySize; int lenP = bits / 2; int lenQ = bits - lenP;
            
			// инициализировать переменные
			Math.BigInteger N = null; Math.BigInteger P = null; Math.BigInteger Q = null; 

            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
			do {
				// сгенерировать первый и второй сомножители
                P = new Math.BigInteger(lenP, 80, random);
                Q = new Math.BigInteger(lenQ, 80, random);

				// вычислить модуль
				N = P.Multiply(Q);
			}
			// проверить выполнение требуемых условий
			while (P.CompareTo(Q) == 0 || N.BitLength != bits);

			// вычислить P-1 и Q-1
			Math.BigInteger P1 = P.Subtract(Math.BigInteger.One); 
			Math.BigInteger Q1 = Q.Subtract(Math.BigInteger.One);

			// вычислить секретную экспоненту
			Math.BigInteger D = E.ModInverse(P1.Multiply(Q1));

            // создать открытый ключ 
            IPublicKey publicKey = new PublicKey(keyFactory, N, E);

            // создать личный ключ 
			using (IPrivateKey privateKey = new PrivateKey(Factory, Scope, 
                keyOID, N, E, D, P, Q, D.Mod(P1), D.Mod(Q1), Q.ModInverse(P)))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
		}
	}
}
