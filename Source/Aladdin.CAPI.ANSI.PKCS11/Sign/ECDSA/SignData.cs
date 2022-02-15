using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи DSA
    ///////////////////////////////////////////////////////////////////////////
    public class SignData : CAPI.PKCS11.SignData
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // идентификатор и параметры алгоритма
        private ulong algID; private ANSI.X962.IParameters parameters; 
    
        // конструктор
	    public SignData(CAPI.PKCS11.Applet applet, ulong algID) 
    
            // сохранить переданные параметры
            : base(applet) { this.algID = algID; this.parameters = null; } 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(algID); 
	    }
		// инициализировать алгоритм
		public override void Init(IPrivateKey privateKey, IRand rand)
        {
		    // инициализировать алгоритм
            base.Init(privateKey, rand); 

            // преобразовать параметры алгоритма
            parameters = (ANSI.X962.IParameters)privateKey.Parameters; 
        }
	    // получить подпись данных
	    public override byte[] Finish(IRand rand) 
        {
            // получить подпись данных
            byte[] signature = base.Finish(rand); 
        
            // закодировать подпись
            return X962.Encoding.DecodeSignature(parameters, signature).Encoded; 
        }
    }
}
