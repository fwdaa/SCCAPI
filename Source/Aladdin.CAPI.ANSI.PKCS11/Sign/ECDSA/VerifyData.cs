﻿using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи DSA
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyData : CAPI.PKCS11.VerifyData
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // конструктор
	    public VerifyData(CAPI.PKCS11.Applet applet, ulong algID) 
    
            // сохранить переданные параметры
            : base(applet) { this.algID = algID; } private ulong algID;

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(algID); 
	    }
	    // инициализировать алгоритм
	    public override void Init(IPublicKey publicKey, byte[] signature)
        {
            // преобразовать параметры алгоритма
            ANSI.X962.IParameters parameters = (ANSI.X962.IParameters)publicKey.Parameters; 
        
            // раскодировать значение подписи
            ASN1.ANSI.X962.ECDSASigValue encoded = 
                new ASN1.ANSI.X962.ECDSASigValue(ASN1.Encodable.Decode(signature)); 

            // вызвать базовую функцию
            base.Init(publicKey, X962.Encoding.EncodeSignature(parameters, encoded)); 
        }
    }
}
