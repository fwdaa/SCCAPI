﻿using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : CAPI.PKCS11.SignHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // конструктор
	    public SignHash(CAPI.PKCS11.Applet applet) : base(applet) {} 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_ECDSA); 
	    }
	    // алгоритм подписи хэш-значения
	    public override byte[] Sign(IPrivateKey privateKey, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAgorithm, byte[] hash) 
        {
            // преобразовать параметры алгоритма
            ANSI.X962.IParameters parameters = (ANSI.X962.IParameters)privateKey.Parameters; 
        
            // подписать хэш-значение
            byte[] signature = base.Sign(privateKey, rand, hashAgorithm, hash); 
        
            // закодировать подпись
            return X962.Encoding.DecodeSignature(parameters, signature).Encoded; 
        }
    }
}