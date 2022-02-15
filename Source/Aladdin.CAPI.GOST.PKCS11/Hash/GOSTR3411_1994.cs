using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Hash
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования ГОСТ R 34.11-94
	///////////////////////////////////////////////////////////////////////////////
	public class GOSTR3411_1994 : CAPI.PKCS11.Hash
	{
		// идентификатор параметров
		private string paramsOID; 

		// конструктор
		public GOSTR3411_1994(CAPI.PKCS11.Applet applet, string paramsOID) 

			// сохранить переданные параметры
			: base(applet) { this.paramsOID = paramsOID; }
		
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// закодировать параметры алгоритма
			byte[] encoded = new ASN1.ObjectIdentifier(paramsOID).Encoded; 

			// вернуть параметры алгоритма
			return new Mechanism(API.CKM_GOSTR3411, encoded); 
		}
		// размер хэш-значения в байтах
		public override int HashSize { get { return 32; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 32; }}
	}
}
