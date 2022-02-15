using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Hash
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования ГОСТ R 34.11-2012
	///////////////////////////////////////////////////////////////////////////////
	public class GOSTR3411_2012 : CAPI.PKCS11.Hash
	{
		// конструктор
		public GOSTR3411_2012(CAPI.PKCS11.Applet applet, int bits) 
			
			// сохранить переданные параметры
			: base(applet) { this.bits = bits; } private int bits; 
		
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// указать параметры алгоритма
			return new Mechanism(bits == 256 ? API.CKM_GOSTR3411_2012_256 : API.CKM_GOSTR3411_2012_512); 
		}
		// размер хэш-значения в байтах
		public override int HashSize { get { return bits / 8; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 64; }}
	}
}
