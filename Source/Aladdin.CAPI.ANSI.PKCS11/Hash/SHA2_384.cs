using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Hash
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA2-384
	///////////////////////////////////////////////////////////////////////////////
	public class SHA2_384 : CAPI.PKCS11.Hash
	{
		// конструктор
		public SHA2_384(CAPI.PKCS11.Applet applet) : base(applet) {}
		
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// выделить память для параметров
			return new Mechanism(API.CKM_SHA384); 
		}
		// размер хэш-значения в байтах
		public override int HashSize { get { return 48; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 128; }}

		// завершить хэширование данных
		public override int Finish(byte[] buf, int bufOff)
        {
            // проверить наличие данных
            if (Total != 0) return base.Finish(buf, bufOff); 

            // создать алгоритм хэширования
            using (CAPI.Hash algorithm = new CAPI.ANSI.Hash.SHA2_384())
            {
                // вычислить хэш-значение
                byte[] hash = algorithm.HashData(new byte[0], 0, 0); 

                // скопировать хэш-значение
                Array.Copy(hash, 0, buf, bufOff, hash.Length); return hash.Length; 
            }
        }
	}
}
