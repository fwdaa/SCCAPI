﻿using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Hash
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования SHA3-224
	///////////////////////////////////////////////////////////////////////////////
	public class SHA3_224 : CAPI.PKCS11.Hash
	{
		// конструктор
		public SHA3_224(CAPI.PKCS11.Applet applet) : base(applet) {}
		
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// выделить память для параметров
			return new Mechanism(API.CKM_SHA3_224); 
		}
		// размер хэш-значения в байтах
		public override int HashSize { get { return 28; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 144; }}

		// завершить хэширование данных
		public override int Finish(byte[] buf, int bufOff)
        {
            // проверить наличие данных
            if (Total != 0) return base.Finish(buf, bufOff); 

            // создать алгоритм хэширования
            using (CAPI.Hash algorithm = new CAPI.ANSI.Hash.SHA3(224))
            {
                // вычислить хэш-значение
                byte[] hash = algorithm.HashData(new byte[0], 0, 0); 

                // скопировать хэш-значение
                Array.Copy(hash, 0, buf, bufOff, hash.Length); return hash.Length; 
            }
        }
	}
}