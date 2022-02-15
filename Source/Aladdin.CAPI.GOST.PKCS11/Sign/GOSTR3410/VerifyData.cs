﻿using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Sign.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи ГОСТ R 34.10-2001, 2012
	///////////////////////////////////////////////////////////////////////////
	public class VerifyData : CAPI.PKCS11.VerifyData
	{
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
	}
}
