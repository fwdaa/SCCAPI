using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Учетные данные аутентификации
	///////////////////////////////////////////////////////////////////////////
	public abstract class Credentials : Authentication 
	{
		// тип аутентификации
		public override Type[] Types { get { return new Type[] { GetType() }; } }
	}
}
