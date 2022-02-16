﻿namespace Aladdin.CAPI.ANSI.X942
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма DH
	///////////////////////////////////////////////////////////////////////////
	public interface IPrivateKey : CAPI.IPrivateKey
	{
		Math.BigInteger	X { get; }	// параметр X
	}
}