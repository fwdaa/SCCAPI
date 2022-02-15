using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Ключ симметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public interface ISecretKey : IRefObject 
    { 
        // тип ключа
        SecretKeyFactory KeyFactory { get; } 
        
        // размер и значение ключа
        int Length { get; } byte[] Value { get; } 
    }
}