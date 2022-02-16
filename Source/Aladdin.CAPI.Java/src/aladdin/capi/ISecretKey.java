package aladdin.capi;
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////
public interface ISecretKey extends IRefObject, javax.crypto.SecretKey
{ 
    // тип, размер и значение ключа
    SecretKeyFactory keyFactory(); int length(); byte[] value(); 
}