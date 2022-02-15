package aladdin.capi.ansi.rsa;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры RSA
///////////////////////////////////////////////////////////////////////////////
public interface IParameters extends aladdin.capi.IParameters
{
    // размер модуля в битах и величина открытой экспоненты
    int getModulusBits(); BigInteger getPublicExponent(); 
}
