package aladdin.capi.ansi.rsa;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры RSA
///////////////////////////////////////////////////////////////////////////////
public interface IParameters extends IKeySizeParameters
{
    // размер модуля в битах и величина открытой экспоненты
    int getModulusBits(); BigInteger getPublicExponent(); 
}
