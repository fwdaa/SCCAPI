package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания генераторов случайных данных
///////////////////////////////////////////////////////////////////////////
public interface IRandFactory extends IRefObject
{
    // создать генератор случайных данных
    IRand createRand(Object window) throws IOException; 
}
