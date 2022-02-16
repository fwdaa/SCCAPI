package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.pbe.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Агрегированная фабрика алгоритмов
///////////////////////////////////////////////////////////////////////////
public final class AggregatedFactory extends Factory
{
    // внешняя и внутренняя фабрики алгоритмов
    private final Factory outer; private final Factory factory; 
        
    // конструктор
    public static Factory create(Factory outer, Factory factory)
    {
        // проверить совпадение ссылок
        if (outer == factory) return RefObject.addRef(factory); 
        
        // создать агрегированную фабрику алгоритмов
        return new AggregatedFactory(outer, factory); 
    }
    // конструктор
    private AggregatedFactory(Factory outer, Factory factory)
    {
        // сохранить переданные параметры
        this.outer   = RefObject.addRef(outer  ); 
        this.factory = RefObject.addRef(factory); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить используемые ресурсы
        RefObject.release(outer); RefObject.release(factory); super.onClose();
    }
    @Override public SecretKeyFactory[] secretKeyFactories() 
    { 
        // поддерживаемые ключи
        return outer.secretKeyFactories(); 
    }
    @Override public KeyFactory[] keyFactories() 
    { 
        // поддерживаемые ключи
        return outer.keyFactories(); 
    }
    @Override public Culture getCulture(SecurityStore scope, String keyOID) 
    {
        // получить алгоритмы по умолчанию
        Culture culture = factory.getCulture(scope, keyOID); 
        
        // проверить наличие алгоритмов
        if (culture != null) return culture; 
                
        // создать алгоритмы из внешней фабрики
        return outer.getCulture(scope, keyOID); 
    }
    @Override public PBECulture getCulture(PBEParameters parameters, String keyOID) 
    {
        // получить алгоритмы по умолчанию
        PBECulture culture = factory.getCulture(parameters, keyOID); 
        
        // проверить наличие алгоритмов
        if (culture != null) return culture; 
                
        // создать алгоритмы из внешней фабрики
        return outer.getCulture(parameters, keyOID); 
    }
    @Override public KeyPairGenerator createGenerator(
        SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // создать алгоритм генерации ключей
        return factory.createGenerator(this, scope, rand, keyOID, parameters);
    }
    @Override public IAlgorithm createAlgorithm(
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // для программных алгоритмов
        if (scope == null || scope instanceof aladdin.capi.software.ContainerStore)
        {
            // создать алгоритм из внутренней фабрики
            IAlgorithm algorithm = factory.createAlgorithm(this, scope, parameters, type);
                
            // проверить наличие алгоритма
            if (algorithm != null) return algorithm; 
                
            // создать алгоритм из внешней фабрики
            return outer.createAlgorithm(scope, parameters, type); 
        }
        // для симметричных алгоритмов
        if (!type.equals(SignHash        .class) && !type.equals(SignData           .class) &&
            !type.equals(IKeyAgreement   .class) && !type.equals(ITransportAgreement.class) &&
            !type.equals(TransportKeyWrap.class))
        {
            // создать алгоритм из внутренней фабрики
            IAlgorithm algorithm = factory.createAlgorithm(this, scope, parameters, type);
                
            // проверить наличие алгоритма
            if (algorithm != null) return algorithm; 
                
            // создать алгоритм из внешней фабрики
            return outer.createAlgorithm(scope, parameters, type); 
        }
        // создать асимметричный алгоритм из внутренней фабрики
        else return factory.createAlgorithm(this, scope, parameters, type);
    }
}
