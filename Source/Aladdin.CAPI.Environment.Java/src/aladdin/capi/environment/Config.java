package aladdin.capi.environment;

///////////////////////////////////////////////////////////////////////////////
// Криптографическая среда по умолчанию
///////////////////////////////////////////////////////////////////////////////
public class Config 
{
    // фабрики алгоритмов
    private static final ConfigFactory[] FACTORIES = new ConfigFactory[] {
        new ConfigFactory("ANSI", "aladdin.capi.ansi.Factory"), 
        new ConfigFactory("GOST", "aladdin.capi.gost.Factory"), 
        new ConfigFactory("STB" , "aladdin.capi.stb.Factory" ), 
        new ConfigFactory("KZ"  , "aladdin.capi.kz.Factory"  ) 
    };  
    // криптографические ключи
    private static final ConfigKey[] KEYS = new ConfigKey[] {
        new ConfigKey("1.2.840.113549.1.1.1"       , "ANSI RSA"                 , "ANSI", "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.2.840.113549.1.1.7"       , "ANSI RSA OAEP"            , "ANSI", "aladdin.capi.ansi.culture.RSAOP"        ),
        new ConfigKey("1.2.840.113549.1.1.10"      , "ANSI RSA PSS"             , "ANSI", "aladdin.capi.ansi.culture.RSAOP"        ),
        new ConfigKey("1.2.840.10040.4.1"          , "ANSI DSA"                 , "ANSI", "aladdin.capi.ansi.culture.DSS"          ),
        new ConfigKey("1.2.840.10046.2.1"          , "ANSI DH"                  , "ANSI", "aladdin.capi.ansi.culture.DSS"          ),
        new ConfigKey("1.2.840.10045.2.1"          , "ANSI ECDSA/ECDH"          , "ANSI", "aladdin.capi.ansi.culture.ECDSS_256"    ),
        new ConfigKey("1.2.643.2.2.20"             , "GOST R34.10-1994"         , "GOST", "aladdin.capi.gost.culture.GOSTR1994"    ),
        new ConfigKey("1.2.643.2.2.19"             , "GOST R34.10-2001"         , "GOST", "aladdin.capi.gost.culture.GOSTR2001"    ),
        new ConfigKey("1.2.643.7.1.1.1.1"          , "GOST R34.10-2012-256"     , "GOST", "aladdin.capi.gost.culture.GOSTR2012_256"),
        new ConfigKey("1.2.643.7.1.1.1.2"          , "GOST R34.10-2012-512"     , "GOST", "aladdin.capi.gost.culture.GOSTR2012_512"),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.1"   , "STB 1172.2 BDS"           , "STB" , "aladdin.capi.stb.culture.STB1176"       ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.2"   , "STB 1172.2 BDSPro"        , "STB" , "aladdin.capi.stb.culture.STB1176Pro"    ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.3"   , "STB 1172.2 BDS/BDH"       , "STB" , "aladdin.capi.stb.culture.STB1176"       ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.4"   , "STB 1172.2 BDSPro/BDH"    , "STB" , "aladdin.capi.stb.culture.STB1176Pro"    ),
        new ConfigKey("1.2.112.0.2.0.34.101.45.2.1", "STB 34.101"               , "STB" , "aladdin.capi.stb.culture.STB34101_256"  ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.8"     , "KZ GOST 34.310-2004-A"    , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.14"    , "KZ GOST 34.310-2004-B"    , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.15"    , "KZ GOST 34.310-2004-C"    , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.20"    , "KZ RSA-1024"              , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.20"    , "KZ RSA-1024-Xch"          , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.21"    , "KZ RSA-1536"              , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.21"    , "KZ RSA-1536-Xch"          , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.22"    , "KZ RSA-2048"              , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.22"    , "KZ RSA-2048-Xch"          , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.23"    , "KZ RSA-3072"              , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.23"    , "KZ RSA-3072-Xch"          , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.24"    , "KZ RSA-4096"              , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.24"    , "KZ RSA-4096-Xch"          , "KZ"  , "aladdin.capi.ansi.culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.8"     , "KZ GOST 34.310-2004-A-Xch", "KZ"  , "aladdin.capi.kz.culture.GOST2004"       ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.14"    , "KZ GOST 34.310-2004-B-Xch", "KZ"  , "aladdin.capi.kz.culture.GOST2004"       )
    };   
    // конфигурация по умолчанию
    public static final ConfigSection DEFAULT = new ConfigSection(
        new ConfigAuthentications(5), FACTORIES, new ConfigRandFactory[0], KEYS, new ConfigPlugin[0]
    ); 
}
