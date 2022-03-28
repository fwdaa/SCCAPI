package aladdin.capi.environment;

///////////////////////////////////////////////////////////////////////////////
// Криптографическая среда по умолчанию
///////////////////////////////////////////////////////////////////////////////
public class Config 
{
    // фабрики алгоритмов
    private static final ConfigFactory[] FACTORIES = new ConfigFactory[] {
        new ConfigFactory("ANSI", "Aladdin.CAPI.ANSI.Factory"), 
        new ConfigFactory("GOST", "Aladdin.CAPI.GOST.Factory"), 
        new ConfigFactory("STB" , "Aladdin.CAPI.STB.Factory" ), 
        new ConfigFactory("KZ"  , "Aladdin.CAPI.KZ.Factory"  ) 
    };  
    // криптографические ключи
    private static final ConfigKey[] KEYS = new ConfigKey[] {
        new ConfigKey("1.2.840.113549.1.1.1"       , "ANSI RSA"                 , "ANSI", "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.2.840.113549.1.1.7"       , "ANSI RSA OAEP"            , "ANSI", "Aladdin.CAPI.ANSI.Culture.RSAOP"        ),
        new ConfigKey("1.2.840.113549.1.1.10"      , "ANSI RSA PSS"             , "ANSI", "Aladdin.CAPI.ANSI.Culture.RSAOP"        ),
        new ConfigKey("1.2.840.10040.4.1"          , "ANSI DSA"                 , "ANSI", "Aladdin.CAPI.ANSI.Culture.DSS"          ),
        new ConfigKey("1.2.840.10046.2.1"          , "ANSI DH"                  , "ANSI", "Aladdin.CAPI.ANSI.Culture.DSS"          ),
        new ConfigKey("1.2.840.10045.2.1"          , "ANSI ECDSA/ECDH"          , "ANSI", "Aladdin.CAPI.ANSI.Culture.ECDSS_256"    ),
        new ConfigKey("1.2.643.2.2.20"             , "GOST R34.10-1994"         , "GOST", "Aladdin.CAPI.GOST.Culture.GOSTR1994"    ),
        new ConfigKey("1.2.643.2.2.19"             , "GOST R34.10-2001"         , "GOST", "Aladdin.CAPI.GOST.Culture.GOSTR2001"    ),
        new ConfigKey("1.2.643.7.1.1.1.1"          , "GOST R34.10-2012-256"     , "GOST", "Aladdin.CAPI.GOST.Culture.GOSTR2012_256"),
        new ConfigKey("1.2.643.7.1.1.1.2"          , "GOST R34.10-2012-512"     , "GOST", "Aladdin.CAPI.GOST.Culture.GOSTR2012_512"),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.1"   , "STB 1172.2 BDS"           , "STB" , "Aladdin.CAPI.STB.Culture.STB1176"       ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.2"   , "STB 1172.2 BDSPro"        , "STB" , "Aladdin.CAPI.STB.Culture.STB1176Pro"    ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.3"   , "STB 1172.2 BDS/BDH"       , "STB" , "Aladdin.CAPI.STB.Culture.STB1176"       ),
        new ConfigKey("1.2.112.0.2.0.1176.2.2.4"   , "STB 1172.2 BDSPro/BDH"    , "STB" , "Aladdin.CAPI.STB.Culture.STB1176Pro"    ),
        new ConfigKey("1.2.112.0.2.0.34.101.45.2.1", "STB 34.101"               , "STB" , "Aladdin.CAPI.STB.Culture.STB34101_256"  ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.8"     , "KZ GOST 34.310-2004-A"    , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.14"    , "KZ GOST 34.310-2004-B"    , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.15"    , "KZ GOST 34.310-2004-C"    , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.20"    , "KZ RSA-1024"              , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.20"    , "KZ RSA-1024-Xch"          , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.21"    , "KZ RSA-1536"              , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.21"    , "KZ RSA-1536-Xch"          , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.22"    , "KZ RSA-2048"              , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.22"    , "KZ RSA-2048-Xch"          , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.23"    , "KZ RSA-3072"              , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.23"    , "KZ RSA-3072-Xch"          , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.5.24"    , "KZ RSA-4096"              , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.24"    , "KZ RSA-4096-Xch"          , "KZ"  , "Aladdin.CAPI.ANSI.Culture.RSA"          ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.8"     , "KZ GOST 34.310-2004-A-Xch", "KZ"  , "Aladdin.CAPI.KZ.Culture.GOST2004"       ),
        new ConfigKey("1.3.6.1.4.1.6801.1.8.14"    , "KZ GOST 34.310-2004-B-Xch", "KZ"  , "Aladdin.CAPI.KZ.Culture.GOST2004"       )
    };   
    // конфигурация по умолчанию
    public static final ConfigSection DEFAULT = new ConfigSection(
        FACTORIES, new ConfigRandFactory[0], KEYS, new ConfigPlugin[0]
    ); 
}
