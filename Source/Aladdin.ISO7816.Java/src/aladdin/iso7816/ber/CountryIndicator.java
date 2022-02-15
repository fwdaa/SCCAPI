package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Код страны и национальные данные (0x41)
///////////////////////////////////////////////////////////////////////////
public class CountryIndicator extends DataObject
{
    // описание региона и дополнительные данные
    public final String region; public final byte[] data;

    // конструктор раскодирования
    public CountryIndicator(byte[] content) throws IOException
    {
        // вызвать базовую функцию
        super(Authority.ISO7816, Tag.COUNTRY_INDICATOR, content); 
        
        // извлечь три цифры
        int[] digits = Encoding.decodeDigits(3, content, 0); 
        
        // вычислить код страны
        int code = digits[0] * 100 + digits[1] * 10 + digits[2];

        // получить описание региона
        region = CountryIndicator.getRegionInfo(code); 
            
        // проверить отсутствие ошибок
        if (region == null) throw new IOException();
            
        // выделить память для переменной
        data = new byte[content.length * 2 - 3]; data[0] = (byte)(content[1] & 0x0F); 

        // скопировать дополнительные данные
        for (int i = 2; i < content.length; i++)
        {
            // скопировать дополнительные данные
            data[2 * i - 3] = (byte)((content[i] >>>  4) & 0x0F);
            data[2 * i - 2] = (byte)((content[i]       ) & 0x0F);
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Стандарт ISO 3166
    ///////////////////////////////////////////////////////////////////////
    private static final Map<Integer, String> ISO3166 = new HashMap<Integer, String>(); 
    static {
        ISO3166.put(  4, "AF"/*"AFG"*/); ISO3166.put(  8, "AL"/*"ALB"*/); ISO3166.put( 10, "AQ"/*"ATA"*/); 
        ISO3166.put( 12, "DZ"/*"DZA"*/); ISO3166.put( 16, "AS"/*"ASM"*/); ISO3166.put( 20, "AD"/*"AND"*/); 
        ISO3166.put( 24, "AO"/*"AGO"*/); ISO3166.put( 28, "AG"/*"ATG"*/); ISO3166.put( 31, "AZ"/*"AZE"*/); 
        ISO3166.put( 32, "AR"/*"ARG"*/); ISO3166.put( 36, "AU"/*"AUS"*/); ISO3166.put( 40, "AT"/*"AUT"*/); 
        ISO3166.put( 44, "BS"/*"BHS"*/); ISO3166.put( 48, "BH"/*"BHR"*/); ISO3166.put( 50, "BD"/*"BGD"*/); 
        ISO3166.put( 51, "AM"/*"ARM"*/); ISO3166.put( 52, "BB"/*"BRB"*/); ISO3166.put( 56, "BE"/*"BEL"*/); 
        ISO3166.put( 60, "BM"/*"BMU"*/); ISO3166.put( 64, "BT"/*"BTN"*/); ISO3166.put( 68, "BO"/*"BOL"*/); 
        ISO3166.put( 70, "BA"/*"BIH"*/); ISO3166.put( 72, "BW"/*"BWA"*/); ISO3166.put( 74, "BV"/*"BVT"*/); 
        ISO3166.put( 76, "BR"/*"BRA"*/); ISO3166.put( 86, "IO"/*"IOT"*/); ISO3166.put( 84, "BZ"/*"BLZ"*/); 
        ISO3166.put( 90, "SB"/*"SLB"*/); ISO3166.put( 92, "VG"/*"VGB"*/); ISO3166.put( 96, "BN"/*"BRN"*/); 
        ISO3166.put(100, "BG"/*"BGR"*/); ISO3166.put(104, "MM"/*"MMR"*/); ISO3166.put(108, "BI"/*"BDI"*/); 
        ISO3166.put(112, "BY"/*"BLR"*/); ISO3166.put(116, "KH"/*"KHM"*/); ISO3166.put(120, "CM"/*"CMR"*/); 
        ISO3166.put(124, "CA"/*"CAN"*/); ISO3166.put(132, "CV"/*"CPV"*/); ISO3166.put(136, "KY"/*"CYM"*/); 
        ISO3166.put(140, "CF"/*"CAF"*/); ISO3166.put(144, "LK"/*"LKA"*/); ISO3166.put(148, "TD"/*"TCD"*/); 
        ISO3166.put(152, "CL"/*"CHL"*/); ISO3166.put(156, "CN"/*"CHN"*/); ISO3166.put(158, "TW"/*"TWN"*/); 
        ISO3166.put(162, "CX"/*"CXR"*/); ISO3166.put(166, "CC"/*"CCK"*/); ISO3166.put(170, "CO"/*"COL"*/); 
        ISO3166.put(174, "KM"/*"COM"*/); ISO3166.put(175, "YT"/*"MYT"*/); ISO3166.put(178, "CG"/*"COG"*/); 
        ISO3166.put(180, "CD"/*"COD"*/); ISO3166.put(184, "CK"/*"COK"*/); ISO3166.put(188, "CR"/*"CRI"*/); 
        ISO3166.put(191, "HR"/*"HRV"*/); ISO3166.put(192, "CU"/*"CUB"*/); ISO3166.put(196, "CY"/*"CYP"*/); 
        ISO3166.put(203, "CZ"/*"CZE"*/); ISO3166.put(204, "BJ"/*"BEN"*/); ISO3166.put(208, "DK"/*"DNK"*/); 
        ISO3166.put(212, "DM"/*"DMA"*/); ISO3166.put(214, "DO"/*"DOM"*/); ISO3166.put(218, "EC"/*"ECU"*/); 
        ISO3166.put(222, "SV"/*"SLV"*/); ISO3166.put(226, "GQ"/*"GNQ"*/); ISO3166.put(231, "ET"/*"ETH"*/); 
        ISO3166.put(232, "ER"/*"ERI"*/); ISO3166.put(233, "EE"/*"EST"*/); ISO3166.put(234, "FO"/*"FRO"*/); 
        ISO3166.put(238, "FK"/*"FLK"*/); ISO3166.put(239, "GS"/*"SGS"*/); ISO3166.put(242, "FJ"/*"FJI"*/); 
        ISO3166.put(246, "FI"/*"FIN"*/); ISO3166.put(248, "AX"/*"ALA"*/); ISO3166.put(250, "FR"/*"FRA"*/); 
        ISO3166.put(254, "GF"/*"GUF"*/); ISO3166.put(258, "PF"/*"PYF"*/); ISO3166.put(260, "TF"/*"ATF"*/); 
        ISO3166.put(262, "DJ"/*"DJI"*/); ISO3166.put(266, "GA"/*"GAB"*/); ISO3166.put(268, "GE"/*"GEO"*/); 
        ISO3166.put(270, "GM"/*"GMB"*/); ISO3166.put(275, "PS"/*"PSE"*/); ISO3166.put(276, "DE"/*"DEU"*/); 
        ISO3166.put(288, "GH"/*"GHA"*/); ISO3166.put(292, "GI"/*"GIB"*/); ISO3166.put(296, "KI"/*"KIR"*/); 
        ISO3166.put(300, "GR"/*"GRC"*/); ISO3166.put(304, "GL"/*"GRL"*/); ISO3166.put(308, "GD"/*"GRD"*/); 
        ISO3166.put(312, "GP"/*"GLP"*/); ISO3166.put(316, "GU"/*"GUM"*/); ISO3166.put(320, "GT"/*"GTM"*/); 
        ISO3166.put(324, "GN"/*"GIN"*/); ISO3166.put(328, "GY"/*"GUY"*/); ISO3166.put(332, "HT"/*"HTI"*/); 
        ISO3166.put(334, "HM"/*"HMD"*/); ISO3166.put(336, "VA"/*"VAT"*/); ISO3166.put(340, "HN"/*"HND"*/); 
        ISO3166.put(344, "HK"/*"HKG"*/); ISO3166.put(348, "HU"/*"HUN"*/); ISO3166.put(352, "IS"/*"ISL"*/); 
        ISO3166.put(356, "IN"/*"IND"*/); ISO3166.put(360, "ID"/*"IDN"*/); ISO3166.put(364, "IR"/*"IRN"*/); 
        ISO3166.put(368, "IQ"/*"IRQ"*/); ISO3166.put(372, "IE"/*"IRL"*/); ISO3166.put(376, "IL"/*"ISR"*/); 
        ISO3166.put(380, "IT"/*"ITA"*/); ISO3166.put(384, "CI"/*"CIV"*/); ISO3166.put(388, "JM"/*"JAM"*/); 
        ISO3166.put(392, "JP"/*"JPN"*/); ISO3166.put(398, "KZ"/*"KAZ"*/); ISO3166.put(400, "JO"/*"JOR"*/); 
        ISO3166.put(404, "KE"/*"KEN"*/); ISO3166.put(408, "KP"/*"PRK"*/); ISO3166.put(410, "KR"/*"KOR"*/); 
        ISO3166.put(414, "KW"/*"KWT"*/); ISO3166.put(417, "KG"/*"KGZ"*/); ISO3166.put(418, "LA"/*"LAO"*/); 
        ISO3166.put(422, "LB"/*"LBN"*/); ISO3166.put(426, "LS"/*"LSO"*/); ISO3166.put(428, "LV"/*"LVA"*/); 
        ISO3166.put(430, "LR"/*"LBR"*/); ISO3166.put(434, "LY"/*"LBY"*/); ISO3166.put(438, "LI"/*"LIE"*/); 
        ISO3166.put(440, "LT"/*"LTU"*/); ISO3166.put(442, "LU"/*"LUX"*/); ISO3166.put(446, "MO"/*"MAC"*/); 
        ISO3166.put(450, "MG"/*"MDG"*/); ISO3166.put(454, "MW"/*"MWI"*/); ISO3166.put(458, "MY"/*"MYS"*/); 
        ISO3166.put(462, "MV"/*"MDV"*/); ISO3166.put(466, "ML"/*"MLI"*/); ISO3166.put(470, "MT"/*"MLT"*/); 
        ISO3166.put(474, "MQ"/*"MTQ"*/); ISO3166.put(478, "MR"/*"MRT"*/); ISO3166.put(480, "MU"/*"MUS"*/); 
        ISO3166.put(484, "MX"/*"MEX"*/); ISO3166.put(492, "MC"/*"MCO"*/); ISO3166.put(496, "MN"/*"MNG"*/); 
        ISO3166.put(498, "MD"/*"MDA"*/); ISO3166.put(499, "ME"/*"MNE"*/); ISO3166.put(500, "MS"/*"MSR"*/); 
        ISO3166.put(504, "MA"/*"MAR"*/); ISO3166.put(508, "MZ"/*"MOZ"*/); ISO3166.put(512, "OM"/*"OMN"*/); 
        ISO3166.put(516, "NA"/*"NAM"*/); ISO3166.put(520, "NR"/*"NRU"*/); ISO3166.put(524, "NP"/*"NPL"*/); 
        ISO3166.put(528, "NL"/*"NLD"*/); ISO3166.put(531, "CW"/*"CUW"*/); ISO3166.put(533, "AW"/*"ABW"*/); 
        ISO3166.put(534, "SX"/*"SXM"*/); ISO3166.put(535, "BQ"/*"BES"*/); ISO3166.put(540, "NC"/*"NCL"*/); 
        ISO3166.put(548, "VU"/*"VUT"*/); ISO3166.put(554, "NZ"/*"NZL"*/); ISO3166.put(558, "NI"/*"NIC"*/); 
        ISO3166.put(562, "NE"/*"NER"*/); ISO3166.put(566, "NG"/*"NGA"*/); ISO3166.put(570, "NU"/*"NIU"*/); 
        ISO3166.put(574, "NF"/*"NFK"*/); ISO3166.put(578, "NO"/*"NOR"*/); ISO3166.put(580, "MP"/*"MNP"*/); 
        ISO3166.put(581, "UM"/*"UMI"*/); ISO3166.put(583, "FM"/*"FSM"*/); ISO3166.put(584, "MH"/*"MHL"*/); 
        ISO3166.put(585, "PW"/*"PLW"*/); ISO3166.put(586, "PK"/*"PAK"*/); ISO3166.put(591, "PA"/*"PAN"*/); 
        ISO3166.put(598, "PG"/*"PNG"*/); ISO3166.put(600, "PY"/*"PRY"*/); ISO3166.put(604, "PE"/*"PER"*/); 
        ISO3166.put(608, "PH"/*"PHL"*/); ISO3166.put(612, "PN"/*"PCN"*/); ISO3166.put(616, "PL"/*"POL"*/); 
        ISO3166.put(620, "PT"/*"PRT"*/); ISO3166.put(624, "GW"/*"GNB"*/); ISO3166.put(626, "TL"/*"TLS"*/); 
        ISO3166.put(630, "PR"/*"PRI"*/); ISO3166.put(634, "QA"/*"QAT"*/); ISO3166.put(638, "RE"/*"REU"*/); 
        ISO3166.put(642, "RO"/*"ROU"*/); ISO3166.put(643, "RU"/*"RUS"*/); ISO3166.put(646, "RW"/*"RWA"*/); 
        ISO3166.put(652, "BL"/*"BLM"*/); ISO3166.put(654, "SH"/*"SHN"*/); ISO3166.put(659, "KN"/*"KNA"*/); 
        ISO3166.put(660, "AI"/*"AIA"*/); ISO3166.put(662, "LC"/*"LCA"*/); ISO3166.put(663, "MF"/*"MAF"*/); 
        ISO3166.put(666, "PM"/*"SPM"*/); ISO3166.put(670, "VC"/*"VCT"*/); ISO3166.put(674, "SM"/*"SMR"*/); 
        ISO3166.put(678, "ST"/*"STP"*/); ISO3166.put(682, "SA"/*"SAU"*/); ISO3166.put(686, "SN"/*"SEN"*/); 
        ISO3166.put(688, "RS"/*"SRB"*/); ISO3166.put(690, "SC"/*"SYC"*/); ISO3166.put(694, "SL"/*"SLE"*/); 
        ISO3166.put(702, "SG"/*"SGP"*/); ISO3166.put(703, "SK"/*"SVK"*/); ISO3166.put(704, "VN"/*"VNM"*/); 
        ISO3166.put(705, "SI"/*"SVN"*/); ISO3166.put(706, "SO"/*"SOM"*/); ISO3166.put(710, "ZA"/*"ZAF"*/); 
        ISO3166.put(716, "ZW"/*"ZWE"*/); ISO3166.put(724, "ES"/*"ESP"*/); ISO3166.put(728, "SS"/*"SSD"*/); 
        ISO3166.put(729, "SD"/*"SDN"*/); ISO3166.put(732, "EH"/*"ESH"*/); ISO3166.put(740, "SR"/*"SUR"*/); 
        ISO3166.put(744, "SJ"/*"SJM"*/); ISO3166.put(748, "SZ"/*"SWZ"*/); ISO3166.put(752, "SE"/*"SWE"*/); 
        ISO3166.put(756, "CH"/*"CHE"*/); ISO3166.put(760, "SY"/*"SYR"*/); ISO3166.put(762, "TJ"/*"TJK"*/); 
        ISO3166.put(764, "TH"/*"THA"*/); ISO3166.put(768, "TG"/*"TGO"*/); ISO3166.put(772, "TK"/*"TKL"*/); 
        ISO3166.put(776, "TO"/*"TON"*/); ISO3166.put(780, "TT"/*"TTO"*/); ISO3166.put(784, "AE"/*"ARE"*/); 
        ISO3166.put(788, "TN"/*"TUN"*/); ISO3166.put(792, "TR"/*"TUR"*/); ISO3166.put(795, "TM"/*"TKM"*/); 
        ISO3166.put(796, "TC"/*"TCA"*/); ISO3166.put(798, "TV"/*"TUV"*/); ISO3166.put(800, "UG"/*"UGA"*/); 
        ISO3166.put(804, "UA"/*"UKR"*/); ISO3166.put(807, "MK"/*"MKD"*/); ISO3166.put(818, "EG"/*"EGY"*/); 
        ISO3166.put(826, "GB"/*"GBR"*/); ISO3166.put(831, "GG"/*"GGY"*/); ISO3166.put(832, "JE"/*"JEY"*/); 
        ISO3166.put(833, "IM"/*"IMN"*/); ISO3166.put(834, "TZ"/*"TZA"*/); ISO3166.put(840, "US"/*"USA"*/); 
        ISO3166.put(850, "VI"/*"VIR"*/); ISO3166.put(854, "BF"/*"BFA"*/); ISO3166.put(858, "UY"/*"URY"*/); 
        ISO3166.put(860, "UZ"/*"UZB"*/); ISO3166.put(862, "VE"/*"VEN"*/); ISO3166.put(876, "WF"/*"WLF"*/); 
        ISO3166.put(882, "WS"/*"WSM"*/); ISO3166.put(887, "YE"/*"YEM"*/); ISO3166.put(894, "ZM"/*"ZMB"*/); 
    }  
    public static String getRegionInfo(int code)
    {
        // проверить корректность кода страны
        if (!ISO3166.containsKey(code)) return null; 

        // получить описание региона
        return ISO3166.get(code); 
    }
    public static int getCountryCode(String region)
    {
        // для всех элементов ISO 3166
        for (Map.Entry<Integer, String> pair : ISO3166.entrySet())
        {
            // проверить совпадение аббревиатуры
            if (pair.getValue().equals(region)) return pair.getKey(); 
        }
        return -1; 
    }
}
