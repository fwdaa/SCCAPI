#if !defined(_AVCSPDEF_H_INCLUDED_)
#define _AVCSPDEF_H_INCLUDED_

#define PROV_AVEST_FULL_DEPRECATED  25
#define PROV_AVEST_PRO_DEPRECATED   24
#define PROV_AVEST_NMC              101
#define PROV_AVEST_PRO_NEW          421
#define PROV_AVEST_FULL_NEW         420

#if defined(AVCSP_NEW_TYPECODES)
# define PROV_AVEST_PRO     PROV_AVEST_PRO_NEW
# define PROV_AVEST_FULL    PROV_AVEST_FULL_NEW
#else
# define PROV_AVEST_PRO     PROV_AVEST_PRO_DEPRECATED
# define PROV_AVEST_FULL    PROV_AVEST_FULL_DEPRECATED
#endif

#define AVCSP_PROV_AVEST_FULL_TYPE_NAME     _T("Avest full")
#define AVCSP_PROV_AVEST_PRO_TYPE_NAME      _T("Avest Pro")
#define AVCSP_PROV_AVEST_NMC_TYPE_NAME      _T("Avest NMC")

#define AVCSP_ALG_SID_BASE      40

#define ALG_SID_BHF             (AVCSP_ALG_SID_BASE + 0)
#define ALG_SID_BDS             (AVCSP_ALG_SID_BASE + 1)
#define ALG_SID_G28147          (AVCSP_ALG_SID_BASE + 2)
#define ALG_SID_BDH             (AVCSP_ALG_SID_BASE + 3)
#define ALG_SID_BDS_BDH         (AVCSP_ALG_SID_BASE + 4)
#define ALG_SID_BDS_PRO         (AVCSP_ALG_SID_BASE + 5)
#define ALG_SID_BDS_PRO_BDH     (AVCSP_ALG_SID_BASE + 6)
#define ALG_SID_G28147_MAC      (AVCSP_ALG_SID_BASE + 7)
#define ALG_SID_BDS_RD          (AVCSP_ALG_SID_BASE + 8)
#define ALG_SID_BDS_NMC         ALG_SID_BDS_RD
#define ALG_SID_BDH_NMC         (AVCSP_ALG_SID_BASE + 9)
#define ALG_SID_G28147_PADDED   (AVCSP_ALG_SID_BASE + 10)
#define ALG_SID_BELT_HASH       (AVCSP_ALG_SID_BASE + 11)

#define CALG_G28147             (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)
#define CALG_G28147_PADDED      (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147_PADDED)
#define CALG_BDS                (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_BDS)
#define CALG_BDS_PRO            (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_BDS_PRO)
#define CALG_BHF                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_BHF)
#define CALG_BDS_BDH            (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_BDS_BDH)
#define CALG_BDS_PRO_BDH        (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_BDS_PRO_BDH)
#define CALG_BDH                (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_BDH)
#define CALG_G28147_MAC         (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)
#define CALG_BDS_RD             (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_BDS_RD)
#define CALG_BDS_NMC            CALG_BDS_RD
#define CALG_BDH_NMC            (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_BDH_NMC)
#define CALG_BELT_HASH          (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_BELT_HASH)

#define AVCSP_OID_BHF           "1.3.6.1.4.1.12656.1.10"
#define AVCSP_OID_BDS           "1.3.6.1.4.1.12656.1.31"
#define AVCSP_OID_BDH           "1.3.6.1.4.1.12656.1.32"
#define AVCSP_OID_BDS_BDH       "1.3.6.1.4.1.12656.1.33"
#define AVCSP_OID_G28147_89     "1.3.6.1.4.1.12656.1.34"
#define AVCSP_OID_BDS_PRO       "1.3.6.1.4.1.12656.1.35"
#define AVCSP_OID_BDS_PRO_BHF   "1.3.6.1.4.1.12656.1.36"
#define AVCSP_OID_BDS_PRO_BDH   "1.3.6.1.4.1.12656.1.37"
#define AVCSP_OID_BDS_RD        "1.3.6.1.4.1.12656.1.38"
#define AVCSP_OID_BDS_RD_BHF    "1.3.6.1.4.1.12656.1.39"
#define AVCSP_OID_BDS_NMC        AVCSP_OID_BDS_RD
#define AVCSP_OID_BDS_NMC_BHF    AVCSP_OID_BDS_RD_BHF

#define AVCSP_OID_BDS_BHF       "1.3.6.1.4.1.12656.1.40"
#define AVCSP_OID_BDH_NMC       "1.3.6.1.4.1.12656.1.41"

#define AVCSP_OID_BELT_HASH     "1.3.6.1.4.1.12656.1.42"
#define AVCSP_OID_BDS_PRO_BELT  "1.3.6.1.4.1.12656.1.43"

#define AVCSP_OID_PRM_BDS_R     "1.3.6.1.4.1.12656.1.31.1"
#define AVCSP_OID_PRM_BDS_L     "1.3.6.1.4.1.12656.1.31.2"
#define AVCSP_OID_PRM_BDS_Z     "1.3.6.1.4.1.12656.1.31.3"
#define AVCSP_OID_PRM_BDS_P     "1.3.6.1.4.1.12656.1.31.4"
#define AVCSP_OID_PRM_BDS_Q     "1.3.6.1.4.1.12656.1.31.5"
#define AVCSP_OID_PRM_BDS_A     "1.3.6.1.4.1.12656.1.31.6"
#define AVCSP_OID_PRM_BDS_H     "1.3.6.1.4.1.12656.1.31.7"

#define AVCSP_OID_PRM_BDH_R     "1.3.6.1.4.1.12656.1.32.1"
#define AVCSP_OID_PRM_BDH_L     "1.3.6.1.4.1.12656.1.32.2"
#define AVCSP_OID_PRM_BDH_Z     "1.3.6.1.4.1.12656.1.32.3"
#define AVCSP_OID_PRM_BDH_P     "1.3.6.1.4.1.12656.1.32.4"
#define AVCSP_OID_PRM_BDH_G     "1.3.6.1.4.1.12656.1.32.5"

#define AVCSP_OID_BDH_ONEWAY_GOST_ECB   "1.3.6.1.4.1.12656.1.32.10.1"

#define AVCSP_OID_PRM_G28147_89_MODE    "1.3.6.1.4.1.12656.1.34.1"
#define AVCSP_OID_G28147_89_CFB         "1.3.6.1.4.1.12656.1.34.1.1"
#define AVCSP_OID_G28147_89_CFB_PADDED  "1.3.6.1.4.1.12656.1.34.1.2"
#define AVCSP_OID_PRM_G28147_89_IV      "1.3.6.1.4.1.12656.1.34.2"

#define AVSCP_OID_BELSSF_MODE           "1.3.6.1.4.1.12656.1.50"
#define AVSCP_OID_BAPB_MODE             "1.3.6.1.4.1.12656.1.51"

#define FUND_OID_PARAMS                 "1.3.6.1.4.1.12656.4.30"
#define AVCA_OID_BASE_DEMO_PARAMS       "1.3.6.1.4.1.12656.7.1"
#define AVCA_OID_BASE_PARAMS            "1.3.6.1.4.1.12656.7.2"
#define AVCA_OID_BASE_PARAMS_BDS        "1.3.6.1.4.1.12656.7.2.1"
#define AVCA_OID_BASE_PARAMS_CSK        "1.3.6.1.4.1.12656.7.2.2"
#define AVCA_OID_BAPB_PARAMS            "1.3.6.1.4.1.12656.7.3"
#define AVCA_OID_NMC_PARAMS             "1.3.6.1.4.1.12656.7.4"
#define NBRB_PARAMS_OID                 "1.3.6.1.4.1.12656.105.10"
#define AVCSP_OID_GOST_SUBST_DEFAULT    "1.3.6.1.4.1.12656.7.5.1"
#define AVCSP_OID_GOST_SUBST_MAILGOV    "1.3.6.1.4.1.12656.7.5.2"
// ГОСТ Р 34.11-94 (Функция хэширования) в приложении А пример с ТБП:
#define AVCSP_OID_GOST_SUBST_RHF_DEMO    "1.3.6.1.4.1.12656.7.5.3"
#define AVCSP_OID_BY_ROOT_PARAMS         "1.3.6.1.4.1.12656.7.6"

#define AVCSP_OID_BELPBE_G28147_ECB     "1.3.6.1.4.1.12656.1.44"

#define AVCSP_TOKEN_CONTROL_ON          1
#define AVCSP_TOKEN_CONTROL_OFF         0

#define AVCSP_TOKEN_TYPE_FLOPPY         1
#define AVCSP_TOKEN_TYPE_IBUTTON        2
#define AVCSP_TOKEN_TYPE_IKEY1000       3 
#define AVCSP_TOKEN_TYPE_ETOKEN         7
#define AVCSP_TOKEN_TYPE_RUTOKEN        8
#define AVCSP_TOKEN_TYPE_ACOS_CARD      9
#define AVCSP_TOKEN_TYPE_AVTOKEN        11

#define AVCSP_PP_BASE                   1000
#define PP_CERT_AVEST_ROOT              (AVCSP_PP_BASE + 1)
#define PP_CERT_AVEST_CODE_SIGN         (AVCSP_PP_BASE + 2)
#define PP_RND_C                        (AVCSP_PP_BASE + 3)
#define PP_BELSSF_AUTH_RND              (AVCSP_PP_BASE + 4)
#define PP_BELSSF_AUTH_KEY              (AVCSP_PP_BASE + 5)
#define PP_NEW_PIN                      (AVCSP_PP_BASE + 6)
#define PP_PARAMS_OID                   (AVCSP_PP_BASE + 7)
#define PP_BAPB_AUTH_RND                (AVCSP_PP_BASE + 8)
#define PP_BAPB_AUTH_KEY                (AVCSP_PP_BASE + 9)
#define PP_TOKEN_CONTROL_MODE           (AVCSP_PP_BASE + 10)
#define PP_FORCE_BDS_PRO_KEY_ACCEPT     (AVCSP_PP_BASE + 11)
#define PP_TOKEN_TYPE_CODE              (AVCSP_PP_BASE + 12)
#define PP_TOKEN_SERIAL_NUM_RAW         (AVCSP_PP_BASE + 13)
#define PP_TOKEN_SERIAL_NUM_STR         (AVCSP_PP_BASE + 14)

#define AVCSP_KP_BASE                   1000
#define KP_PARAMS_OID                   (AVCSP_KP_BASE + 1)
#define KP_PARAMS_OID_ENCODED_REF       (AVCSP_KP_BASE + 2)
#define KP_SIGN_LEN                     (AVCSP_KP_BASE + 3)
#define KP_PARAMS_VALUES_ENCODED        (AVCSP_KP_BASE + 4)
#define KP_SUBST_BLOCK_OID              (AVCSP_KP_BASE + 5)
#define KP_BDS_PRM_P                    (AVCSP_KP_BASE + 6)
#define KP_BDS_PRM_Q                    (AVCSP_KP_BASE + 7)
#define KP_BDS_PRM_A                    (AVCSP_KP_BASE + 8)
#define KP_BDS_PRM_R                    (AVCSP_KP_BASE + 9)
#define KP_BDS_PRM_L                    (AVCSP_KP_BASE + 10)
#define KP_BDS_PRM_H                    (AVCSP_KP_BASE + 11)
#define KP_PARAMS_VALUES_ENCODED_NMC    (AVCSP_KP_BASE + 12)

#define AVCSP_HP_BASE                   1000
#define HP_INIT_VECTOR                  (AVCSP_HP_BASE + 1)
#define HP_BHF_L                        (AVCSP_HP_BASE + 2)

#define AVCSPF_SIGN_FORCE_HASH          0x80000000

///////////////////////////////////////////////////////////////////////

#define AVCSP_PROXY_CONTEXT     "##AvCSP_2_RSA_Proxy##"


#endif //!defined(_AVCSPDEF_H_INCLUDED_)
