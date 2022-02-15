/*! 
\mainpage 
Precise BioMatch Flex H Toolkit
\version 1.4.0
*/

/*! \file pb_flex_h.h
\brief 
BioMatch Flex H Header File
\details
Contains the definitions and functionality for Precise Biometrics BioMatch 
Flex H technology.
*/
#ifndef HEADER_PB_FLEX_H_H
#define HEADER_PB_FLEX_H_H

#include "pb_common.h"

#ifdef _WIN32
#undef PBCALL
#define PBCALL __cdecl
#else
#undef PBCALL
#define PBCALL
#endif

#ifdef __cplusplus
extern "C" {
#endif
    /*!
    \fn int PBCALL pb_fh_create_enrollment_data(const pb_image_t* image, int 
    far_level, unsigned char** reference_data, unsigned int* 
    reference_data_length, unsigned char** header_data, unsigned int* 
    header_data_length);
    \brief
    Creates reference data and header data for storage on card. 
    \details
    Used to create the enrollment data from a fingerprint image that is to be 
    stored on a smart card. Reference and header data needs to be freed with 
    pb_free() when they are no longer needed.
    \param[in] image 
    The image used to create enrollment data from.
    \param[in] far_level
    The requested maximum \ref FAR of future verifications. 
    \param[out] reference_data
    The newly created reference data.
    \param[out] reference_data_length
    Length of the reference data.
    \param[out] header_data
    The newly created header data.
    \param[out] header_data_length
    Length of the header data. 
    \retval 
    #PB_EOK if successful.
    \retval
    #PB_ETRIAL if trial validation was not successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_fh_create_enrollment_data(
        const pb_image_t* image, 
        int far_level,
        unsigned char** reference_data, 
        unsigned int* reference_data_length, 
        unsigned char** header_data, 
        unsigned int* header_data_length);

    /*!
    \fn int PBCALL pb_fh_create_verification_data(const pb_image_t* image, 
    const unsigned char* header_data, unsigned int header_data_length, 
    unsigned char** verification_data, unsigned int* 
    verification_data_length);
    \brief
    Creates verification data for match-on-card. 
    \details
    Used to create verification data from a fingerprint image that is to be 
    used for biometric matching on a BioMatch Flex H enabled smart card.
    Verification_data needs to be freed with pb_free() when it is no longer 
    needed.
    \param[in] image
    The image used to create verification data from. 
    \param[in] header_data
    The header data retrieved from the smart card. 
    \param[in] header_data_length
    Length of the header data. 
    \param[out] verification_data
    The newly created verification data. 
    \param[out] verification_data_length
    Length of the verification data. 
    \retval 
    #PB_EOK if successful.
    \retval
    #PB_ETRIAL if trial validation was not successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_fh_create_verification_data(
        const pb_image_t* image, 
        const unsigned char* header_data, 
        unsigned int header_data_length, 
        unsigned char** verification_data, 
        unsigned int* verification_data_length);

    /*!
    \fn int PBCALL pb_fh_validate_template(const pb_image_t* image, 
    const unsigned char* header_data, unsigned int header_data_length, 
    const unsigned char* reference_data, unsigned int reference_data_length, 
    int* validated);
    \brief
    Validates the quality of an image relative to a MoC BioMatch Flex H 
    template. 
    \details
    This function can be used to validate enrollment data against an image 
    before it is stored on the smart card. 
    \param[in] image
    The image to compare with the MoC template. 
    \param[in] header_data
    Header data from previous call to pb_fh_create_enrollment_data().
    \param[in] header_data_length
    Length of header data
    \param[in] reference_data
    Reference data from previous call to pb_fh_create_enrollment_data().
    \param[in] reference_data_length
    Length of reference data. 
    \param[out] validated
    Validation flag. #PB_TRUE if the image quality is good enough relative to 
    the template, #PB_FALSE otherwise.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_fh_validate_template(
        const pb_image_t* image, 
        const unsigned char* header_data, 
        unsigned int header_data_length, 
        const unsigned char* reference_data, 
        unsigned int reference_data_length, 
        int* validated);

#ifdef __cplusplus
}
#endif

#endif
