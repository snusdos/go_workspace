#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "getBasics.h"

// Init general fields 
char *serialNumber;
int lineBelow = 0;

// Init subject fields. If the fields are not found, we default
// these to an empty string.
char *subjectC = "";
char *subjectCN = "";
char *subjectO = "";
char *subjectOU = "";
char *subjectL = "";

// Init issuer fields
char *issuerC = "";
char *issuerCN = "";
char *issuerO = "";
char *issuerOU = "";
char *issuerL = "";

char *typeOfCert = "";
char *signatureAlgorithm = "";
char *publicKeyAlgorithm = "";
char *CRL = "";
char *OCSP = "";

char *notBefore = "";
char *notAfter = "";
char *validity = "";
char *keyLength = "";

int SCTcount = 0;

int main(int argc, char *argv[]) {
    // Exit program if no/more than 1 argument is passed
    if (argc != 2)
    {
        printf("Error: This program takes one file as argument.\n");
        return -1;
    }
    FILE *fp;
    fp = fopen(argv[1], "r");
    char line[2048]; // Assume no line is longer than 2048, should be OK...

    // Iterate through each line in the file and
    // extract desired fields.
    while (fgets(line, sizeof(line), fp)) {
        getSerialNumber(line);
        // Get all subject & issuer fields.
        // Remember to free line AFTER 
        // the last function is called.
        // (before getIssuer returns)
        for(int i = 0; i < FIELD_COUNT; i++) {
            enum Field f = i;
            getSubject(line, f);
            getIssuer(line, f);
        }
        getCertValidation(line);
        incrementSCT(line);
        getSignatureAlgorithm(line);
        getPublicKeyAlgorithm(line);
        getCRL(line);
        getOCSP(line);
        getValidity(line);
        getKeyLength(line);
    }
    printAllFields();
    return 0;
}

// This function will return the value on the line
// that matches the pattern. For example,
// getStrSameLine("OCSP - URI:http://ocsp.pki.goog/gts1o1core", "OCSP - URI:")
// will return http://ocsp.pki.goog/gts1o1core.
char *getStrSameLine(char *line, char *pattern) {

    // See if our current line patches the pattern. If true,
    // the entire line will be returned.
    char *matched_string = strstr(line, pattern);
    if (matched_string == NULL) {
        return NULL;
    }

    // For our starting index, we want to start where
    // the pattern isn't in the actual string.
    char *pattern_val = (char *) malloc(strlen(line) * sizeof(char));
    
    int pattern_len = 0;
    int start_index = matched_string - line + strlen(pattern);

    int quote = 0; // While quote == 1, we are inside of a quoted string.

    // From our starting index, we add each char 
    // and continue until we reach a newline or a comma (or null terminator).
    for (int i = start_index; i < strlen(line); i++) {      
        if (line[i] == '\n' || line[i] == '\0' || line[i] == ',') {
            if(quote == 1) {
                 pattern_val[pattern_len++] = line[i];
                 continue;
            }
            break;
        } else if (line[i])
        if (line[i] == '"') {
            quote++;
            if(quote == 1) {
                continue;
            } else if (quote == 2) {
                break;
            }
        } else {
            pattern_val[pattern_len++] = line[i];
        }
    }

    // Add null terminator at end of string, realloc then return string.
    pattern_val[pattern_len] = '\0';
    pattern_val = (char *) realloc(pattern_val, pattern_len * sizeof(char) +1);
    return pattern_val;
}

void getSerialNumber(char *line) {
    // If we haven't found the line containting
    // our pattern, we will look for it and then
    // set the flag to true.
    if (!lineBelow) {
        char *matched_string = strstr(line, "Serial Number:");
        if (matched_string == NULL) {
            return;
        }
        // Here, we check for the edge cases where
        // some certificates put their serial number on the same
        // line as well as both in decimal and hex.
        matched_string = strstr(line, "(");
        int atNumber = 0;

        // Here, we extract the number from the line.
        // Example line:
        // Serial Number: 4216700566239890036 (0x3a84bad2eeeaca74)
        // 4216700566239890036 will be extracted and saved into tempStr.
        if (matched_string != NULL) {
            char *tempStr = (char *) malloc(strlen(line) * sizeof(char) + 1);
            int counter = 0;
            for (int i = 0; i < strlen(line); i++) {
                if (line[i] == ':') {
                    atNumber = 1;
                } else if (line[i] == '(') {
                    atNumber = 0;
                } else if (atNumber && line[i] != ' ') {
                    tempStr[counter++] = line[i];
                }
            }
            tempStr[counter] = '\0';
            serialNumber = malloc(sizeof(char) * counter);
            strncpy(serialNumber, tempStr, counter);
            free(tempStr);
        } else {
            lineBelow = 1;
        }
    } else {
        // If the was set to true in the previous iteration,
        // we know that *line will we the correct string.
        // We set the flag to false and save output in main loop.
        // Offset of 12 because

        lineBelow = 0;

        // Ugly hack, for some files, a line with the
        // signature algorithm was included.
        char *matched_string = strstr(line, "Signature Algorithm:");
        char *tempStr = (char *) malloc(strlen(line) * sizeof(char) + 1);
        int counter = 0;
        if (matched_string == NULL) {
            for (int i = 12; i < strlen(line); i++) {
                if (line[i] != '\n' || line[i] != ' ') {
                    tempStr[counter++] = line[i];
                }
                if (line[i] == '\n' || line[i] == '\0')  {
                    break;
                }
            }
        }
        tempStr[counter-1] = '\0';
        serialNumber = malloc(sizeof(char) * counter);
        strncpy(serialNumber, tempStr, counter);
        free(tempStr);
    }
}

// This function will look for the field value
// for the Subject and assign it to the corresponding
// variable.
void getSubject(char* line, enum Field f) {
    // If the line does not sart with "Subject",
    // we are on the wrong line and return.
    char* matched_string = strstr(line, "Subject:");
    if(matched_string == NULL) {
        return;
    }

    // If we are on the correct line, we see if the corresponding
    // Field is present. 
     matched_string = getStrSameLine(line, fieldToString(f));
     if(matched_string == NULL) {
         return;
     }     
    copyToSubject(matched_string, f);
}

// This function is exactly the same as getSubject, except
// it looks for the Issuer fields.
void getIssuer(char* line, enum Field f) {
    char* matched_string = strstr(line, "Issuer:");
    if(matched_string == NULL) {
        return;
    }
    matched_string = getStrSameLine(line, fieldToString(f));
    if(matched_string == NULL) {
        return;
    }
    copyToIssuer(matched_string, f);
}

// Taken from the CA Browser forum: https://cabforum.org/object-registry/
// All CA:s don't use these policies however,
// so we won't get 100 % accuracy with these.
// These can also be found here https://docs.microsoft.com/en-us/security/trusted-root/program-requirements 
// on 3.A.10
void getCertValidation(char* line) {
    char* matched_string = strstr(line, "Policy: ");
    if(matched_string == NULL) {
        return;
    }

    matched_string = strstr(line, "2.23.140.1.2.1");
    if(matched_string != NULL) {
        typeOfCert = "DV";
        return;
    }

    matched_string = strstr(line, "2.23.140.1.2.2");
    if(matched_string != NULL) {
        typeOfCert = "OV";
    }

    matched_string = strstr(line, "2.23.140.1.1");
    if(matched_string != NULL) {
        typeOfCert = "EV";
    }

    matched_string = strstr(line, "2.23.140.1.2.3");
    if(matched_string != NULL) {
        typeOfCert = "IV";
    }
}

// If the cert contains a SCT, we increment our counter.
void incrementSCT(char *line) {
    char *matched_string = strstr(line, "Signed Certificate Timestamp:");
    if(matched_string !=  NULL) {
        SCTcount++;
    }
}

// This function sets the signature algorithm
// for the certificate.
void getSignatureAlgorithm(char *line) {
    // If we already found the field, don't
    // check for it again.
    if(strcmp(signatureAlgorithm, "") != 0) {
        return;
    }

    char *matched_string = getStrSameLine(line, "Signature Algorithm: ");
    if(matched_string == NULL) {
        return;
    }
    signatureAlgorithm = (char *) malloc(strlen(matched_string) + 1);
    strcpy(signatureAlgorithm, matched_string);
}

// This function sets the public key algorithm
// for the certificate.
void getPublicKeyAlgorithm(char *line) {
    char *matched_string = getStrSameLine(line, "Public Key Algorithm: ");
    if(matched_string == NULL) {
        return;
    }
    publicKeyAlgorithm = (char *) malloc(strlen(matched_string) + 1);
    strcpy(publicKeyAlgorithm, matched_string);
}

// Fetches the CRL URL for the certificate.
void getCRL(char *line) {
    char *matched_string = getStrSameLine(line, ".crl\n");
    if(matched_string == NULL) {
        return;
    }
    matched_string = getStrSameLine(line, "URI:");
    if(matched_string == NULL) {
        return;
    }
    CRL = (char *) malloc(strlen(matched_string) + 1);
    strcpy(CRL, matched_string);
}

void getOCSP(char *line) {
    char* matched_string = getStrSameLine(line, "OCSP - URI:");
    if(matched_string == NULL) {
        return;
    }
    OCSP = (char *) malloc(strlen(matched_string) + 1);
    strcpy(OCSP, matched_string);
}

// This function will get the validity period
// of the certificate in the following format:
// notBefore - notAfter, i.e.:
// Feb  4 13:54:57 2021 GMT - May  5 13:54:57 2021 GMT.
// We use two global variables, notBefore & notAfter.
// Since these always come in the same line order, we know
// that we are done when we find notAfter.
void getValidity(char *line) {
    // If we're on the line with the Not Before time, we save it 
    // and return.
    char* matched_string = getStrSameLine(line, "Not Before: ");
    if(matched_string != NULL) {
        notBefore = (char *) malloc(strlen(matched_string) + 1);
        strcpy(notBefore, matched_string);
    }

    matched_string = getStrSameLine(line, "Not After : ");

    // Here, we reach the Not After line and skip the return
    if(matched_string != NULL) {
        notAfter = (char *) malloc(strlen(matched_string) + 1);
        strcpy(notAfter, matched_string);
    } else {
        // If we're not on Not Before or Not After line, we simply return.
        return;
    }

    // We concat notBefore with ' - ', 3 extra chars.
    char *tempStr = (char *) malloc(strlen(notBefore) + 3 + strlen(notAfter));
    strcpy(tempStr, notBefore);
    tempStr[strlen(notBefore)] = ' ';
    tempStr[strlen(notBefore) + 1] = '-';
    tempStr[strlen(notBefore) + 2] = ' ';

    // We add the Not After time to our temporary notBefore string
    strcat(tempStr, notAfter);

    // Finally, we copy the temporary string to validity
    validity = (char *) malloc(strlen(tempStr) + 1);
    strcpy(validity, tempStr);
    free(tempStr);
}

// Get public key length
void getKeyLength(char *line) {
    char *matched_string = getStrSameLine(line, "Public-Key: (");
    if(matched_string == NULL) {
        return;
    }    

    char *tempStr = (char *) malloc(strlen(matched_string));
    int tempStrLen = 0;

    // We continue until we reach a ')'
    for(int i = 0; i < strlen(matched_string); i++) {
        if(matched_string[i] == ')'){
            break;
        }
        tempStr[tempStrLen++] = matched_string[i];
    }

    // We add a null terminator, malloc keyLength then 
    // copy over the string
    tempStr[tempStrLen] = '\0';
    keyLength = malloc(tempStrLen + 1);
    strcpy(keyLength, tempStr);
    free(tempStr);
    
}

// This function will copy the string
// to the corresponding variable for the Subject field.
void copyToSubject(char* line, enum Field f) {
    switch(f) {
        case country:
            subjectC = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(subjectC, line);
            break;
        case commonName:
            subjectCN = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(subjectCN, line);
            break;
        case locality:
            subjectL = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(subjectL, line);
            break;
        case organization:
            subjectO = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(subjectO, line);
            break;
        case organizationUnit:
            subjectOU = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(subjectOU, line);
            break;
    }
}

// This function will copy the string
// to the corresponding variable for the Issuer field.
void copyToIssuer(char* line, enum Field f) {
    switch(f) {
        case country:
            issuerC = (char *)  malloc(sizeof(char) * strlen(line) + 1);
            strcpy(issuerC, line);
            break;
        case commonName:
            issuerCN = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(issuerCN, line);
            break;
        case locality:
            issuerL = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(issuerL, line);
            break;
        case organization:
            issuerO = (char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(issuerO, line);
            break;
        case organizationUnit:
            issuerOU =(char *) malloc(sizeof(char) * strlen(line) + 1);
            strcpy(issuerOU, line);
            break;
    }
}

void printAllFields() {
    
   printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s",
    serialNumber, subjectC, subjectCN, subjectL, subjectO, subjectOU,
    issuerC, issuerCN, issuerL, issuerO, issuerOU, typeOfCert, SCTcount,
    signatureAlgorithm, publicKeyAlgorithm, CRL, OCSP, validity, keyLength);
    
}
