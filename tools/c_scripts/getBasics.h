char *getStrSameLine(char *line, char *pattern);
void getSerialNumber(char *line);
void getCertValidation(char *line);
void incrementSCT(char *line);
void getSignatureAlgorithm(char *line);
void getPublicKeyAlgorithm(char *line);
void getCRL(char *line);
void getOCSP(char *line);
void getValidity(char *line);
void getKeyLength(char *line);
void printAllFields();

enum Field {
    country,
    commonName,
    locality,
    organization,
    organizationUnit
};

const unsigned FIELD_COUNT = 5;

void getSubject(char* line, enum Field f);
void getIssuer(char* line, enum Field f);
void copyToSubject(char* line, enum Field f);
void copyToIssuer(char* line, enum Field f);


// Maps enum to array of corresponding string
static inline char* fieldToString(enum Field f) {
    static char* strings[] = {
        "C = ",
        "CN = ",
        "L = ",
        "O = ",
        "OU = "
    };

    return strings[f];
}
