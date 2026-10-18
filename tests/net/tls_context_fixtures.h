/* Public, deliberately non-secret test keys; never use outside tests. */
#ifndef VIREO_TEST_TLS_CONTEXT_FIXTURES_H
#define VIREO_TEST_TLS_CONTEXT_FIXTURES_H

static unsigned char const fixture_leaf[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByjCCAW+gAwIBAgICDUkwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTVmlyZW8t\n"
    "MDM0LXRlc3Qtcm9vdDAeFw0yNjEwMTUxOTMxMThaFw0zNjEwMTIxOTMxMThaMCEx\n"
    "HzAdBgNVBAMMFnZpcmVvLTAzNC10ZXN0LmludmFsaWQwWTATBgcqhkjOPQIBBggq\n"
    "hkjOPQMBBwNCAASitJaSpnw7iGilijnykNxSdBPi74cBYNIgHaWU67ed25oJasOi\n"
    "NUH92h8T2Fy+Ec44nQPi82EhB9y6W0Veszaoo4GZMIGWMAwGA1UdEwEB/wQCMAAw\n"
    "DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCEGA1UdEQQaMBiC\n"
    "FnZpcmVvLTAzNC10ZXN0LmludmFsaWQwHQYDVR0OBBYEFJGZbFR7impkRw9ML9TV\n"
    "ourSzfncMB8GA1UdIwQYMBaAFLZh/xhS1ZDD3OwZnbYBRh/R0+0vMAoGCCqGSM49\n"
    "BAMCA0kAMEYCIQCD+171VwbT79dwJWbuNmeJQeSQ4NJ4tgu5deIweBD9UwIhANij\n"
    "1huB9n8KYdahI1Efj6UNXDZWlaSZq7tFviMzqyZY\n"
    "-----END CERTIFICATE-----\n";

static unsigned char const fixture_root[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCCATegAwIBAgIUTc4kgYPI8nYPbYilGSqzRtabFhgwCgYIKoZIzj0EAwIw\n"
    "HjEcMBoGA1UEAwwTVmlyZW8tMDM0LXRlc3Qtcm9vdDAeFw0yNjEwMTUxOTMxMTha\n"
    "Fw0zNjEwMTIxOTMxMThaMB4xHDAaBgNVBAMME1ZpcmVvLTAzNC10ZXN0LXJvb3Qw\n"
    "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThwOumoh03I9G0/tsDGlhtw5uPndj3\n"
    "4d8n6WWLusccnviqXyVZiD6wqin5xQvEYbKOVkeDfVXhIYAq7SY9JXLUo1MwUTAd\n"
    "BgNVHQ4EFgQUtmH/GFLVkMPc7BmdtgFGH9HT7S8wHwYDVR0jBBgwFoAUtmH/GFLV\n"
    "kMPc7BmdtgFGH9HT7S8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF\n"
    "AiEAnw/q0s5LbilPAz6KzqCx9MBzS1nLg1Qat2BWvml/6mMCICVunmnlAoXAKiHM\n"
    "tlKHzr4jMUYTlFXrJqaydJoOyaq6\n"
    "-----END CERTIFICATE-----\n";

static unsigned char const fixture_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK6/ZuHk663RNm/K0\n"
    "bgJtFZNPfk0Zjm6LsQ0NEx+plKuhRANCAASitJaSpnw7iGilijnykNxSdBPi74cB\n"
    "YNIgHaWU67ed25oJasOiNUH92h8T2Fy+Ec44nQPi82EhB9y6W0Veszao\n"
    "-----END PRIVATE KEY-----\n";

static unsigned char const fixture_other_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcnhJYCNbGfGpj11x\n"
    "kZh+L0MqU9KkPSwpT93LHkR9poehRANCAAT2hdJr7vhpH1NaiYxaXTdzU2ELy519\n"
    "+BkCTxUnJgomlc+6c7wK98iGhAa+jp0mxzUUyfBBmaR+7y0u+/5tMWeE\n"
    "-----END PRIVATE KEY-----\n";

static unsigned char const fixture_encrypted_key[] =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAg9icgwdUV4lgICCAAw\n"
    "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEFRmWFTb7MkpIlpuA3cajUwEgZBS\n"
    "piWRgo//qSlCdD9JbG+vzau53IO4eU9JdwvRKc2H/LIDC2ayJwU+HA9vVkVnUR53\n"
    "Yd2m2b04PWdsbZG4fthxOaKf93pI1VZ31wZfGa71aqDXdGM3ZZbQ6NTq1sUUswgO\n"
    "9V/3dkZowEuozXjChwAcCauoKUDJkneszLiY/2bivwL2Ao2KB1Rml3ucgClsL20=\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

static unsigned char const fixture_traditional_encrypted_key[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-256-CBC,21B9D8124EAF2A4E16089755016FA2D8\n"
    "\n"
    "1KwILn02KsBF9iKytFDe6x7TK3RQC0LbUgXiO8JNDW3drf3nn1QQCM90R9JgRKQz\n"
    "FZziiR0hnznV7Z5OeXk72FWb7Y749m51Ct1OrA0RF2CCqxb12twNaBxhLq//mCyD\n"
    "RqY4+tBYxbfMdfn2GgyMsr4xGFg4Z6a4syT6O7zHxPk=\n"
    "-----END EC PRIVATE KEY-----\n";

#endif
