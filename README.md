# vc-authentication

The FIWARE Verifiable Credential Authentication (vc-authentication) is an integrated suite of components designed to facilitate authentication using Verifiable Credentials.

This repository provides a description of the FIWARE Verifiable Credential Authentication, its technical implementation and deployment recipes.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Overview](#overview)
- [Release Information](#release-information)
- [Components](#components)
- [Description of flows](#description-of-flows)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Overview
The FIWARE Verifiable Credential Authentication solution enables secure and decentralized authentication mechanisms by leveraging Verifiable Credentials (VCs). It allows users to authenticate themselves using cryptographic proofs, enhancing security and privacy in digital interactions. It allows to:
* Interface with Trust Services aligned with [EBSI specifications](https://api-pilot.ebsi.eu/docs/apis)
* Implement authentication based on [W3C DID](https://www.w3.org/TR/did-core/) with 
  [VC/VP standards](https://www.w3.org/TR/vc-data-model/) and 
  [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-cross-device-self-issued-op) / 
  [OIDC4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#request_scope) protocols

Technically, the FIWARE Verifiable Credential Authentication is a 
[Helm Umbrella-Chart](https://helm.sh/docs/howto/charts_tips_and_tricks/#complex-charts-with-many-dependencies), 
containing all the sub-charts and their dependencies for deployment via Helm.  
Thus, being provided as Helm chart, the FIWARE Verifiable Credential Authentication can be deployed on 
[Kubernetes](https://kubernetes.io/) environments.

## Release Information

ToDo

## Components

The following diagram shows a logical overview of the different components of the FIWARE Verifiable Credential Authentication.

![connector-components](doc/img/flows/components.png)

The main components of the FIWARE Verifiable Credential Authentication are:

| Component       | Role            | Link |
|-----------------|-----------------|------|
| VCVerifier      | Validates VCs and exchanges them for tokens | https://github.com/FIWARE/VCVerifier |
| credentials-config-service | Holds the information which VCs are required for accessing a service | https://github.com/FIWARE/credentials-config-service |
| trusted-issuers-list | Acts as Trusted Issuers List by providing an [EBSI Trusted Issuers Registry](https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry) API | https://github.com/FIWARE/trusted-issuers-list |

**Note,** that the FIWARE Verifiable Credential Authentication does not include a Verifiable Credential Issuer nor a Verifiable Credential Wallet. Regarding the SQL database, any SQL database technology could be used theoretically, but it has been tested with both MySQL and PostgreSQL.

## Description of flows