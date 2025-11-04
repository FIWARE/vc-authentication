# vc-authentication

The FIWARE Verifiable Credential Authentication (vc-authentication) is an integrated suite of components designed to facilitate authentication using Verifiable Credentials.

This repository provides a description of the FIWARE Verifiable Credential Authentication, its technical implementation and deployment recipes.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Overview](#overview)
- [Release Information](#release-information)
- [Components](#components)
- [Description of flows in vc-authentication](#description-of-flows-in-vc-authentication)
  - [Registration](#registration)
- [Deployment](#deployment)
  - [Local Deployment](#local-deployment)
  - [Deployment with Helm](#deployment-with-helm)
- [Testing](#testing)

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

![vc-authentication-components](doc/img/flows/components.png)

The main components of the FIWARE Verifiable Credential Authentication are:

| Component       | Role            | Link |
|-----------------|-----------------|------|
| VCVerifier      | Validates VCs and exchanges them for tokens | https://github.com/FIWARE/VCVerifier |
| credentials-config-service | Holds the information which VCs are required for accessing a service | https://github.com/FIWARE/credentials-config-service |
| trusted-issuers-list | Acts as Trusted Issuers List by providing an [EBSI Trusted Issuers Registry](https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry) API | https://github.com/FIWARE/trusted-issuers-list |

**Note,** that the FIWARE Verifiable Credential Authentication does not include a Verifiable Credential Issuer nor a Verifiable Credential Wallet. Regarding the SQL database, any SQL database technology could be used theoretically, but it has been tested with both MySQL and PostgreSQL.

## Description of flows in vc-authentication

This section details the key interaction patterns and workflows within the FIWARE Verifiable Credential Authentication.

### Registration

ToDo

## Deployment

### Local Deployment

The FIWARE Verifiable Credential Authentication provides a minimal local deployment setup intended for development and testing purposes.

The requirements for the local deployment are:
* [Maven](https://maven.apache.org/)
* Java Development Kit (at least v17)
* [Docker](https://www.docker.com/)
* [Helm](https://helm.sh/)
* [Helmfile](https://helmfile.readthedocs.io/en/latest/)

In order to interact with the system, the following tools are also helpful:
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [curl](https://curl.se/download.html)
- [jq](https://stedolan.github.io/jq/download/)
- [yq](https://mikefarah.gitbook.io/yq/)

> :warning: In current Linux installations, ```br_netfilter``` is disabled by default. That leads to networking issues inside the k3s cluster and will prevent the connector to start up properly. Make sure that its enabled via ```modprobe br_netfilter```. See [Stackoverflow](https://stackoverflow.com/questions/48148838/kube-dns-error-reply-from-unexpected-source/48151279#48151279) for more.

To start the deployment, just use:

```shell
    mvn clean deploy -Plocal
```

ToDo diagram of the deployment

### Deployment with Helm

The vc-authentication is a [Helm Umbrella-Chart](https://helm.sh/docs/howto/charts_tips_and_tricks/#complex-charts-with-many-dependencies), containing all the sub-charts of the different components and their dependencies. Its sources can be found 
[here](./charts/vc-authentication).

The chart is available at the repository ```https://fiware.github.io/vc-authentication/```. You can install it via:

```shell
    # add the repo
    helm repo add vc-authentication https://fiware.github.io/vc-authentication/
    # install the chart
    helm install <DeploymentName> vc-authentication/vc-authentication -n <Namespace> -f values.yaml
```
**Note,** that due to the app-of-apps structure of the deployment and the different dependencies between the components, a deployment without providing any configuration values will not work. Make sure to provide a 
`values.yaml` file for the deployment, specifying all necessary parameters. This includes setting parameters of the endpoints, DNS information (providing Ingress or OpenShift Route parameters), 
structure and type of the required VCs, internal hostnames of the different components and providing the configuration of the DID and keys/certs.

Configurations for all sub-charts (and sub-dependencies) can be managed through the top-level [values.yaml](./charts/vc-authentication/values.yaml) of the chart. It contains the default values of each component and additional parameter shared between the components. The configuration of the applications can be changed under the key ```<APPLICATION_NAME>```, please see the individual applications and there sub-charts for the available options.

The chart is [published and released](./github/workflows/release-helm.yaml) on each merge to master.

## Testing

In order to test the [helm-chart](./charts/vc-authentication) provided for the FIWARE Verifiable Credentials Authentication, an integration-test 
framework based on [Cucumber](https://cucumber.io/) and [Junit5](https://junit.org/junit5/) is provided: [it](./it).

The tests can be executed via: 
```shell
    mvn clean integration-test -Ptest
```
They will spin up the [Local Deployment](#local-deployment) and run 
the [test-scenarios](./it/src/test/resources/it/mvds_basic.feature) against it.