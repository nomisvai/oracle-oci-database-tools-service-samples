# oracle-oci-database-tools-service-samples

This repository contains code snippets presented
as [unit tests](src/test/java/nomisvai/TestSamples.java) demonstrating how to use the new Oracle
Cloud [Database Tools Service](https://docs.oracle.com/en-us/iaas/Content/Database-Tools/dbtools_topic-overview.htm)
with java.

The Database Tools Service allows the use of a
[Rest Enabled SQL Service](https://docs.oracle.com/en/database/oracle/oracle-rest-data-services/21.3/aelig/rest-enabled-sql-service.html)
endpoint with pre-defined Connections that leverage the OCI Vault, Private Endpoints and OCI based
access control and policies.

In other words, a Database Tools Connection will allow SQL statements to be sent securely to your
database from any host using
an [OCI Identity](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/overview.htm). The
Database Tools Service is also integrated
with [Private Endpoints](https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/security-restrict-private-endpoint.html)
which allows it to reach databases in private subnets.

## Features In This Demo

The File [TestSamples.java](src/test/java/nomisvai/TestSamples.java) has 5 ordered tests:

* Download a wallet from an Autonomous Databased Shared and uploads its cwallet.sso and password to
  an oci vault
* Create a Database Tools Private Endpoint if the ADB-S requires it.
* Create a Database Tools Connection
* Validates the Database Tools Connection
* Executes an SQL statement on the database using the Database Tools Service REST-Enabled SQL
  endpoint

All resources(Secrets, Private Endpoint, Database Tools Connection) will be created in the same
compartment as the database and their ids, once created, can be found in the
testconfig/resource.properties file.

## Setting up the environment

1. Create
   an [Autonomous Database Shared](https://docs.oracle.com/en-us/iaas/Content/Database/Tasks/adbcreating.htm)
1. Create
   a [Vault](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/managingvaults.htm)
1. Setup [oci cli](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/cliconcepts.htm), the
   tests require a valid profile in
   the [oci config file](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File)
   with the proper permissions to perform all the operations.

1. When oci cli is working, edit testconfig/config.properties and provide:
    * The created Autonomous Database Shared Id
    * The created Vault Id
    * An oci config profile name that has all the necessary access to the database compartment which
      is used by the tests for all resources.
    * A DB User and password (the password will be added as a secret in the Vault)

## How to run

```
mvn clean install
```

And look at the  "T E S T S" output.
