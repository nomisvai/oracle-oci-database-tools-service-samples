package nomisvai;

import com.google.common.base.Strings;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.database.DatabaseClient;
import com.oracle.bmc.database.model.AutonomousDatabase;
import com.oracle.bmc.database.model.DatabaseConnectionStringProfile;
import com.oracle.bmc.database.model.GenerateAutonomousDatabaseWalletDetails;
import com.oracle.bmc.database.requests.GenerateAutonomousDatabaseWalletRequest;
import com.oracle.bmc.database.requests.GetAutonomousDatabaseRequest;
import com.oracle.bmc.database.responses.GenerateAutonomousDatabaseWalletResponse;
import com.oracle.bmc.database.responses.GetAutonomousDatabaseResponse;
import com.oracle.bmc.databasetools.DatabaseToolsClient;
import com.oracle.bmc.databasetools.model.CreateDatabaseToolsConnectionOracleDatabaseDetails;
import com.oracle.bmc.databasetools.model.CreateDatabaseToolsPrivateEndpointDetails;
import com.oracle.bmc.databasetools.model.DatabaseToolsKeyStoreContentSecretIdDetails;
import com.oracle.bmc.databasetools.model.DatabaseToolsKeyStoreDetails;
import com.oracle.bmc.databasetools.model.DatabaseToolsUserPasswordSecretIdDetails;
import com.oracle.bmc.databasetools.model.KeyStoreType;
import com.oracle.bmc.databasetools.model.LifecycleState;
import com.oracle.bmc.databasetools.model.ValidateDatabaseToolsConnectionOracleDatabaseDetails;
import com.oracle.bmc.databasetools.requests.CreateDatabaseToolsConnectionRequest;
import com.oracle.bmc.databasetools.requests.CreateDatabaseToolsPrivateEndpointRequest;
import com.oracle.bmc.databasetools.requests.GetDatabaseToolsConnectionRequest;
import com.oracle.bmc.databasetools.requests.GetDatabaseToolsPrivateEndpointRequest;
import com.oracle.bmc.databasetools.requests.ListDatabaseToolsEndpointServicesRequest;
import com.oracle.bmc.databasetools.requests.ValidateDatabaseToolsConnectionRequest;
import com.oracle.bmc.databasetools.responses.CreateDatabaseToolsConnectionResponse;
import com.oracle.bmc.databasetools.responses.CreateDatabaseToolsPrivateEndpointResponse;
import com.oracle.bmc.databasetools.responses.GetDatabaseToolsConnectionResponse;
import com.oracle.bmc.databasetools.responses.GetDatabaseToolsPrivateEndpointResponse;
import com.oracle.bmc.databasetools.responses.ValidateDatabaseToolsConnectionResponse;
import com.oracle.bmc.http.internal.ResponseHelper;
import com.oracle.bmc.http.signing.RequestSigningFilter;
import com.oracle.bmc.keymanagement.KmsManagementClient;
import com.oracle.bmc.keymanagement.KmsVaultClient;
import com.oracle.bmc.keymanagement.model.Vault;
import com.oracle.bmc.keymanagement.requests.GetVaultRequest;
import com.oracle.bmc.keymanagement.requests.ListKeysRequest;
import com.oracle.bmc.secrets.SecretsClient;
import com.oracle.bmc.secrets.requests.GetSecretBundleByNameRequest;
import com.oracle.bmc.secrets.responses.GetSecretBundleByNameResponse;
import com.oracle.bmc.vault.VaultsClient;
import com.oracle.bmc.vault.model.Base64SecretContentDetails;
import com.oracle.bmc.vault.model.CreateSecretDetails;
import com.oracle.bmc.vault.model.Secret;
import com.oracle.bmc.vault.requests.CreateSecretRequest;
import com.oracle.bmc.vault.requests.GetSecretRequest;
import com.oracle.bmc.vault.responses.CreateSecretResponse;
import com.oracle.bmc.vault.responses.GetSecretResponse;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
public class TestSamples {
    private static String autonomousDatabaseId = null;
    private static String vaultId = null;
    private static String dbPassword = null;
    private static String dbUser = null;
    private static String ociProfile = null;
    private static String testStatement = null;
    private static String walletSecretName = null;
    private static String passwordSecretName = null;

    private static String dbPasswordSecretId = "";
    private static String dbWalletSecretId = "";
    private static String dbtoolsConnectionId = "";
    private static String dbtoolsPrivateEndpointId = "";
    private static String defaultCompartmentId = null;
    private static String vaultKeyId = null;

    private static DatabaseClient databaseClient = null;
    private static DatabaseToolsClient databaseToolsClient = null;
    private static KmsVaultClient kmsVaultClient = null;
    private static SecretsClient secretsClient = null;
    private static VaultsClient vaultsClient = null;
    private static boolean mtlsConnectionRequired = true;

    private static AutonomousDatabase autonomousDatabase;
    private static String ordsEndpoint = null;
    private static Client ordsClient = null;

    @BeforeAll
    @SneakyThrows
    public static void init() {
        try (FileInputStream fileInputStream =
                new FileInputStream(System.getProperty("testconfigdir") + "/config.properties")) {
            Properties properties = new Properties();
            properties.load(fileInputStream);
            autonomousDatabaseId = properties.getProperty("autonomousDatabaseId");
            ociProfile = properties.getProperty("ociProfile");
            vaultId = properties.getProperty("vaultId");
            dbUser = properties.getProperty("dbUser");
            dbPassword = properties.getProperty("dbPassword");
            testStatement = properties.getProperty("testStatement");
            walletSecretName = properties.getProperty("walletSecretName");
            passwordSecretName = properties.getProperty("passwordSecretName");
            try {
                mtlsConnectionRequired =
                        Boolean.parseBoolean(properties.getProperty("mtlsConnectionRequired"));
            } catch (RuntimeException e) {
                log.info(
                        "Could not parse property mtlsConnectionRequired, setting to true. {}",
                        "" + e);
                mtlsConnectionRequired = true;
            }

            databaseClient =
                    DatabaseClient.builder()
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));
            databaseToolsClient =
                    DatabaseToolsClient.builder()
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));
            secretsClient =
                    SecretsClient.builder()
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));
            kmsVaultClient =
                    KmsVaultClient.builder()
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));

            vaultsClient =
                    VaultsClient.builder()
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));

            // Deduct the ords endpoint from the dbtools endpoint
            ordsEndpoint = databaseToolsClient.getEndpoint().replace("https://", "https://sql.");
            System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
            ordsClient =
                    ClientBuilder.newBuilder()
                            .build()
                            .register(
                                    RequestSigningFilter.fromAuthProvider(
                                            new ConfigFileAuthenticationDetailsProvider(
                                                    ociProfile)));

        } catch (IOException e) {
            log.error("init error", e);
            throw e;
        }

        try (FileInputStream fileInputStream =
                new FileInputStream(
                        System.getProperty("testconfigdir") + "/resources.properties")) {
            Properties properties = new Properties();
            properties.load(fileInputStream);
            dbPasswordSecretId = properties.getProperty("dbPasswordSecretId");
            dbWalletSecretId = properties.getProperty("dbWalletSecretId");
            dbtoolsPrivateEndpointId = properties.getProperty("dbtoolsPrivateEndpointId");
            dbtoolsConnectionId = properties.getProperty("dbtoolsConnectionId");
        } catch (FileNotFoundException fnfe) {
            // expected
        } catch (IOException e) {
            log.error("init error", e);
            throw e;
        }
    }

    @AfterAll
    @SneakyThrows
    public static void cleanUp() {
        try (FileOutputStream fileOutputStream =
                new FileOutputStream(
                        System.getProperty("testconfigdir") + "/resources.properties")) {
            Properties properties = new Properties();
            properties.store(fileOutputStream, null);
            properties.setProperty("dbPasswordSecretId", dbPasswordSecretId);
            properties.setProperty("dbWalletSecretId", dbWalletSecretId);
            properties.setProperty("dbtoolsPrivateEndpointId", dbtoolsPrivateEndpointId);
            properties.setProperty("dbtoolsConnectionId", dbtoolsConnectionId);
            properties.store(fileOutputStream, null);
        } catch (IOException e) {
            log.error("cleanUp error", e);
            throw e;
        }
    }

    /**
     * Stores a base64 encoded secret in a vault and returns the created secretId, if a secret with
     * the specified name already exists, the id of the existing secret will be returned.
     */
    @SneakyThrows
    private String createSecret(String name, String base64Secret) {
        if (vaultKeyId == null) {
            log.info("Retrieving the vault {} key to create secrets...", vaultId);
            Vault vault =
                    kmsVaultClient
                            .getVault(GetVaultRequest.builder().vaultId(vaultId).build())
                            .getVault();
            log.info("Vault {} management endpoint is {}", vaultId, vault.getManagementEndpoint());
            KmsManagementClient kmsManagementClient =
                    KmsManagementClient.builder()
                            .vault(vault)
                            .build(new ConfigFileAuthenticationDetailsProvider(ociProfile));
            // This will only work if the key is in the same compartment as the vault, which is
            // usually the case
            vaultKeyId =
                    kmsManagementClient
                            .listKeys(
                                    ListKeysRequest.builder()
                                            .compartmentId(vault.getCompartmentId())
                                            .build())
                            .getItems()
                            .iterator()
                            .next()
                            .getId();
            log.info("Vault {} key id is {}", vaultId, vaultKeyId);
        }

        try {
            log.info("Trying to read the secret by name before creating it...");
            GetSecretBundleByNameResponse getSecretBundleByNameResponse =
                    secretsClient.getSecretBundleByName(
                            GetSecretBundleByNameRequest.builder()
                                    .secretName(name)
                                    .vaultId(vaultId)
                                    .stage(GetSecretBundleByNameRequest.Stage.Current)
                                    .build());
            log.warn(
                    "Secret with name {} found! It will be used instead, secret id: {}",
                    name,
                    getSecretBundleByNameResponse.getSecretBundle().getSecretId());
            return getSecretBundleByNameResponse.getSecretBundle().getSecretId();
        } catch (Exception e) {
            log.info("Secret with name {} not found, it will be created...", name);
        }

        CreateSecretResponse createSecretResponse =
                vaultsClient.createSecret(
                        CreateSecretRequest.builder()
                                .createSecretDetails(
                                        CreateSecretDetails.builder()
                                                .vaultId(vaultId)
                                                .keyId(vaultKeyId)
                                                .compartmentId(defaultCompartmentId)
                                                .secretName(name)
                                                .secretContent(
                                                        Base64SecretContentDetails.builder()
                                                                .content(base64Secret)
                                                                .build())
                                                .build())
                                .build());
        log.info(
                "Created secret {}, id {}, waiting for secret to become Available",
                name,
                createSecretResponse.getSecret().getId());

        GetSecretResponse secretResponse =
                vaultsClient.getSecret(
                        GetSecretRequest.builder()
                                .secretId(createSecretResponse.getSecret().getId())
                                .build());
        while (secretResponse.getSecret().getLifecycleState() != Secret.LifecycleState.Active) {
            if (secretResponse.getSecret().getLifecycleState() == Secret.LifecycleState.Failed) {
                throw new RuntimeException(
                        "Secret lifecycle state is unexpected "
                                + secretResponse.getSecret().getLifecycleState());
            }
            log.info(
                    "Waiting for secret {} to be available, current state = {} (It can take a few minutes)...",
                    secretResponse.getSecret().getId(),
                    secretResponse.getSecret().getLifecycleState());
            Thread.sleep(1500);
            secretResponse =
                    vaultsClient.getSecret(
                            GetSecretRequest.builder()
                                    .secretId(createSecretResponse.getSecret().getId())
                                    .build());
        }
        log.info("Secret {} is active!", secretResponse.getSecret().getId());
        return secretResponse.getSecret().getId();
    }

    @Order(1)
    @Test
    @SneakyThrows
    public void getWalletAndCreateSecrets() {
        log.info("Getting Database {} info...", autonomousDatabaseId);
        GetAutonomousDatabaseResponse response =
                databaseClient.getAutonomousDatabase(
                        GetAutonomousDatabaseRequest.builder()
                                .autonomousDatabaseId(autonomousDatabaseId)
                                .build());
        autonomousDatabase = response.getAutonomousDatabase();
        log.info("Database privateEndpoint: {}", autonomousDatabase.getPrivateEndpoint());
        log.info("Database privateEndpointIp: {}", autonomousDatabase.getPrivateEndpointIp());
        log.info("Database compartmentId: {}", autonomousDatabase.getCompartmentId());

        // We will use the db compartment for all operations
        defaultCompartmentId = autonomousDatabase.getCompartmentId();

        if (!Strings.isNullOrEmpty(dbWalletSecretId)) {
            log.info("Wallet secret id {} will be used", dbWalletSecretId);
        } else {
            log.info("Getting Database {} wallet...", autonomousDatabaseId);
            ResponseHelper.shouldAutoCloseResponseInputStream(false);
            GenerateAutonomousDatabaseWalletResponse walletResponse =
                    databaseClient.generateAutonomousDatabaseWallet(
                            GenerateAutonomousDatabaseWalletRequest.builder()
                                    .autonomousDatabaseId(autonomousDatabaseId)
                                    .generateAutonomousDatabaseWalletDetails(
                                            GenerateAutonomousDatabaseWalletDetails.builder()
                                                    .password("Welcome1")
                                                    .build())
                                    .build());
            log.info("Uploading cwallet.sso to the vault...");

            // first extract the file from the wallet zip
            ByteArrayOutputStream walletOut = null;
            try (ZipInputStream zis = new ZipInputStream(walletResponse.getInputStream())) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.getName().equals("cwallet.sso")) {
                        walletOut = new ByteArrayOutputStream();
                        IOUtils.copy(zis, walletOut);
                        break;
                    }
                }
            }
            if (walletOut == null) {
                throw new RuntimeException("cwallet.sso was not found in wallet zip file!");
            }

            // create secret in vault
            dbWalletSecretId =
                    createSecret(
                            walletSecretName,
                            Base64.getEncoder().encodeToString(walletOut.toByteArray()));
        }

        if (!Strings.isNullOrEmpty(dbPasswordSecretId)) {
            log.info("Password secret id {} will be used", dbPasswordSecretId);
        } else {
            dbPasswordSecretId =
                    createSecret(
                            passwordSecretName,
                            Base64.getEncoder()
                                    .encodeToString(dbPassword.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Order(2)
    @Test
    @SneakyThrows
    public void createPrivateEndpoint() {
        if (Strings.isNullOrEmpty(autonomousDatabase.getPrivateEndpoint())) {
            log.info("The specified autonomous database does not require private endpoint access.");
            return;
        }

        if (!Strings.isNullOrEmpty(dbtoolsPrivateEndpointId)) {
            log.info("Re-using private endpoint {}", dbtoolsPrivateEndpointId);
            return;
        }

        String endpointServiceId =
                databaseToolsClient
                        .listDatabaseToolsEndpointServices(
                                ListDatabaseToolsEndpointServicesRequest.builder()
                                        .compartmentId(defaultCompartmentId)
                                        .name("DATABASE_TOOLS")
                                        .build())
                        .getDatabaseToolsEndpointServiceCollection()
                        .getItems()
                        .get(0)
                        .getId();

        CreateDatabaseToolsPrivateEndpointResponse createPrivateEndpointResponse =
                databaseToolsClient.createDatabaseToolsPrivateEndpoint(
                        CreateDatabaseToolsPrivateEndpointRequest.builder()
                                .createDatabaseToolsPrivateEndpointDetails(
                                        CreateDatabaseToolsPrivateEndpointDetails.builder()
                                                .compartmentId(defaultCompartmentId)
                                                .endpointServiceId(endpointServiceId)
                                                .subnetId(autonomousDatabase.getSubnetId())
                                                .displayName(
                                                        "test-sample-pe-"
                                                                + System.currentTimeMillis())
                                                .build())
                                .build());

        String peId = createPrivateEndpointResponse.getDatabaseToolsPrivateEndpoint().getId();
        GetDatabaseToolsPrivateEndpointResponse getPrivateEndpointResponse = null;
        do {
            if (getPrivateEndpointResponse != null) {
                log.info("Waiting for private endpoint {} creation to complete...", peId);
                Thread.sleep(5000);
            }
            getPrivateEndpointResponse =
                    databaseToolsClient.getDatabaseToolsPrivateEndpoint(
                            GetDatabaseToolsPrivateEndpointRequest.builder()
                                    .databaseToolsPrivateEndpointId(peId)
                                    .build());
            if (getPrivateEndpointResponse.getDatabaseToolsPrivateEndpoint().getLifecycleState()
                    == LifecycleState.Failed) {
                throw new RuntimeException(
                        String.format(
                                "Could not create private endpoint %s %s",
                                peId,
                                getPrivateEndpointResponse
                                        .getDatabaseToolsPrivateEndpoint()
                                        .getLifecycleDetails()));
            }

        } while (getPrivateEndpointResponse.getDatabaseToolsPrivateEndpoint().getLifecycleState()
                != LifecycleState.Active);
        dbtoolsPrivateEndpointId = peId;
        log.info("Private endpoint {} created successfully!", peId);
    }

    @Order(3)
    @Test
    @SneakyThrows
    public void createConnection() {
        if (!Strings.isNullOrEmpty(dbtoolsConnectionId)) {
            log.info("Re-using connection {}", dbtoolsConnectionId);
            return;
        }

        CreateDatabaseToolsConnectionRequest createDatabaseToolsConnectionRequest;
        log.info("Creating a database tools connection...");
        // Get the mTls low connection string
        String connectionString =
                autonomousDatabase.getConnectionStrings().getProfiles().stream()
                        .filter(
                                p ->
                                        p.getTlsAuthentication()
                                                        .equals(
                                                                DatabaseConnectionStringProfile
                                                                        .TlsAuthentication.Mutual)
                                                && p.getConsumerGroup()
                                                        .equals(
                                                                DatabaseConnectionStringProfile
                                                                        .ConsumerGroup.Low))
                        .collect(Collectors.toList())
                        .iterator()
                        .next()
                        .getValue();

        List<DatabaseToolsKeyStoreDetails> keyStores =
                Collections.singletonList(
                        DatabaseToolsKeyStoreDetails.builder()
                                .keyStoreType(KeyStoreType.Sso)
                                .keyStoreContent(
                                        DatabaseToolsKeyStoreContentSecretIdDetails.builder()
                                                .secretId(dbWalletSecretId)
                                                .build())
                                .build());

        // If mtlsConnectionRequired is false, use the non mtls connection string and set the
        // keystore to null
        if (!mtlsConnectionRequired && !autonomousDatabase.getIsMtlsConnectionRequired()) {
            log.info("Using non mtls connection string.");
            connectionString =
                    autonomousDatabase.getConnectionStrings().getProfiles().stream()
                            .filter(
                                    p ->
                                            p.getTlsAuthentication()
                                                            .equals(
                                                                    DatabaseConnectionStringProfile
                                                                            .TlsAuthentication
                                                                            .Server)
                                                    && p.getConsumerGroup()
                                                            .equals(
                                                                    DatabaseConnectionStringProfile
                                                                            .ConsumerGroup.Low))
                            .collect(Collectors.toList())
                            .iterator()
                            .next()
                            .getValue();
            keyStores = null;
        }

        CreateDatabaseToolsConnectionOracleDatabaseDetails.Builder
                createDatabaseToolsConnectionOracleDatabaseDetailsBuilder =
                        CreateDatabaseToolsConnectionOracleDatabaseDetails.builder()
                                .compartmentId(defaultCompartmentId)
                                .connectionString(connectionString)
                                .displayName("test-sample-connection-" + System.currentTimeMillis())
                                .userName(dbUser)
                                .userPassword(
                                        DatabaseToolsUserPasswordSecretIdDetails.builder()
                                                .secretId(dbPasswordSecretId)
                                                .build())
                                .keyStores(keyStores);

        if (dbtoolsPrivateEndpointId != null) {
            createDatabaseToolsConnectionOracleDatabaseDetailsBuilder.privateEndpointId(
                    dbtoolsPrivateEndpointId);
        }

        createDatabaseToolsConnectionRequest =
                CreateDatabaseToolsConnectionRequest.builder()
                        .createDatabaseToolsConnectionDetails(
                                createDatabaseToolsConnectionOracleDatabaseDetailsBuilder.build())
                        .build();
        CreateDatabaseToolsConnectionResponse createDatabaseToolsConnectionResponse =
                databaseToolsClient.createDatabaseToolsConnection(
                        createDatabaseToolsConnectionRequest);
        String connectionId =
                createDatabaseToolsConnectionResponse.getDatabaseToolsConnection().getId();
        GetDatabaseToolsConnectionResponse getConnectionResponse = null;

        do {
            if (getConnectionResponse != null) {
                log.info("Waiting for connection {} creation to complete...", connectionId);
                Thread.sleep(5000);
            }
            getConnectionResponse =
                    databaseToolsClient.getDatabaseToolsConnection(
                            GetDatabaseToolsConnectionRequest.builder()
                                    .databaseToolsConnectionId(connectionId)
                                    .build());
            if (getConnectionResponse.getDatabaseToolsConnection().getLifecycleState()
                    == LifecycleState.Failed) {
                throw new RuntimeException(
                        String.format(
                                "Could not create connection %s %s",
                                connectionId,
                                getConnectionResponse
                                        .getDatabaseToolsConnection()
                                        .getLifecycleDetails()));
            }

        } while (getConnectionResponse.getDatabaseToolsConnection().getLifecycleState()
                != LifecycleState.Active);
        dbtoolsConnectionId = connectionId;
        log.info("Connection {} created successfully!", connectionId);
    }

    @Order(4)
    @Test
    public void validateConnection() {
        log.info("Validating Database Tools Connection {}", dbtoolsConnectionId);
        ValidateDatabaseToolsConnectionResponse response =
                databaseToolsClient.validateDatabaseToolsConnection(
                        ValidateDatabaseToolsConnectionRequest.builder()
                                .databaseToolsConnectionId(dbtoolsConnectionId)
                                .validateDatabaseToolsConnectionDetails(
                                        ValidateDatabaseToolsConnectionOracleDatabaseDetails
                                                .builder()
                                                .build())
                                .build());
        log.info(
                "validateDatabaseToolsConnection result {}",
                response.getValidateDatabaseToolsConnectionResult());
        Assertions.assertEquals(
                "OK", response.getValidateDatabaseToolsConnectionResult().getCode());
    }

    @Order(5)
    @Test
    public void executeSqlStatement() {
        log.info("Executing sql statement on connection {}", dbtoolsConnectionId);
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
        final Entity<String> body = Entity.entity(testStatement, "application/sql");

        // There is no oci sdk to call the ords data-plane endpoint of the database tools service,
        // the documentation of this endpoint
        // is pretty much the same as the one for the REST-Enabled SQL Service:
        // https://docs.oracle.com/en/database/oracle/oracle-rest-data-services/21.3/aelig/rest-enabled-sql-service.html
        // The difference is that the endpoint is slightly different and it requires an OCI Identity
        // and signed request.
        Response response =
                ordsClient
                        .target(ordsEndpoint)
                        .path("20201005")
                        .path("ords")
                        .path(dbtoolsConnectionId)
                        .path("_")
                        .path("sql")
                        .request()
                        .post(body);
        Assertions.assertEquals(200, response.getStatus());
        log.info("Response Body {}", response.readEntity(String.class));
        log.info(
                "\n"
                        + " ___  _  _  __  __  ___  ___  ___  _ \n"
                        + "/ __)( )( )/ _)/ _)(  _)/ __)/ __)/ \\\n"
                        + "\\__ \\ )()(( (_( (_  ) _)\\__ \\\\__ \\\\_/\n"
                        + "(___/ \\__/ \\__)\\__)(___)(___/(___/(_)\n"
                        + "\n");
    }
}
