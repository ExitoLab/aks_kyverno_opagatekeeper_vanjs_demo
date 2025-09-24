import pulumi
import pulumi_random as random
import pulumi_azure_native as azure_native
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------------------------
# Config
# ---------------------------
config = pulumi.Config()
project = pulumi.get_project()
stack = pulumi.get_stack()

location = config.get("azure:location") or "eastus2"
env = config.get("azure:env") or "prod"
name_prefix = f"{project}-{env}"

# ---------------------------
# Resource Group (safe adoption)
# ---------------------------
rg_name = f"{name_prefix}-rg"

try:
    resource_group = azure_native.resources.ResourceGroup.get("rg", rg_name)
except Exception:
    resource_group = azure_native.resources.ResourceGroup(
        "rg",
        resource_group_name=rg_name,
        location=location,
    )

# ---------------------------
# Azure Container Registry (safe adoption)
# ---------------------------
acr_name = f"{name_prefix}acr".lower().replace("-", "").replace("_", "")

try:
    acr = azure_native.containerregistry.Registry.get("acr", acr_name)
except Exception:
    acr = azure_native.containerregistry.Registry(
        "acr",
        resource_group_name=rg_name,      # FIXED: Use string variable
        location=location,                # FIXED: Use string variable
        sku=azure_native.containerregistry.SkuArgs(name="Premium"),
        admin_user_enabled=False,
        registry_name=acr_name,
    )

# ---------------------------
# Key Vault (safe adoption)
# ---------------------------
client_config = azure_native.authorization.get_client_config_output()
kv_name = f"{name_prefix}-kv".lower().replace("_", "")[:24]

try:
    key_vault = azure_native.keyvault.Vault.get("kv", kv_name)
except Exception:
    key_vault = azure_native.keyvault.Vault(
        "kv",
        resource_group_name=rg_name,     # FIXED: Use string variable
        location=location,
        properties=azure_native.keyvault.VaultPropertiesArgs(
            sku=azure_native.keyvault.SkuArgs(family="A", name="standard"),
            tenant_id=client_config.tenant_id,
            enable_rbac_authorization=True,
        ),
        vault_name=kv_name,
    )

# Generate RSA key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
).decode()

# ---------------------------
# Key Vault secrets (safe adoption)
# ---------------------------
secret_name = "aks-ssh-public-key"

try:
    ssh_public_key_secret = azure_native.keyvault.Secret.get(
        "sshPublicKeySecretVault",
        f"{kv_name}/{secret_name}"
    )
except Exception:
    ssh_public_key_secret = azure_native.keyvault.Secret(
        "sshPublicKeySecretVault",
        resource_group_name=rg_name,
        vault_name=kv_name,
        properties=azure_native.keyvault.SecretPropertiesArgs(
            value=public_pem,
        ),
        secret_name=secret_name,
    )

# ---------------------------
# AKS Cluster
# ---------------------------
aks_name = f"{name_prefix}-aks"

try:
    aks_cluster = azure_native.containerservice.ManagedCluster.get("aks", aks_name)
    print(f"Found existing AKS cluster: {aks_name}")
except Exception:
    print(f"Creating new AKS cluster: {aks_name}")
    aks_cluster = azure_native.containerservice.ManagedCluster(
        "aks",
        resource_group_name=rg_name,
        location=location,
        dns_prefix=f"{name_prefix}-dns",
        kubernetes_version="1.33.2",
        enable_rbac=True,
        api_server_access_profile=azure_native.containerservice.ManagedClusterAPIServerAccessProfileArgs(
            enable_private_cluster=True,
        ),
        identity=azure_native.containerservice.ManagedClusterIdentityArgs(
            type="SystemAssigned",
        ),
        agent_pool_profiles=[
            azure_native.containerservice.ManagedClusterAgentPoolProfileArgs(
                name="systempool",
                mode="System",
                count=1,
                vm_size="Standard_B2ms",
                os_type="Linux",
                os_disk_size_gb=30,
                #availability_zones=["1"],             # Demo: Single zone only
                type="VirtualMachineScaleSets",
                enable_auto_scaling=False,
            ),
            azure_native.containerservice.ManagedClusterAgentPoolProfileArgs(
                name="userpool",
                mode="User",
                count=1,
                vm_size="Standard_B2ms",
                os_type="Linux",
                os_disk_size_gb=30,
                type="VirtualMachineScaleSets",
                enable_auto_scaling=False,
            ),
        ],
        linux_profile=azure_native.containerservice.ContainerServiceLinuxProfileArgs(
            admin_username="aksadmin",
            ssh=azure_native.containerservice.ContainerServiceSshConfigurationArgs(
                public_keys=[
                    azure_native.containerservice.ContainerServiceSshPublicKeyArgs(
                        key_data=public_pem
                    )
                ]
            ),
        ),
        network_profile=azure_native.containerservice.ContainerServiceNetworkProfileArgs(
            network_plugin="azure",
            load_balancer_sku="standard",
            outbound_type="loadBalancer",
        ),
        resource_name=aks_name,  # Explicitly set the AKS cluster name
    )

# --------------------------------
# Role Assignment: AKS → ACR Pull 
# --------------------------------
def create_role_assignment(principal_id):
    if principal_id is not None:
        return azure_native.authorization.RoleAssignment(
            "aksAcrPullRole",
            principal_id=principal_id,
            principal_type="ServicePrincipal",
            role_definition_id=client_config.subscription_id.apply(
                lambda sid: f"/subscriptions/{sid}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d"
            ),
            scope=pulumi.Output.concat(
                "/subscriptions/", client_config.subscription_id,
                "/resourceGroups/", rg_name,
                "/providers/Microsoft.ContainerRegistry/registries/", acr_name
            ),
        )
    else:
        pulumi.log.warn("AKS cluster has no identity; skipping RoleAssignment")
        return None

# Apply safe RoleAssignment
aks_cluster_identity = aks_cluster.identity.apply(lambda id: id.principal_id if id is not None else None)
role_assignment = aks_cluster_identity.apply(create_role_assignment)

# ---------------------------
# Exports
# ---------------------------
pulumi.export("resource_group", rg_name)
pulumi.export("acr_name", acr_name)
pulumi.export("aks_name", aks_cluster.name)
pulumi.export(
    "kubeconfig",
    pulumi.Output.secret(
        azure_native.containerservice.list_managed_cluster_user_credentials_output(
            resource_group_name=rg_name,
            resource_name=aks_cluster.name,
        ).kubeconfigs[0].value
    ),
)
pulumi.export("key_vault_name", kv_name)
pulumi.export("ssh_public_key_secret", secret_name)