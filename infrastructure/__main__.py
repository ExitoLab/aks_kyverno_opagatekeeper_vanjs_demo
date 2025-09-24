import pulumi
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

def get_or_create_rg(name, location):
    """Adopt existing RG or create new one."""
    try:
        # Attempt to adopt the existing resource group
        return azure_native.resources.ResourceGroup.get(
            "rg", 
            id=f"/subscriptions/{azure_native.authorization.get_client_config().subscription_id}/resourceGroups/{name}"
        )
    except Exception:
        # If it doesn't exist, create it
        return azure_native.resources.ResourceGroup(
            "rg",
            resource_group_name=name,
            location=location,
        )

resource_group = get_or_create_rg(rg_name, location)

# ---------------------------
# Azure Container Registry
# ---------------------------
acr_name = f"{name_prefix}acr".lower().replace("-", "").replace("_", "")

def get_or_create_acr(name, rg_name, location):
    try:
        return azure_native.containerregistry.Registry.get(
            "acr", 
            id=f"/subscriptions/{azure_native.authorization.get_client_config().subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.ContainerRegistry/registries/{name}"
        )
    except Exception:
        return azure_native.containerregistry.Registry(
            "acr",
            resource_group_name=rg_name,
            location=location,
            sku=azure_native.containerregistry.SkuArgs(name="Premium"),
            admin_user_enabled=False,
            registry_name=name,
        )

acr = get_or_create_acr(acr_name, resource_group.name, location)

# ---------------------------
# Key Vault
# ---------------------------
client_config = azure_native.authorization.get_client_config_output()
kv_name = f"{name_prefix}-kv".lower().replace("_", "")[:24]

def get_or_create_kv(name, rg_name, location, tenant_id):
    try:
        return azure_native.keyvault.Vault.get(
            "kv", 
            id=f"/subscriptions/{azure_native.authorization.get_client_config().subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{name}"
        )
    except Exception:
        return azure_native.keyvault.Vault(
            "kv",
            resource_group_name=rg_name,
            location=location,
            properties=azure_native.keyvault.VaultPropertiesArgs(
                sku=azure_native.keyvault.SkuArgs(family="A", name="standard"),
                tenant_id=tenant_id,
                enable_rbac_authorization=True,
            ),
            vault_name=name,
        )

key_vault = get_or_create_kv(kv_name, resource_group.name, location, client_config.tenant_id)

# ---------------------------
# Generate RSA key
# ---------------------------
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
# Key Vault Secret
# ---------------------------
secret_name = "aks-ssh-public-key"

def get_or_create_secret(kv_name, rg_name, secret_name, public_pem):
    try:
        return azure_native.keyvault.Secret.get(
            "sshPublicKeySecretVault",
            id=f"/subscriptions/{azure_native.authorization.get_client_config().subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{kv_name}/secrets/{secret_name}"
        )
    except Exception:
        return azure_native.keyvault.Secret(
            "sshPublicKeySecretVault",
            resource_group_name=rg_name,
            vault_name=kv_name,
            properties=azure_native.keyvault.SecretPropertiesArgs(
                value=public_pem,
            ),
            secret_name=secret_name,
        )

ssh_public_key_secret = get_or_create_secret(kv_name, resource_group.name, secret_name, public_pem)

# ---------------------------
# AKS Cluster
# ---------------------------
aks_name = f"{name_prefix}-aks"

try:
    aks_cluster = azure_native.containerservice.ManagedCluster.get(
        "aks", 
        id=f"/subscriptions/{azure_native.authorization.get_client_config().subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.ContainerService/managedClusters/{aks_name}"
    )
    pulumi.log.info(f"Found existing AKS cluster: {aks_name}")
except Exception:
    pulumi.log.info(f"Creating new AKS cluster: {aks_name}")
    aks_cluster = azure_native.containerservice.ManagedCluster(
        "aks",
        resource_group_name=resource_group.name,
        location=location,
        dns_prefix=f"{name_prefix}-dns",
        kubernetes_version="1.29.9",  # Fixed: 1.33.2 doesn't exist
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
        resource_name=aks_name,
    )

# ---------------------------
# Role Assignment: AKS → ACR Pull
# ---------------------------
def create_role_assignment_if_identity_exists():
    def create_assignment(identity):
        if identity and hasattr(identity, 'principal_id') and identity.principal_id:
            return azure_native.authorization.RoleAssignment(
                "aksAcrPullRole",
                principal_id=identity.principal_id,
                principal_type="ServicePrincipal",
                role_definition_id=client_config.subscription_id.apply(
                    lambda sid: f"/subscriptions/{sid}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d"
                ),
                scope=client_config.subscription_id.apply(
                    lambda sid: f"/subscriptions/{sid}/resourceGroups/{rg_name}/providers/Microsoft.ContainerRegistry/registries/{acr_name}"
                ),
            )
        else:
            pulumi.log.warn("AKS cluster has no identity; skipping RoleAssignment")
            return None
    
    return aks_cluster.identity.apply(create_assignment)

role_assignment = create_role_assignment_if_identity_exists()

# ---------------------------
# Conditional Kubeconfig Export
# ---------------------------
def get_kubeconfig_safely():
    def fetch_kubeconfig(cluster_name, rg_name):
        try:
            if cluster_name and rg_name:
                return azure_native.containerservice.list_managed_cluster_user_credentials_output(
                    resource_group_name=rg_name,
                    resource_name=cluster_name,
                ).kubeconfigs[0].value
            else:
                pulumi.log.warn("Cannot fetch kubeconfig: missing cluster or resource group name")
                return "kubeconfig-not-available"
        except Exception as e:
            pulumi.log.warn(f"Failed to fetch kubeconfig: {e}")
            return "kubeconfig-not-available"
    
    return pulumi.Output.all(aks_cluster.name, resource_group.name).apply(
        lambda args: fetch_kubeconfig(args[0], args[1])
    )

# ---------------------------
# Exports
# ---------------------------
pulumi.export("resource_group", resource_group.name)
pulumi.export("acr_name", acr_name)
pulumi.export("aks_name", aks_cluster.name)
pulumi.export("kubeconfig", pulumi.Output.secret(get_kubeconfig_safely()))
pulumi.export("key_vault_name", kv_name)
pulumi.export("ssh_public_key_secret", secret_name)