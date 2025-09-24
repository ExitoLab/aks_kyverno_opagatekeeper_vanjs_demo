import pulumi
import pulumi_azure_native as azure_native
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pulumi import Output

config = pulumi.Config()
project = pulumi.get_project()
env = config.get("azure:env") or "prod"
location = config.get("azure:location") or "eastus2"
name_prefix = f"{project}-{env}"

client_config = azure_native.authorization.get_client_config_output()

# ---------------------------
# Resource Group
# ---------------------------
rg_name = f"{name_prefix}-rg"
resource_group = azure_native.resources.ResourceGroup(
    "rg",
    resource_group_name=rg_name,
    location=location
)

# ---------------------------
# Azure Container Registry
# ---------------------------
acr_name = f"{name_prefix}acr".lower().replace("-", "").replace("_", "")
acr = azure_native.containerregistry.Registry(
    "acr",
    resource_group_name=resource_group.name,
    location=location,
    sku=azure_native.containerregistry.SkuArgs(name="Premium"),
    admin_user_enabled=False,
    registry_name=acr_name
)

# ---------------------------
# Key Vault (create only if not exists)
# ---------------------------
kv_name = f"{name_prefix}-kv".lower()[:24]

def create_or_get_kv(args):
    rg_name, kv_name = args
    try:
        # Try to fetch existing vault
        return azure_native.keyvault.get_vault_output(
            resource_group_name=rg_name,
            vault_name=kv_name
        )
    except Exception:
        # Vault doesn't exist, create new
        return azure_native.keyvault.Vault(
            "kv",
            resource_group_name=rg_name,
            location=location,
            properties=azure_native.keyvault.VaultPropertiesArgs(
                sku=azure_native.keyvault.SkuArgs(family="A", name="standard"),
                tenant_id=client_config.tenant_id,
                enable_rbac_authorization=True,
            ),
            vault_name=kv_name
        )

key_vault = Output.all(resource_group.name, kv_name).apply(create_or_get_kv)

# ---------------------------
# RSA Key
# ---------------------------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
).decode()

# ---------------------------
# Key Vault Secret (depends on vault)
# ---------------------------
secret_name = "aks-ssh-public-key"
ssh_secret = key_vault.apply(lambda kv: azure_native.keyvault.Secret(
    "sshSecret",
    resource_group_name=resource_group.name,
    vault_name=kv.name,
    properties=azure_native.keyvault.SecretPropertiesArgs(value=public_pem),
    secret_name=secret_name
))

# ---------------------------
# AKS Cluster
# ---------------------------
aks_name = f"{name_prefix}-aks"
aks_cluster = azure_native.containerservice.ManagedCluster(
    "aks",
    resource_group_name=resource_group.name,
    location=location,
    dns_prefix=f"{name_prefix}-dns",
    kubernetes_version="1.33.3",
    enable_rbac=True,
    identity=azure_native.containerservice.ManagedClusterIdentityArgs(
        type="SystemAssigned"
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
    ],
    linux_profile=azure_native.containerservice.ContainerServiceLinuxProfileArgs(
        admin_username="aksadmin",
        ssh=azure_native.containerservice.ContainerServiceSshConfigurationArgs(
            public_keys=[azure_native.containerservice.ContainerServiceSshPublicKeyArgs(key_data=public_pem)]
        )
    ),
    network_profile=azure_native.containerservice.ContainerServiceNetworkProfileArgs(
        network_plugin="azure",
        load_balancer_sku="standard",
        outbound_type="loadBalancer",
    ),
)

# ---------------------------
# Exports
# ---------------------------
pulumi.export("resource_group", resource_group.name)
pulumi.export("acr_name", acr_name)
pulumi.export("key_vault_name", kv_name)
pulumi.export("ssh_public_key_secret", secret_name)
pulumi.export("aks_name", aks_cluster.name)
