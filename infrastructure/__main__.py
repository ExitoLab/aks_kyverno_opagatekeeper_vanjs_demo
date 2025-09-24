import pulumi
import pulumi_azure_native as azure_native
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

config = pulumi.Config()
project = pulumi.get_project()
env = config.get("azure:env") or "prod"
location = config.get("azure:location") or "eastus2"
name_prefix = f"{project}-{env}"

# ---------------------------
# Resource Group safe adoption
# ---------------------------
rg_name = f"{name_prefix}-rg"
client_config = azure_native.authorization.get_client_config()

def get_or_create_rg(name, location):
    try:
        # Must use literal subscription ID + RG name
        return azure_native.resources.ResourceGroup.get(
            "rg",
            id=f"/subscriptions/{client_config.subscription_id}/resourceGroups/{name}"
        )
    except Exception:
        return azure_native.resources.ResourceGroup(
            "rg",
            resource_group_name=name,
            location=location
        )

resource_group = get_or_create_rg(rg_name, location)

# ---------------------------
# Azure Container Registry
# ---------------------------
acr_name = f"{name_prefix}acr".lower().replace("-", "").replace("_", "")

try:
    acr = azure_native.containerregistry.Registry.get(
        "acr",
        id=f"/subscriptions/{client_config.subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.ContainerRegistry/registries/{acr_name}"
    )
except Exception:
    acr = azure_native.containerregistry.Registry(
        "acr",
        resource_group_name=resource_group.name,  # safe to use Output
        location=location,
        sku=azure_native.containerregistry.SkuArgs(name="Premium"),
        admin_user_enabled=False,
        registry_name=acr_name
    )

# ---------------------------
# Key Vault
# ---------------------------
kv_name = f"{name_prefix}-kv".lower()[:24]

try:
    key_vault = azure_native.keyvault.Vault.get(
        "kv",
        id=f"/subscriptions/{client_config.subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{kv_name}"
    )
except Exception:
    key_vault = azure_native.keyvault.Vault(
        "kv",
        resource_group_name=resource_group.name,
        location=location,
        properties=azure_native.keyvault.VaultPropertiesArgs(
            sku=azure_native.keyvault.SkuArgs(family="A", name="standard"),
            tenant_id=client_config.tenant_id,
            enable_rbac_authorization=True,
        ),
        vault_name=kv_name
    )

# ---------------------------
# RSA Key
# ---------------------------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
).decode()

# ---------------------------
# Key Vault Secret
# ---------------------------
secret_name = "aks-ssh-public-key"

try:
    ssh_secret = azure_native.keyvault.Secret.get(
        "sshSecret",
        id=f"/subscriptions/{client_config.subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{kv_name}/secrets/{secret_name}"
    )
except Exception:
    ssh_secret = azure_native.keyvault.Secret(
        "sshSecret",
        resource_group_name=resource_group.name,
        vault_name=kv_name,
        properties=azure_native.keyvault.SecretPropertiesArgs(value=public_pem),
        secret_name=secret_name
    )

pulumi.export("resource_group", resource_group.name)
pulumi.export("acr_name", acr_name)
pulumi.export("key_vault_name", kv_name)
pulumi.export("ssh_public_key_secret", secret_name)
