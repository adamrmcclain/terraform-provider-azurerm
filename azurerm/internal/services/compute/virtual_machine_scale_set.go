package compute

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type VirtualMachineScaleSetResourceID struct {
	Base azure.ResourceID

	Name string
}

func ParseVirtualMachineScaleSetResourceID(input string) (*VirtualMachineScaleSetResourceID, error) {
	id, err := azure.ParseAzureResourceID(input)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Unable to parse Virtual Machine Scale Set ID %q: %+v", input, err)
	}

	networkSecurityGroup := VirtualMachineScaleSetResourceID{
		Base: *id,
		Name: id.Path["virtualMachineScaleSets"],
	}

	if networkSecurityGroup.Name == "" {
		return nil, fmt.Errorf("ID was missing the `virtualMachineScaleSets` element")
	}

	return &networkSecurityGroup, nil
}

func VirtualMachineScaleSetAdditionalCapabilitiesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"ultra_ssd_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
			},
		},
	}
}

func ExpandVirtualMachineScaleSetAdditionalCapabilities(input []interface{}) *compute.AdditionalCapabilities {
	capabilities := compute.AdditionalCapabilities{}

	if len(input) > 0 {
		raw := input[0].(map[string]interface{})

		capabilities.UltraSSDEnabled = utils.Bool(raw["ultra_ssd_enabled"].(bool))
	}

	return &capabilities
}

func FlattenVirtualMachineScaleSetAdditionalCapabilities(input *compute.AdditionalCapabilities) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	ultraSsdEnabled := false

	if input.UltraSSDEnabled != nil {
		ultraSsdEnabled = *input.UltraSSDEnabled
	}

	return []interface{}{
		map[string]interface{}{
			"ultra_ssd_enabled": ultraSsdEnabled,
		},
	}
}

func VirtualMachineScaleSetNetworkInterfaceSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		// TODO: confirm this is the same as MinItems: 1
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.NoZeroValues,
				},
				"ip_configuration": virtualMachineScaleSetIPConfigurationSchema(),

				"dns_servers": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validate.NoEmptyStrings,
					},
				},
				"enable_accelerated_networking": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
				"enable_ip_forwarding": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
				"network_security_group_id": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: azure.ValidateResourceIDOrEmpty,
				},
				"primary": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
			},
		},
	}
}

func virtualMachineScaleSetIPConfigurationSchema() *schema.Schema {
	return &schema.Schema{
		// TODO: does this want to be a Set?
		Type:     schema.TypeList,
		Required: true,
		// TODO: confirm this is the same as MinItems: 1
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validate.NoEmptyStrings,
				},
				"subnet_id": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: azure.ValidateResourceID,
				},

				// Optional
				"application_gateway_backend_address_pool_ids": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
					Set:      schema.HashString,
				},

				"application_security_group_ids": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: azure.ValidateResourceID,
					},
					Set:      schema.HashString,
					MaxItems: 20,
				},

				"load_balancer_backend_address_pool_ids": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
					Set:      schema.HashString,
				},

				"load_balancer_inbound_nat_rules_ids": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
					Set:      schema.HashString,
				},

				"primary": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"public_ip_address": virtualMachineScaleSetPublicIPAddressSchema(),

				"version": {
					Type:     schema.TypeString,
					Optional: true,
					Default:  string(compute.IPv4),
					ValidateFunc: validation.StringInSlice([]string{
						string(compute.IPv4),
						string(compute.IPv6),
					}, false),
				},
			},
		},
	}
}

func virtualMachineScaleSetPublicIPAddressSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validate.NoEmptyStrings,
				},

				// TODO: confirm Required/Optional here
				"domain_name_label": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validate.NoEmptyStrings,
				},
				"idle_time_in_minutes": {
					Type:         schema.TypeInt,
					Optional:     true,
					ValidateFunc: validation.IntBetween(4, 32),
				},
				"ip_tag": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"tag": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validate.NoEmptyStrings,
							},
							"type": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validate.NoEmptyStrings,
							},
						},
					},
				},
				"public_ip_prefix_id": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: azure.ValidateResourceIDOrEmpty,
				},
			},
		},
	}
}

func ExpandVirtualMachineScaleSetNetworkInterface(input []interface{}) *[]compute.VirtualMachineScaleSetNetworkConfiguration {
	output := make([]compute.VirtualMachineScaleSetNetworkConfiguration, 0)

	for _, v := range input {
		raw := v.(map[string]interface{})

		dnsServers := utils.ExpandStringSlice(raw["dns_servers"].([]interface{}))

		ipConfigurations := make([]compute.VirtualMachineScaleSetIPConfiguration, 0)
		ipConfigurationsRaw := raw["ip_configuration"].([]interface{})
		for _, configV := range ipConfigurationsRaw {
			configRaw := configV.(map[string]interface{})
			ipConfiguration := expandVirtualMachineScaleSetIPConfiguration(configRaw)
			ipConfigurations = append(ipConfigurations, ipConfiguration)
		}

		config := compute.VirtualMachineScaleSetNetworkConfiguration{
			Name: utils.String(raw["name"].(string)),
			VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
				DNSSettings: &compute.VirtualMachineScaleSetNetworkConfigurationDNSSettings{
					DNSServers: dnsServers,
				},
				EnableAcceleratedNetworking: utils.Bool(raw["enable_accelerated_networking"].(bool)),
				EnableIPForwarding:          utils.Bool(raw["enable_ip_forwarding"].(bool)),
				IPConfigurations:            &ipConfigurations,
				Primary:                     utils.Bool(raw["primary"].(bool)),
			},
		}

		if nsgId := raw["network_security_group_id"].(string); nsgId != "" {
			config.VirtualMachineScaleSetNetworkConfigurationProperties.NetworkSecurityGroup = &compute.SubResource{
				ID: utils.String(nsgId),
			}
		}

		output = append(output, config)
	}

	return &output
}

func expandVirtualMachineScaleSetIPConfiguration(raw map[string]interface{}) compute.VirtualMachineScaleSetIPConfiguration {
	/*
		TODO: expand:
			application_gateway_backend_address_pool_ids
			application_security_group_ids
			load_balancer_backend_address_pool_ids
			load_balancer_inbound_nat_rules_ids
			public_ip_address
	*/

	ipConfiguration := compute.VirtualMachineScaleSetIPConfiguration{
		Name: utils.String(raw["name"].(string)),
		VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
			Subnet: &compute.APIEntityReference{
				ID: utils.String(raw["subnet_id"].(string)),
			},
			Primary:                 utils.Bool(raw["primary"].(bool)),
			PrivateIPAddressVersion: compute.IPVersion(raw["version"].(string)),

			// TODO: expand/set me
			ApplicationGatewayBackendAddressPools: nil,
			ApplicationSecurityGroups:             nil,
			LoadBalancerBackendAddressPools:       nil,
			LoadBalancerInboundNatPools:           nil,
		},
	}

	publicIPConfigsRaw := raw["public_ip_address"].([]interface{})
	if len(publicIPConfigsRaw) > 0 {
		publicIPConfigRaw := publicIPConfigsRaw[0].(map[string]interface{})
		publicIPAddressConfig := expandVirtualMachineScaleSetPublicIPAddress(publicIPConfigRaw)
		ipConfiguration.VirtualMachineScaleSetIPConfigurationProperties.PublicIPAddressConfiguration = publicIPAddressConfig
	}

	return ipConfiguration
}

func expandVirtualMachineScaleSetPublicIPAddress(raw map[string]interface{}) *compute.VirtualMachineScaleSetPublicIPAddressConfiguration {
	ipTagsRaw := raw["ip_tag"].([]interface{})
	ipTags := make([]compute.VirtualMachineScaleSetIPTag, 0)
	for _, ipTagV := range ipTagsRaw {
		ipTagRaw := ipTagV.(map[string]interface{})
		ipTags = append(ipTags, compute.VirtualMachineScaleSetIPTag{
			Tag:       utils.String(ipTagRaw["tag"].(string)),
			IPTagType: utils.String(ipTagRaw["type"].(string)),
		})
	}

	publicIPAddressConfig := compute.VirtualMachineScaleSetPublicIPAddressConfiguration{
		Name: utils.String(raw["name"].(string)),
		VirtualMachineScaleSetPublicIPAddressConfigurationProperties: &compute.VirtualMachineScaleSetPublicIPAddressConfigurationProperties{
			DNSSettings: &compute.VirtualMachineScaleSetPublicIPAddressConfigurationDNSSettings{
				DomainNameLabel: utils.String(raw["domain_name_label"].(string)),
			},
			IdleTimeoutInMinutes: utils.Int32(int32(raw["idle_timeout_in_minutes"].(int))),
			IPTags:               &ipTags,
		},
	}

	publicIPAddressConfig.VirtualMachineScaleSetPublicIPAddressConfigurationProperties.PublicIPPrefix = &compute.SubResource{
		ID: utils.String(raw["public_ip_prefix_id"].(string)),
	}

	return &publicIPAddressConfig
}

func FlattenVirtualMachineScaleSetNetworkInterface(input *[]compute.VirtualMachineScaleSetNetworkConfiguration) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	results := make([]interface{}, 0)
	for _, v := range *input {

		var name, networkSecurityGroupId string
		if v.Name != nil {
			name = *v.Name
		}
		if v.NetworkSecurityGroup != nil && v.NetworkSecurityGroup.ID != nil {
			networkSecurityGroupId = *v.NetworkSecurityGroup.ID
		}

		var enableAcceleratedNetworking, enableIPForwarding, primary bool
		if v.EnableAcceleratedNetworking != nil {
			enableAcceleratedNetworking = *v.EnableAcceleratedNetworking
		}
		if v.EnableIPForwarding != nil {
			enableIPForwarding = *v.EnableIPForwarding
		}
		if v.Primary != nil {
			primary = *v.Primary
		}

		var dnsServers []interface{}
		if settings := v.DNSSettings; settings != nil {
			dnsServers = utils.FlattenStringSlice(v.DNSSettings.DNSServers)
		}

		var ipConfigurations []interface{}
		if v.IPConfigurations != nil {
			for _, configRaw := range *v.IPConfigurations {
				config := flattenVirtualMachineScaleSetIPConfiguration(configRaw)
				ipConfigurations = append(ipConfigurations, config)
			}
		}

		results = append(results, map[string]interface{}{
			"name":                          name,
			"dns_servers":                   dnsServers,
			"enable_accelerated_networking": enableAcceleratedNetworking,
			"enable_ip_forwarding":          enableIPForwarding,
			"ip_configuration":              ipConfigurations,
			"network_security_group_id":     networkSecurityGroupId,
			"primary":                       primary,
		})
	}

	return results
}

func flattenVirtualMachineScaleSetIPConfiguration(input compute.VirtualMachineScaleSetIPConfiguration) map[string]interface{} {
	var name, subnetId string
	if input.Name != nil {
		name = *input.Name
	}
	if input.Subnet != nil && input.Subnet.ID != nil {
		subnetId = *input.Subnet.ID
	}

	var primary bool
	if input.Primary != nil {
		primary = *input.Primary
	}

	var publicIPAddresses []interface{}
	if input.PublicIPAddressConfiguration != nil {
		publicIPAddresses = append(publicIPAddresses, flattenVirtualMachineScaleSetPublicIPAddress(*input.PublicIPAddressConfiguration))
	}

	return map[string]interface{}{
		"name":              name,
		"primary":           primary,
		"public_ip_address": publicIPAddresses,
		"subnet_id":         subnetId,
		"version":           string(input.PrivateIPAddressVersion),

		// TODO: flatten these
		"application_gateway_backend_address_pool_ids": []interface{}{},
		"application_security_group_ids":               []interface{}{},
		"load_balancer_backend_address_pool_ids":       []interface{}{},
		"load_balancer_inbound_nat_rules_ids":          []interface{}{},
	}
}

func flattenVirtualMachineScaleSetPublicIPAddress(input compute.VirtualMachineScaleSetPublicIPAddressConfiguration) map[string]interface{} {
	ipTags := make([]interface{}, 0)
	if input.IPTags != nil {
		for _, rawTag := range *input.IPTags {
			var tag, tagType string

			if rawTag.IPTagType != nil {
				tagType = *rawTag.IPTagType
			}

			if rawTag.Tag != nil {
				tag = *rawTag.Tag
			}

			ipTags = append(ipTags, map[string]interface{}{
				"tag":  tag,
				"type": tagType,
			})
		}
	}

	var domainNameLabel, name, publicIPPrefixId string
	if input.DNSSettings != nil && input.DNSSettings.DomainNameLabel != nil {
		domainNameLabel = *input.DNSSettings.DomainNameLabel
	}
	if input.Name != nil {
		name = *input.Name
	}
	if input.PublicIPPrefix != nil && input.PublicIPPrefix.ID != nil {
		publicIPPrefixId = *input.PublicIPPrefix.ID
	}

	var idleTimeoutInMinutes int
	if input.IdleTimeoutInMinutes != nil {
		idleTimeoutInMinutes = int(*input.IdleTimeoutInMinutes)
	}

	return map[string]interface{}{
		"name":                    name,
		"domain_name_label":       domainNameLabel,
		"idle_timeout_in_minutes": idleTimeoutInMinutes,
		"ip_tag":                  ipTags,
		"public_ip_prefix_id":     publicIPPrefixId,
	}
}

func VirtualMachineScaleSetOSDiskSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"caching": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(compute.CachingTypesNone),
						string(compute.CachingTypesReadOnly),
						string(compute.CachingTypesReadWrite),
					}, false),
				},
				"storage_account_type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						// note: OS Disks don't support Ultra SSDs
						string(compute.StorageAccountTypesPremiumLRS),
						string(compute.StorageAccountTypesStandardLRS),
						string(compute.StorageAccountTypesStandardSSDLRS),
					}, false),
				},

				"diff_disk_settings": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					// TODO: should this be ForceNew?
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"option": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.StringInSlice([]string{
									string(compute.Local),
								}, false),
							},
						},
					},
				},

				"disk_size_gb": {
					Type:         schema.TypeInt,
					Optional:     true,
					ValidateFunc: validation.IntBetween(0, 1023),
					// TODO: should this be ForceNew?
				},

				"write_accelerator_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
					// TODO: should this be ForceNew?
				},
			},
		},
	}
}

func ExpandVirtualMachineScaleSetOSDisk(input []interface{}, osType compute.OperatingSystemTypes) *compute.VirtualMachineScaleSetOSDisk {
	raw := input[0].(map[string]interface{})
	disk := compute.VirtualMachineScaleSetOSDisk{
		Caching: compute.CachingTypes(raw["caching"].(string)),
		ManagedDisk: &compute.VirtualMachineScaleSetManagedDiskParameters{
			StorageAccountType: compute.StorageAccountTypes(raw["storage_account_type"].(string)),
		},
		WriteAcceleratorEnabled: utils.Bool(raw["write_accelerator_enabled"].(bool)),

		// these have to be hard-coded so there's no point exposing them
		CreateOption: compute.DiskCreateOptionTypesFromImage,
		OsType:       osType,
	}

	if osDiskSize := raw["disk_size_gb"].(int); osDiskSize > 0 {
		disk.DiskSizeGB = utils.Int32(int32(osDiskSize))
	}

	if diffDiskSettingsRaw := raw["diff_disk_settings"].([]interface{}); len(diffDiskSettingsRaw) > 0 {
		diffDiskRaw := diffDiskSettingsRaw[0].(map[string]interface{})
		disk.DiffDiskSettings = &compute.DiffDiskSettings{
			Option: compute.DiffDiskOptions(diffDiskRaw["option"].(string)),
		}
	}

	return &disk
}

func FlattenVirtualMachineScaleSetOSDisk(input *compute.VirtualMachineScaleSetOSDisk) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	diffDataSettings := make([]interface{}, 0)
	if input.DiffDiskSettings != nil {
		diffDataSettings = append(diffDataSettings, map[string]interface{}{
			"option": string(input.DiffDiskSettings.Option),
		})
	}

	diskSizeGb := 0
	if input.DiskSizeGB != nil && *input.DiskSizeGB != 0 {
		diskSizeGb = int(*input.DiskSizeGB)
	}

	var storageAccountType string
	if input.ManagedDisk != nil {
		storageAccountType = string(input.ManagedDisk.StorageAccountType)
	}

	writeAcceleratorEnabled := false
	if input.WriteAcceleratorEnabled != nil {
		writeAcceleratorEnabled = *input.WriteAcceleratorEnabled
	}
	return []interface{}{
		map[string]interface{}{
			"caching":                   string(input.Caching),
			"disk_size_gb":              diskSizeGb,
			"diff_data_settings":        diffDataSettings,
			"storage_account_type":      storageAccountType,
			"write_accelerator_enabled": writeAcceleratorEnabled,
		},
	}
}

func VirtualMachineScaleSetSourceImageReferenceSchema() *schema.Schema {
	// whilst originally I was hoping we could use the 'id' from `azurerm_platform_image' unfortunately Azure doesn't
	// like this as a value for the 'id' field:
	// Id /...../Versions/16.04.201909091 is not a valid resource reference."
	// as such the image is split into two fields (source_image_id and source_image_reference) to provide better validation
	return &schema.Schema{
		Type:          schema.TypeList,
		Optional:      true,
		MaxItems:      1,
		ConflictsWith: []string{"source_image_id"},
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"publisher": {
					Type:     schema.TypeString,
					Required: true,
				},
				"offer": {
					Type:     schema.TypeString,
					Required: true,
				},
				"sku": {
					Type:     schema.TypeString,
					Required: true,
				},
				"version": {
					Type:     schema.TypeString,
					Required: true,
				},
			},
		},
	}
}

func ExpandVirtualMachineScaleSetSourceImageReference(input []interface{}) *compute.ImageReference {
	if len(input) == 0 {
		return nil
	}

	raw := input[0].(map[string]interface{})
	return &compute.ImageReference{
		Publisher: utils.String(raw["publisher"].(string)),
		Offer:     utils.String(raw["offer"].(string)),
		Sku:       utils.String(raw["sku"].(string)),
		Version:   utils.String(raw["version"].(string)),
	}
}

func FlattenVirtualMachineScaleSetSourceImageReference(input *compute.ImageReference) []interface{} {
	// since the image id is pulled out as a separate field, if that's set we should return an empty block here
	if input == nil || input.ID != nil {
		return []interface{}{}
	}

	var publisher, offer, sku, version string

	if input.Publisher != nil {
		publisher = *input.Publisher
	}
	if input.Offer != nil {
		offer = *input.Offer
	}
	if input.Sku != nil {
		sku = *input.Sku
	}
	if input.Version != nil {
		version = *input.Version
	}

	return []interface{}{
		map[string]interface{}{
			"publisher": publisher,
			"offer":     offer,
			"sku":       sku,
			"version":   version,
		},
	}
}

func VirtualMachineScaleSetUpgradePolicySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"mode": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(compute.Automatic),
						string(compute.Manual),
						string(compute.Rolling),
					}, false),
				},

				"automatic_os_upgrade_policy": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							// TODO: should these be optional + defaulted?
							"disable_automatic_rollback": {
								Type:     schema.TypeBool,
								Required: true,
							},
							"enable_automatic_os_upgrade": {
								Type:     schema.TypeBool,
								Required: true,
							},
						},
					},
				},

				"rolling_upgrade_policy": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"max_batch_instance_percent": {
								Type:     schema.TypeInt,
								Required: true,
							},
							"max_unhealthy_instance_percent": {
								Type:     schema.TypeInt,
								Required: true,
							},
							"max_unhealthy_upgraded_instance_percent": {
								Type:     schema.TypeInt,
								Required: true,
							},
							"pause_time_between_batches": {
								Type:     schema.TypeString,
								Required: true,
							},
						},
					},
				},
			},
		},
	}
}

func ExpandVirtualMachineScaleSetUpgradePolicy(input []interface{}) (*compute.UpgradePolicy, error) {
	raw := input[0].(map[string]interface{})
	automaticPoliciesRaw := raw["automatic_os_upgrade_policy"].([]interface{})
	rollingPoliciesRaw := raw["rolling_upgrade_policy"].([]interface{})

	policy := compute.UpgradePolicy{
		Mode: compute.UpgradeMode(raw["mode"].(string)),
	}

	if len(automaticPoliciesRaw) > 0 {
		if policy.Mode != compute.Automatic {
			return nil, fmt.Errorf("A `automatic_os_upgrade_policy` block cannot be specified when `mode` is not set to `Automatic`")
		}

		automaticRaw := automaticPoliciesRaw[0].(map[string]interface{})
		policy.AutomaticOSUpgradePolicy = &compute.AutomaticOSUpgradePolicy{
			DisableAutomaticRollback: utils.Bool(automaticRaw["disable_automatic_rollback"].(bool)),
			EnableAutomaticOSUpgrade: utils.Bool(automaticRaw["enable_automatic_os_upgrade"].(bool)),
		}
	}

	if len(rollingPoliciesRaw) > 0 {
		if policy.Mode != compute.Rolling {
			return nil, fmt.Errorf("A `rolling_upgrade_policy` block cannot be specified when `mode` is not set to `Rolling`")
		}

		rollingRaw := rollingPoliciesRaw[0].(map[string]interface{})
		policy.RollingUpgradePolicy = &compute.RollingUpgradePolicy{
			MaxBatchInstancePercent:             utils.Int32(int32(rollingRaw["max_batch_instance_percent"].(int))),
			MaxUnhealthyInstancePercent:         utils.Int32(int32(rollingRaw["max_unhealthy_instance_percent"].(int))),
			MaxUnhealthyUpgradedInstancePercent: utils.Int32(int32(rollingRaw["max_unhealthy_upgraded_instance_percent"].(int))),
			PauseTimeBetweenBatches:             utils.String(rollingRaw["pause_time_between_batches"].(string)),
		}
	}

	if policy.Mode == compute.Automatic && policy.AutomaticOSUpgradePolicy == nil {
		return nil, fmt.Errorf("A `automatic_os_upgrade_policy` block must be specified when `mode` is set to `Automatic`")
	}

	if policy.Mode == compute.Rolling && policy.RollingUpgradePolicy == nil {
		return nil, fmt.Errorf("A `rolling_upgrade_policy` block must be specified when `mode` is set to `Rolling`")
	}

	return &policy, nil
}

func FlattenVirtualMachineScaleSetUpgradePolicy(input *compute.UpgradePolicy) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	automaticOutput := make([]interface{}, 0)
	if policy := input.AutomaticOSUpgradePolicy; policy != nil {
		disableAutomaticRollback := false
		enableAutomaticOSUpgrade := false

		if policy.DisableAutomaticRollback != nil {
			disableAutomaticRollback = *policy.DisableAutomaticRollback
		}

		if policy.EnableAutomaticOSUpgrade != nil {
			enableAutomaticOSUpgrade = *policy.EnableAutomaticOSUpgrade
		}

		automaticOutput = append(automaticOutput, map[string]interface{}{
			"disable_automatic_rollback":  disableAutomaticRollback,
			"enable_automatic_os_upgrade": enableAutomaticOSUpgrade,
		})
	}

	rollingOutput := make([]interface{}, 0)
	if policy := input.RollingUpgradePolicy; policy != nil {
		maxBatchInstancePercent := 0
		maxUnhealthyInstancePercent := 0
		maxUnhealthyUpgradedInstancePercent := 0
		pauseTimeBetweenBatches := ""

		if policy.MaxBatchInstancePercent != nil {
			maxBatchInstancePercent = int(*policy.MaxBatchInstancePercent)
		}
		if policy.MaxUnhealthyInstancePercent != nil {
			maxUnhealthyInstancePercent = int(*policy.MaxUnhealthyInstancePercent)
		}
		if policy.MaxUnhealthyUpgradedInstancePercent != nil {
			maxUnhealthyUpgradedInstancePercent = int(*policy.MaxUnhealthyUpgradedInstancePercent)
		}
		if policy.PauseTimeBetweenBatches != nil {
			pauseTimeBetweenBatches = *policy.PauseTimeBetweenBatches
		}

		rollingOutput = append(rollingOutput, map[string]interface{}{
			"max_batch_instance_percent":              maxBatchInstancePercent,
			"max_unhealthy_instance_percent":          maxUnhealthyInstancePercent,
			"max_unhealthy_upgraded_instance_percent": maxUnhealthyUpgradedInstancePercent,
			"pause_time_between_batches":              pauseTimeBetweenBatches,
		})
	}

	return []interface{}{
		map[string]interface{}{
			"mode":                        string(input.Mode),
			"automatic_os_upgrade_policy": automaticOutput,
			"rolling_upgrade_policy":      rollingOutput,
		},
	}
}
