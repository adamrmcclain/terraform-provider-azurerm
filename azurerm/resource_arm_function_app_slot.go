package azurerm

import (
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2018-02-01/web"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/suppress"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/features"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmFunctionAppSlot() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmFunctionAppSlotCreate,
		Read:   resourceArmFunctionAppSlotRead,
		Update: resourceArmFunctionAppSlotCreate,
		Delete: resourceArmFunctionAppSlotDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateAppServiceName,
			},

			"resource_group_name": azure.SchemaResourceGroupName(),

			"location": azure.SchemaLocation(),

			"identity": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:             schema.TypeString,
							Required:         true,
							DiffSuppressFunc: suppress.CaseDifference,
							ValidateFunc: validation.StringInSlice([]string{
								string(web.ManagedServiceIdentityTypeSystemAssigned),
							}, true),
						},
						"principal_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tenant_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},

			"app_service_plan_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"version": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "~1",
			},

			"kind": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"enable_builtin_logging": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			"app_service_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"storage_connection_string": {
				Type:      schema.TypeString,
				Required:  true,
				ForceNew:  true,
				Sensitive: true,
			},

			"site_config": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"always_on": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"use_32_bit_worker_process": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},
						"websockets_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"linux_fx_version": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"virtual_network_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"cors": azure.SchemaWebCorsSettings(),
					},
				},
			},

			"auth_settings": azure.SchemaAppServiceAuthSettings(),

			"client_affinity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},

			"https_only": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			"app_settings": {
				Type:     schema.TypeMap,
				Optional: true,
			},

			"connection_string": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(web.APIHub),
								string(web.Custom),
								string(web.DocDb),
								string(web.EventHub),
								string(web.MySQL),
								string(web.NotificationHub),
								string(web.PostgreSQL),
								string(web.RedisCache),
								string(web.ServiceBus),
								string(web.SQLAzure),
								string(web.SQLServer),
							}, true),
							DiffSuppressFunc: suppress.CaseDifference,
						},
					},
				},
			},

			"tags": tags.Schema(),

			"site_credential": {
				Type:     schema.TypeList,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"username": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"password": {
							Type:      schema.TypeString,
							Computed:  true,
							Sensitive: true,
						},
					},
				},
			},

			"default_hostname": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"outbound_ip_addresses": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"possible_outbound_ip_addresses": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceArmFunctionAppSlotCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).web.AppServicesClient
	ctx := meta.(*ArmClient).StopContext

	slot := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)
	appServiceName := d.Get("app_service_name").(string)
	kind := "functionapp"

	if features.ShouldResourcesBeImported() && d.IsNewResource() {
		existing, err := client.GetSlot(ctx, resourceGroup, appServiceName, slot)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("Error checking for presence of existing Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_app_service_slot", *existing.ID)
		}
	}

	location := azure.NormalizeLocation(d.Get("location").(string))
	appServicePlanId := d.Get("app_service_plan_id").(string)
	enabled := d.Get("enabled").(bool)
	httpsOnly := d.Get("https_only").(bool)
	t := d.Get("tags").(map[string]interface{})
	affinity := d.Get("client_affinity_enabled").(bool)

	appServiceTier, err := getFunctionAppServiceTier(ctx, appServicePlanId, meta)

	if err != nil {
		return err
	}

	basicAppSettings := getBasicFunctionAppAppSettings(d, appServiceTier)
	siteConfig := expandFunctionAppSiteConfig(d)
	siteConfig.AppSettings = &basicAppSettings

	siteEnvelope := web.Site{
		Kind:     &kind,
		Location: &location,
		Tags:     tags.Expand(t),
		SiteProperties: &web.SiteProperties{
			ServerFarmID:          utils.String(appServicePlanId),
			Enabled:               utils.Bool(enabled),
			HTTPSOnly:             utils.Bool(httpsOnly),
			SiteConfig:            &siteConfig,
			ClientAffinityEnabled: &affinity,
		},
	}

	if v, ok := d.GetOk("identity.0.type"); ok {
		siteEnvelope.Identity = &web.ManagedServiceIdentity{
			Type: web.ManagedServiceIdentityType(v.(string)),
		}
	}

	createFuture, err := client.CreateOrUpdateSlot(ctx, resourceGroup, appServiceName, siteEnvelope, slot)
	if err != nil {
		return fmt.Errorf("Error creating Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	err = createFuture.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		return fmt.Errorf("Error waiting for creation of Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	read, err := client.GetSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		return fmt.Errorf("Error retrieving Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	if read.ID == nil {
		return fmt.Errorf("Cannot read ID for Slot %q (App Service %q / Resource Group %q) ID", slot, appServiceName, resourceGroup)
	}

	d.SetId(*read.ID)

	return resourceArmFunctionAppSlotUpdate(d, meta)
}

func resourceArmFunctionAppSlotUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).web.AppServicesClient
	ctx := meta.(*ArmClient).StopContext

	id, err := azure.ParseAzureResourceID(d.Id())
	if err != nil {
		return err
	}

	resourceGroup := id.ResourceGroup
	appServiceName := id.Path["sites"]
	slot := id.Path["slots"]
	kind := "functionapp"

	location := azure.NormalizeLocation(d.Get("location").(string))
	appServicePlanId := d.Get("app_service_plan_id").(string)

	appServiceTier, err := getFunctionAppServiceTier(ctx, appServicePlanId, meta)

	if err != nil {
		return err
	}

	basicAppSettings := getBasicFunctionAppAppSettings(d, appServiceTier)
	siteConfig := expandFunctionAppSiteConfig(d)

	siteConfig.AppSettings = &basicAppSettings

	enabled := d.Get("enabled").(bool)
	httpsOnly := d.Get("https_only").(bool)
	t := d.Get("tags").(map[string]interface{})

	siteEnvelope := web.Site{
		Kind:     &kind,
		Location: &location,
		Tags:     tags.Expand(t),
		SiteProperties: &web.SiteProperties{
			ServerFarmID: utils.String(appServicePlanId),
			Enabled:      utils.Bool(enabled),
			HTTPSOnly:    utils.Bool(httpsOnly),
			SiteConfig:   &siteConfig,
		},
	}

	if v, ok := d.GetOk("client_affinity_enabled"); ok {
		enabled := v.(bool)
		siteEnvelope.SiteProperties.ClientAffinityEnabled = utils.Bool(enabled)
	}

	if v, ok := d.GetOk("identity.0.type"); ok {
		siteEnvelope.Identity = &web.ManagedServiceIdentity{
			Type: web.ManagedServiceIdentityType(v.(string)),
		}
	}

	createFuture, err := client.CreateOrUpdateSlot(ctx, resourceGroup, appServiceName, siteEnvelope, slot)
	if err != nil {
		return fmt.Errorf("Error updating Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	err = createFuture.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		return fmt.Errorf("Error waiting for update of Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	if d.HasChange("site_config") {
		// update the main configuration
		siteConfig := expandFunctionAppSiteConfig(d)
		siteConfigResource := web.SiteConfigResource{
			SiteConfig: &siteConfig,
		}
		if _, err := client.CreateOrUpdateConfigurationSlot(ctx, resourceGroup, appServiceName, siteConfigResource, slot); err != nil {
			return fmt.Errorf("Error updating Configuration for Function App Service Slot %q/%q: %+v", appServiceName, slot, err)
		}
	}

	if d.HasChange("auth_settings") {
		authSettingsRaw := d.Get("auth_settings").([]interface{})
		authSettingsProperties := azure.ExpandAppServiceAuthSettings(authSettingsRaw)
		id := d.Id()
		authSettings := web.SiteAuthSettings{
			ID:                         &id,
			SiteAuthSettingsProperties: &authSettingsProperties,
		}

		if _, err := client.UpdateAuthSettingsSlot(ctx, resourceGroup, appServiceName, authSettings, slot); err != nil {
			return fmt.Errorf("Error updating Authentication Settings for Function App Service %q: %+v", appServiceName, err)
		}
	}

	if d.HasChange("app_settings") {
		// update the AppSettings
		appSettings := expandAppServiceAppSettings(d)
		settings := web.StringDictionary{
			Properties: appSettings,
		}

		if _, err := client.UpdateApplicationSettingsSlot(ctx, resourceGroup, appServiceName, settings, slot); err != nil {
			return fmt.Errorf("Error updating Application Settings for Function App Service Slot %q/%q: %+v", appServiceName, slot, err)
		}
	}

	if d.HasChange("connection_string") {
		// update the ConnectionStrings
		connectionStrings := expandFunctionAppConnectionStrings(d)
		properties := web.ConnectionStringDictionary{
			Properties: connectionStrings,
		}

		if _, err := client.UpdateConnectionStringsSlot(ctx, resourceGroup, appServiceName, properties, slot); err != nil {
			return fmt.Errorf("Error updating Connection Strings for Function App Service Slot %q/%q: %+v", appServiceName, slot, err)
		}
	}

	return resourceArmFunctionAppSlotRead(d, meta)
}

func resourceArmFunctionAppSlotRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).web.AppServicesClient

	id, err := azure.ParseAzureResourceID(d.Id())
	if err != nil {
		return err
	}

	resourceGroup := id.ResourceGroup
	appServiceName := id.Path["sites"]
	slot := id.Path["slots"]

	ctx := meta.(*ArmClient).StopContext
	resp, err := client.GetSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] Slot %q (App Service %q / Resource Group %q) were not found - removing from state!", slot, appServiceName, resourceGroup)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("Error reading Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	configResp, err := client.GetConfigurationSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		if utils.ResponseWasNotFound(configResp.Response) {
			log.Printf("[DEBUG] Configuration for Slot %q (App Service %q / Resource Group %q) were not found - removing from state!", slot, appServiceName, resourceGroup)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("Error reading Configuration for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	authResp, err := client.GetAuthSettingsSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		return fmt.Errorf("Error reading Auth Settings for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	appSettingsResp, err := client.ListApplicationSettingsSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		if utils.ResponseWasNotFound(appSettingsResp.Response) {
			log.Printf("[DEBUG] App Settings for Slot %q (App Service %q / Resource Group %q) were not found - removing from state!", slot, appServiceName, resourceGroup)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("Error reading App Settings for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	connectionStringsResp, err := client.ListConnectionStringsSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		return fmt.Errorf("Error listing Connection Strings for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	siteCredFuture, err := client.ListPublishingCredentialsSlot(ctx, resourceGroup, appServiceName, slot)
	if err != nil {
		return fmt.Errorf("Error retrieving publishing credentials for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}
	err = siteCredFuture.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		return fmt.Errorf("Error waiting for publishing credentials for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}
	siteCredResp, err := siteCredFuture.Result(*client)
	if err != nil {
		return fmt.Errorf("Error reading publishing credentials for Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
	}

	d.Set("name", slot)
	d.Set("app_service_name", appServiceName)
	d.Set("resource_group_name", resourceGroup)
	d.Set("kind", resp.Kind)

	if location := resp.Location; location != nil {
		d.Set("location", azure.NormalizeLocation(*location))
	}

	if props := resp.SiteProperties; props != nil {
		d.Set("app_service_plan_id", props.ServerFarmID)
		d.Set("client_affinity_enabled", props.ClientAffinityEnabled)
		d.Set("default_hostname", props.DefaultHostName)
		d.Set("enabled", props.Enabled)
		d.Set("outbound_ip_addresses", props.OutboundIPAddresses)
		d.Set("possible_outbound_ip_addresses", props.PossibleOutboundIPAddresses)
		d.Set("https_only", props.HTTPSOnly)
	}

	appSettings := flattenAppServiceAppSettings(appSettingsResp.Properties)

	d.Set("storage_connection_string", appSettings["AzureWebJobsStorage"])
	d.Set("version", appSettings["FUNCTIONS_EXTENSION_VERSION"])

	dashboard, ok := appSettings["AzureWebJobsDashboard"]
	d.Set("enable_builtin_logging", ok && dashboard != "")

	delete(appSettings, "AzureWebJobsDashboard")
	delete(appSettings, "AzureWebJobsStorage")
	delete(appSettings, "FUNCTIONS_EXTENSION_VERSION")
	delete(appSettings, "WEBSITE_CONTENTSHARE")
	delete(appSettings, "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING")

	if err := d.Set("app_settings", appSettings); err != nil {
		return fmt.Errorf("Error setting `app_settings`: %s", err)
	}

	if err := d.Set("connection_string", flattenFunctionAppConnectionStrings(connectionStringsResp.Properties)); err != nil {
		return fmt.Errorf("Error setting `connection_string`: %s", err)
	}

	authSettings := azure.FlattenAppServiceAuthSettings(authResp.SiteAuthSettingsProperties)
	if err := d.Set("auth_settings", authSettings); err != nil {
		return fmt.Errorf("Error setting `auth_settings`: %s", err)
	}

	if err = d.Set("identity", flattenFunctionAppIdentity(resp.Identity)); err != nil {
		return err
	}

	siteCred := flattenFunctionAppSiteCredential(siteCredResp.UserProperties)
	if err := d.Set("site_credential", siteCred); err != nil {
		return fmt.Errorf("Error setting `site_credential`: %s", err)
	}

	siteConfig := flattenFunctionAppSiteConfig(configResp.SiteConfig)
	if err := d.Set("site_config", siteConfig); err != nil {
		return fmt.Errorf("Error setting `site_config`: %s", err)
	}

	return tags.FlattenAndSet(d, resp.Tags)
}

func resourceArmFunctionAppSlotDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).web.AppServicesClient

	id, err := azure.ParseAzureResourceID(d.Id())
	if err != nil {
		return err
	}
	resourceGroup := id.ResourceGroup
	appServiceName := id.Path["sites"]
	slot := id.Path["slots"]

	log.Printf("[DEBUG] Deleting Slot %q (App Service %q / Resource Group %q)", slot, appServiceName, resourceGroup)

	deleteMetrics := true
	deleteEmptyServerFarm := false
	ctx := meta.(*ArmClient).StopContext
	resp, err := client.DeleteSlot(ctx, resourceGroup, appServiceName, slot, &deleteMetrics, &deleteEmptyServerFarm)
	if err != nil {
		if !utils.ResponseWasNotFound(resp) {
			return fmt.Errorf("Error deleting Slot %q (App Service %q / Resource Group %q): %s", slot, appServiceName, resourceGroup, err)
		}
	}

	return nil
}
