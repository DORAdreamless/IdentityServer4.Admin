using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Helpers;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Services.Interfaces;
using Skoruba.IdentityServer4.Admin.Api.Configuration.Constants;
using Skoruba.IdentityServer4.Admin.EntityFramework.DbContexts;
using Skoruba.IdentityServer4.Admin.Api.ExceptionHandling;

namespace Skoruba.IdentityServer4.Admin.Api.Controllers
{
    [Authorize(Policy = AuthorizationConsts.AdministrationPolicy)]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    public class ConfigurationController : BaseController
    {
        private readonly IIdentityResourceService<AdminDbContext> _identityResourceService;
        private readonly IApiResourceService<AdminDbContext> _apiResourceService;
        private readonly IClientService<AdminDbContext> _clientService;
        private readonly IStringLocalizer<ConfigurationController> _localizer;

        public ConfigurationController(IIdentityResourceService<AdminDbContext> identityResourceService,
            IApiResourceService<AdminDbContext> apiResourceService,
            IClientService<AdminDbContext> clientService,
            IStringLocalizer<ConfigurationController> localizer,
            ILogger<ConfigurationController> logger)
            : base(logger)
        {
            _identityResourceService = identityResourceService;
            _apiResourceService = apiResourceService;
            _clientService = clientService;
            _localizer = localizer;
        }

        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> Client(int id)
        {
            if (id == 0)
            {
                var clientDto = _clientService.BuildClientViewModel();
                return Success(clientDto);
            }

            var client = await _clientService.GetClientAsync((int)id);
            client = _clientService.BuildClientViewModel(client);

            return Success(client);
        }

        [HttpPost]
        
        public async Task<IActionResult> Client(ClientDto client)
        {
            client = _clientService.BuildClientViewModel(client);

            if (!ModelState.IsValid)
            {
                return Success(client);
            }

            //Add new client
            if (client.Id == 0)
            {
                var clientId = await _clientService.AddClientAsync(client);
                

                return Success( new { Id = clientId });
            }

            //Update client
            await _clientService.UpdateClientAsync(client);
            

            return Success( new { client.Id });
        }

        [HttpGet]
        public async Task<IActionResult> ClientClone(int id)
        {
            if (id == 0) return NotFound();

            var clientDto = await _clientService.GetClientAsync(id);
            var client = _clientService.BuildClientCloneViewModel(id, clientDto);

            return Success(client);
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientClone(ClientCloneDto client)
        {
            if (!ModelState.IsValid)
            {
                return Success(client);
            }

            var newClientId = await _clientService.CloneClientAsync(client);
            

            return Success( new { Id = newClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientDelete(int id)
        {
            if (id == 0) return NotFound();

            var client = await _clientService.GetClientAsync(id);

            return Success(client);
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientDelete(ClientDto client)
        {
            await _clientService.RemoveClientAsync(client);

            

            return Success(nameof(Clients));
        }

        [HttpGet]
        public async Task<IActionResult> ClientClaims(int id, int? page)
        {
            if (id == 0) return NotFound();

            var claims = await _clientService.GetClientClaimsAsync(id, page ?? 1);

            return Success(claims);
        }

        [HttpGet]
        public async Task<IActionResult> ClientProperties(int id, int? page)
        {
            if (id == 0) return NotFound();

            var properties = await _clientService.GetClientPropertiesAsync(id, page ?? 1);

            return Success(properties);
        }

        [HttpGet]
        public async Task<IActionResult> ApiResourceProperties(int id, int? page)
        {
            if (id == 0) return NotFound();

            var properties = await _apiResourceService.GetApiResourcePropertiesAsync(id, page ?? 1);

            return Success(properties);
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiResourceProperties(ApiResourcePropertiesDto apiResourceProperty)
        {
            if (!ModelState.IsValid)
            {
                return Success(apiResourceProperty);
            }

            await _apiResourceService.AddApiResourcePropertyAsync(apiResourceProperty);
            

            return Success( new { Id = apiResourceProperty.ApiResourceId });
        }

        [HttpGet]
        public async Task<IActionResult> IdentityResourceProperties(int id, int? page)
        {
            if (id == 0) return NotFound();

            var properties = await _identityResourceService.GetIdentityResourcePropertiesAsync(id, page ?? 1);

            return Success(properties);
        }

        [HttpPost]
        
        public async Task<IActionResult> IdentityResourceProperties(IdentityResourcePropertiesDto identityResourceProperty)
        {
            if (!ModelState.IsValid)
            {
                return Success(identityResourceProperty);
            }

            await _identityResourceService.AddIdentityResourcePropertyAsync(identityResourceProperty);
            

            return Success( new { Id = identityResourceProperty.IdentityResourceId });
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientProperties(ClientPropertiesDto clientProperty)
        {
            if (!ModelState.IsValid)
            {
                return Success(clientProperty);
            }

            await _clientService.AddClientPropertyAsync(clientProperty);
            

            return Success( new { Id = clientProperty.ClientId });
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientClaims(ClientClaimsDto clientClaim)
        {
            if (!ModelState.IsValid)
            {
                return Success(clientClaim);
            }

            await _clientService.AddClientClaimAsync(clientClaim);
            

            return Success( new { Id = clientClaim.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientClaimDelete(int id)
        {
            if (id == 0) return NotFound();

            var clientClaim = await _clientService.GetClientClaimAsync(id);

            return Success( clientClaim);
        }

        [HttpGet]
        public async Task<IActionResult> ClientPropertyDelete(int id)
        {
            if (id == 0) return NotFound();

            var clientProperty = await _clientService.GetClientPropertyAsync(id);

            return Success( clientProperty);
        }

        [HttpGet]
        public async Task<IActionResult> ApiResourcePropertyDelete(int id)
        {
            if (id == 0) return NotFound();

            var apiResourceProperty = await _apiResourceService.GetApiResourcePropertyAsync(id);

            return Success( apiResourceProperty);
        }

        [HttpGet]
        public async Task<IActionResult> IdentityResourcePropertyDelete(int id)
        {
            if (id == 0) return NotFound();

            var identityResourceProperty = await _identityResourceService.GetIdentityResourcePropertyAsync(id);

            return Success( identityResourceProperty);
        }

        [HttpPost]
        public async Task<IActionResult> ClientClaimDelete(ClientClaimsDto clientClaim)
        {
            await _clientService.DeleteClientClaimAsync(clientClaim);
            

            return Success( new { Id = clientClaim.ClientId });
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientPropertyDelete(ClientPropertiesDto clientProperty)
        {
            await _clientService.DeleteClientPropertyAsync(clientProperty);
            

            return Success( new { Id = clientProperty.ClientId });
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiResourcePropertyDelete(ApiResourcePropertiesDto apiResourceProperty)
        {
            await _apiResourceService.DeleteApiResourcePropertyAsync(apiResourceProperty);
            

            return Success( new { Id = apiResourceProperty.ApiResourceId });
        }

        [HttpPost]
        
        public async Task<IActionResult> IdentityResourcePropertyDelete(IdentityResourcePropertiesDto identityResourceProperty)
        {
            await _identityResourceService.DeleteIdentityResourcePropertyAsync(identityResourceProperty);
            

            return Success( new { Id = identityResourceProperty.IdentityResourceId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientSecrets(int id, int? page)
        {
            if (id == 0) return NotFound();

            var clientSecrets = await _clientService.GetClientSecretsAsync(id, page ?? 1);
            _clientService.BuildClientSecretsViewModel(clientSecrets);

            return Success(clientSecrets);
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientSecrets(ClientSecretsDto clientSecret)
        {
            await _clientService.AddClientSecretAsync(clientSecret);
            

            return Success( new { Id = clientSecret.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientSecretDelete(int id)
        {
            if (id == 0) return NotFound();

            var clientSecret = await _clientService.GetClientSecretAsync(id);

            return Success( clientSecret);
        }

        [HttpPost]
        
        public async Task<IActionResult> ClientSecretDelete(ClientSecretsDto clientSecret)
        {
            await _clientService.DeleteClientSecretAsync(clientSecret);
            

            return Success( new { Id = clientSecret.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> SearchScopes(string scope, int limit = 0)
        {
            var scopes = await _clientService.GetScopesAsync(scope, limit);

            return Ok(scopes);
        }

        [HttpGet]
        public IActionResult SearchClaims(string claim, int limit = 0)
        {
            var claims = _clientService.GetStandardClaims(claim, limit);

            return Ok(claims);
        }

        [HttpGet]
        public IActionResult SearchGrantTypes(string grant, int limit = 0)
        {
            var grants = _clientService.GetGrantTypes(grant, limit);

            return Ok(grants);
        }

        [HttpGet]
        public async Task<IActionResult> Clients(int? page, string search)
        {
            return Success(await _clientService.GetClientsAsync(search, page ?? 1));
        }

        [HttpGet]
        public async Task<IActionResult> IdentityResourceDelete(int id)
        {
            if (id == 0) return NotFound();

            var identityResource = await _identityResourceService.GetIdentityResourceAsync(id);

            return Success(identityResource);
        }

        [HttpPost]
        
        public async Task<IActionResult> IdentityResourceDelete(IdentityResourceDto identityResource)
        {
            await _identityResourceService.DeleteIdentityResourceAsync(identityResource);
            

            return Success(nameof(IdentityResources));
        }

        [HttpPost]
        
        public async Task<IActionResult> IdentityResource(IdentityResourceDto identityResource)
        {
            if (!ModelState.IsValid)
            {
                return Success(identityResource);
            }

            identityResource = _identityResourceService.BuildIdentityResourceViewModel(identityResource);

            int identityResourceId;

            if (identityResource.Id == 0)
            {
                identityResourceId = await _identityResourceService.AddIdentityResourceAsync(identityResource);
            }
            else
            {
                identityResourceId = identityResource.Id;
                await _identityResourceService.UpdateIdentityResourceAsync(identityResource);
            }

            

            return Success( new { Id = identityResourceId });
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiResource(ApiResourceDto apiResource)
        {
            if (!ModelState.IsValid)
            {
                return Success(apiResource);
            }

            ComboBoxHelpers.PopulateValuesToList(apiResource.UserClaimsItems, apiResource.UserClaims);

            int apiResourceId;

            if (apiResource.Id == 0)
            {
                apiResourceId = await _apiResourceService.AddApiResourceAsync(apiResource);
            }
            else
            {
                apiResourceId = apiResource.Id;
                await _apiResourceService.UpdateApiResourceAsync(apiResource);
            }

            

            return Success( new { Id = apiResourceId });
        }

        [HttpGet]
        public async Task<IActionResult> ApiResourceDelete(int id)
        {
            if (id == 0) return NotFound();

            var apiResource = await _apiResourceService.GetApiResourceAsync(id);

            return Success(apiResource);
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiResourceDelete(ApiResourceDto apiResource)
        {
            await _apiResourceService.DeleteApiResourceAsync(apiResource);
            

            return Success(nameof(ApiResources));
        }

        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> ApiResource(int id)
        {
            if (id == 0)
            {
                var apiResourceDto = new ApiResourceDto();
                return Success(apiResourceDto);
            }

            var apiResource = await _apiResourceService.GetApiResourceAsync(id);

            return Success(apiResource);
        }

        [HttpGet]
        public async Task<IActionResult> ApiSecrets(int id, int? page)
        {
            if (id == 0) return NotFound();

            var apiSecrets = await _apiResourceService.GetApiSecretsAsync(id, page ?? 1);
            _apiResourceService.BuildApiSecretsViewModel(apiSecrets);

            return Success(apiSecrets);
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiSecrets(ApiSecretsDto apiSecret)
        {
            if (!ModelState.IsValid)
            {
                return Success(apiSecret);
            }

            await _apiResourceService.AddApiSecretAsync(apiSecret);
            

            return Success( new { Id = apiSecret.ApiResourceId });
        }

        [HttpGet]
        public async Task<IActionResult> ApiScopes(int id, int? page, int? scope)
        {
            if (id == 0 || !ModelState.IsValid) return NotFound();

            if (scope == null)
            {
                var apiScopesDto = await _apiResourceService.GetApiScopesAsync(id, page ?? 1);

                return Success(apiScopesDto);
            }
            else
            {
                var apiScopesDto = await _apiResourceService.GetApiScopeAsync(id, scope.Value);
                return Success(apiScopesDto);
            }
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiScopes(ApiScopesDto apiScope)
        {
            if (!ModelState.IsValid)
            {
                return Success(apiScope);
            }

            _apiResourceService.BuildApiScopeViewModel(apiScope);

            int apiScopeId;

            if (apiScope.ApiScopeId == 0)
            {
                apiScopeId = await _apiResourceService.AddApiScopeAsync(apiScope);
            }
            else
            {
                apiScopeId = apiScope.ApiScopeId;
                await _apiResourceService.UpdateApiScopeAsync(apiScope);
            }

            

            return Success( new { Id = apiScope.ApiResourceId, Scope = apiScopeId });
        }

        [HttpGet]
        public async Task<IActionResult> ApiScopeDelete(int id, int scope)
        {
            if (id == 0 || scope == 0) return NotFound();

            var apiScope = await _apiResourceService.GetApiScopeAsync(id, scope);

            return Success( apiScope);
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiScopeDelete(ApiScopesDto apiScope)
        {
            await _apiResourceService.DeleteApiScopeAsync(apiScope);
            

            return Success( new { Id = apiScope.ApiResourceId });
        }

        [HttpGet]
        public async Task<IActionResult> ApiResources(int? page, string search)
        {
            var apiResources = await _apiResourceService.GetApiResourcesAsync(search, page ?? 1);

            return Success(apiResources);
        }

        [HttpGet]
        public async Task<IActionResult> IdentityResources(int? page, string search)
        {
            var identityResourcesDto = await _identityResourceService.GetIdentityResourcesAsync(search, page ?? 1);

            return Success(identityResourcesDto);
        }

        [HttpGet]
        public async Task<IActionResult> ApiSecretDelete(int id)
        {
            if (id == 0) return NotFound();

            var clientSecret = await _apiResourceService.GetApiSecretAsync(id);

            return Success( clientSecret);
        }

        [HttpPost]
        
        public async Task<IActionResult> ApiSecretDelete(ApiSecretsDto apiSecret)
        {
            await _apiResourceService.DeleteApiSecretAsync(apiSecret);
            

            return Success( new { Id = apiSecret.ApiResourceId });
        }

        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> IdentityResource(int id)
        {
            if (id == 0)
            {
                var identityResourceDto = new IdentityResourceDto();
                return Success(identityResourceDto);
            }

            var identityResource = await _identityResourceService.GetIdentityResourceAsync(id);

            return Success(identityResource);
        }
    }
}