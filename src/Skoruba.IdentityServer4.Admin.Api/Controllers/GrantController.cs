using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Dtos.Grant;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services.Interfaces;
using Skoruba.IdentityServer4.Admin.Api.ExceptionHandling;
using Skoruba.IdentityServer4.Admin.Api.Helpers;
using Skoruba.IdentityServer4.Admin.Api.Configuration.Constants;
using Skoruba.IdentityServer4.Admin.EntityFramework.DbContexts;
using Skoruba.IdentityServer4.Admin.EntityFramework.Identity.Entities.Identity;

namespace Skoruba.IdentityServer4.Admin.Api.Controllers
{
    [Authorize(Policy = AuthorizationConsts.AdministrationPolicy)]
    public class GrantController : BaseController
    {
        private readonly IPersistedGrantAspNetIdentityService<AdminDbContext, UserIdentity, UserIdentityRole, string, UserIdentityUserClaim, UserIdentityUserRole, UserIdentityUserLogin, UserIdentityRoleClaim, UserIdentityUserToken> _persistedGrantService;
        private readonly IStringLocalizer<GrantController> _localizer;

        public GrantController(IPersistedGrantAspNetIdentityService<AdminDbContext, UserIdentity, UserIdentityRole, string, UserIdentityUserClaim, UserIdentityUserRole, UserIdentityUserLogin, UserIdentityRoleClaim, UserIdentityUserToken> persistedGrantService,
            ILogger<ConfigurationController> logger,
            IStringLocalizer<GrantController> localizer) : base(logger)
        {
            _persistedGrantService = persistedGrantService;
            _localizer = localizer;
        }

        [HttpGet]
        public async Task<IActionResult> PersistedGrants(int? page, string search)
        {
            var persistedGrants = await _persistedGrantService.GetPersitedGrantsByUsers(search, page ?? 1);

            return Success(persistedGrants);
        }

        [HttpGet]
        public async Task<IActionResult> PersistedGrantDelete(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var grant = await _persistedGrantService.GetPersitedGrantAsync(UrlHelpers.QueryStringUnSafeHash(id));
            if (grant == null) return NotFound();

            return Success(grant);
        }


        [HttpPost]
        public async Task<IActionResult> PersistedGrantDelete(PersistedGrantDto grant)
        {
            await _persistedGrantService.DeletePersistedGrantAsync(grant.Key);

            

            return Success();
        }

        [HttpPost]
        public async Task<IActionResult> PersistedGrantsDelete(PersistedGrantsDto grants)
        {
            await _persistedGrantService.DeletePersistedGrantsAsync(grants.SubjectId);

            

            return Success();
        }


        [HttpGet]
        public async Task<IActionResult> PersistedGrant(string id, int? page)
        {
            var persistedGrants = await _persistedGrantService.GetPersitedGrantsByUser(id, page ?? 1);
            persistedGrants.SubjectId = id;

            return Success(persistedGrants);
        }
    }
}