using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Dtos.Identity;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services.Interfaces;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.Dtos.Common;

namespace Skoruba.IdentityServer4.Admin.Api.Controllers
{
    public class BaseIdentityController<TIdentityDbContext, TUserDto, TUserDtoKey, TRoleDto, TRoleDtoKey, TUserKey, TRoleKey, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> : BaseController
        where TIdentityDbContext : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>
        where TUserDto : UserDto<TUserDtoKey>, new()
        where TRoleDto : RoleDto<TRoleDtoKey>, new()
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TRoleClaim : IdentityRoleClaim<TKey>
        where TUserToken : IdentityUserToken<TKey>
        where TRoleDtoKey : IEquatable<TRoleDtoKey>
        where TUserDtoKey : IEquatable<TUserDtoKey>
    {
        private readonly IIdentityService<TIdentityDbContext, TUserDto, TUserDtoKey, TRoleDto, TRoleDtoKey, TUserKey, TRoleKey, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> _identityService;
        private readonly IStringLocalizer<IdentityController> _localizer;

        public BaseIdentityController(IIdentityService<TIdentityDbContext, TUserDto, TUserDtoKey, TRoleDto, TRoleDtoKey, TUserKey, TRoleKey, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> identityService,
            ILogger<ConfigurationController> logger,
            IStringLocalizer<IdentityController> localizer) : base(logger)
        {
            _identityService = identityService;
            _localizer = localizer;
        }

        [HttpGet]
        [Route("/api/Identity/Role")]
        public async Task<IActionResult> Roles(int? page, string search)
        {
            var roles = await _identityService.GetRolesAsync(search, page ?? 1);

            return Success(roles);
        }

        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id}")]
        public async Task<IActionResult> Role(TRoleDtoKey id)
        {
            if (EqualityComparer<TRoleDtoKey>.Default.Equals(id, default))
            {
                return Success(new TRoleDto());
            }

            var role = await _identityService.GetRoleAsync(id.ToString());

            return Success(role);
        }

        [HttpPost]
        
        public async Task<IActionResult> Role(TRoleDto role)
        {
            if (!ModelState.IsValid)
            {
                return Success(role);
            }

            TKey roleId;

            if (EqualityComparer<TRoleDtoKey>.Default.Equals(role.Id, default))
            {
                var roleData = await _identityService.CreateRoleAsync(role);
                roleId = roleData.roleId;
            }
            else
            {
                var roleData = await _identityService.UpdateRoleAsync(role);
                roleId = roleData.roleId;
            }

            

            return Success( new { Id = roleId });
        }

        [HttpGet]
        public async Task<IActionResult> Users(int? page, string search)
        {
            var usersDto = await _identityService.GetUsersAsync(search, page ?? 1);

            return Success(usersDto);
        }

        [HttpPost]
        public async Task<IActionResult> UserProfile(TUserDto user)
        {
            if (!ModelState.IsValid)
            {
                return Success(user);
            }

            TKey userId;

            if (EqualityComparer<TUserDtoKey>.Default.Equals(user.Id, default))
            {
                var userData = await _identityService.CreateUserAsync(user);
                userId = userData.userId;
            }
            else
            {
                var userData = await _identityService.UpdateUserAsync(user);
                userId = userData.userId;
            }

            

            return Success( new { Id = userId });
        }

        [HttpGet]
        public IActionResult UserProfile()
        {
            var newUser = new TUserDto();

            return Success(newUser);
        }

        [HttpGet]
        [Route("[controller]/UserProfile/{id}")]
        public async Task<IActionResult> UserProfile(TUserDtoKey id)
        {
            var user = await _identityService.GetUserAsync(id.ToString());
            if (user == null) return NotFound();

            return Success( user);
        }

        [HttpGet]
        public async Task<IActionResult> UserRoles(TUserDtoKey id, int? page)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)) return NotFound();

            var userRoles = await _identityService.BuildUserRolesViewModel(id, page);

            return Success(userRoles);
        }

        [HttpPost]
        
        public async Task<IActionResult> UserRoles(UserRolesDto<TRoleDto, TUserDtoKey, TRoleDtoKey> role)
        {
            await _identityService.CreateUserRoleAsync(role);
            

            return Success( new { Id = role.UserId });
        }

        [HttpGet]
        public async Task<IActionResult> UserRolesDelete(TUserDtoKey id, TRoleDtoKey roleId)
        {
            await _identityService.ExistsUserAsync(id.ToString());
            await _identityService.ExistsRoleAsync(roleId.ToString());

            var userDto = await _identityService.GetUserAsync(id.ToString());
            var roles = await _identityService.GetRolesAsync();

            var rolesDto = new UserRolesDto<TRoleDto, TUserDtoKey, TRoleDtoKey>
            {
                UserId = id,
                RolesList = roles.Select(x => new SelectItem(x.Id.ToString(), x.Name)).ToList(),
                RoleId = roleId,
                UserName = userDto.UserName
            };

            return Success(rolesDto);
        }

        [HttpPost]
        
        public async Task<IActionResult> UserRolesDelete(UserRolesDto<TRoleDto, TUserDtoKey, TRoleDtoKey> role)
        {
            await _identityService.DeleteUserRoleAsync(role);
            

            return Success( new { Id = role.UserId });
        }

        [HttpPost]
        
        public async Task<IActionResult> UserClaims(UserClaimsDto<TUserDtoKey> claim)
        {
            if (!ModelState.IsValid)
            {
                return Success(claim);
            }

            await _identityService.CreateUserClaimsAsync(claim);
            

            return Success( new { Id = claim.UserId });
        }

        [HttpGet]
        public async Task<IActionResult> UserClaims(TUserDtoKey id, int? page)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)) return NotFound();

            var claims = await _identityService.GetUserClaimsAsync(id.ToString(), page ?? 1);
            claims.UserId = id;

            return Success(claims);
        }

        [HttpGet]
        public async Task<IActionResult> UserClaimsDelete(TUserDtoKey id, int claimId)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)
            || EqualityComparer<int>.Default.Equals(claimId, default)) return NotFound();

            var claim = await _identityService.GetUserClaimAsync(id.ToString(), claimId);
            if (claim == null) return NotFound();

            var userDto = await _identityService.GetUserAsync(id.ToString());
            claim.UserName = userDto.UserName;

            return Success(claim);
        }

        [HttpPost]
        
        public async Task<IActionResult> UserClaimsDelete(UserClaimsDto<TUserDtoKey> claim)
        {
            await _identityService.DeleteUserClaimsAsync(claim);
            

            return Success( new { Id = claim.UserId });
        }

        [HttpGet]
        public async Task<IActionResult> UserProviders(TUserDtoKey id)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)) return NotFound();

            var providers = await _identityService.GetUserProvidersAsync(id.ToString());

            return Success(providers);
        }

        [HttpGet]
        public async Task<IActionResult> UserProvidersDelete(TUserDtoKey id, string providerKey)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default) || string.IsNullOrEmpty(providerKey)) return NotFound();

            var provider = await _identityService.GetUserProviderAsync(id.ToString(), providerKey);
            if (provider == null) return NotFound();

            return Success(provider);
        }

        [HttpPost]
        
        public async Task<IActionResult> UserProvidersDelete(UserProviderDto<TUserDtoKey> provider)
        {
            await _identityService.DeleteUserProvidersAsync(provider);
            

            return Success( new { Id = provider.UserId });
        }

        [HttpGet]
        public async Task<IActionResult> UserChangePassword(TUserDtoKey id)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)) return NotFound();

            var user = await _identityService.GetUserAsync(id.ToString());
            var userDto = new UserChangePasswordDto<TUserDtoKey> { UserId = id, UserName = user.UserName };

            return Success(userDto);
        }

        [HttpPost]
        
        public async Task<IActionResult> UserChangePassword(UserChangePasswordDto<TUserDtoKey> userPassword)
        {
            if (!ModelState.IsValid)
            {
                return Success(userPassword);
            }

            var identityResult = await _identityService.UserChangePasswordAsync(userPassword);

            if (!identityResult.Errors.Any())
            {
                

                return Success( new { Id = userPassword.UserId });
            }

            foreach (var error in identityResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Success(userPassword);
        }

        [HttpPost]
        
        public async Task<IActionResult> RoleClaims(RoleClaimsDto<TRoleDtoKey> claim)
        {
            if (!ModelState.IsValid)
            {
                return Success(claim);
            }

            await _identityService.CreateRoleClaimsAsync(claim);
            

            return Success( new { Id = claim.RoleId });
        }

        [HttpGet]
        public async Task<IActionResult> RoleClaims(TRoleDtoKey id, int? page)
        {
            if (EqualityComparer<TRoleDtoKey>.Default.Equals(id, default)) return NotFound();

            var claims = await _identityService.GetRoleClaimsAsync(id.ToString(), page ?? 1);
            claims.RoleId = id;

            return Success(claims);
        }

        [HttpGet]
        public async Task<IActionResult> RoleClaimsDelete(TRoleDtoKey id, int claimId)
        {
            if (EqualityComparer<TRoleDtoKey>.Default.Equals(id, default) ||
                EqualityComparer<int>.Default.Equals(claimId, default)) return NotFound();

            var claim = await _identityService.GetRoleClaimAsync(id.ToString(), claimId);

            return Success(claim);
        }

        [HttpPost]
        
        public async Task<IActionResult> RoleClaimsDelete(RoleClaimsDto<TRoleDtoKey> claim)
        {
            await _identityService.DeleteRoleClaimsAsync(claim);
            

            return Success( new { Id = claim.RoleId });
        }

        [HttpGet]
        public async Task<IActionResult> RoleDelete(TRoleDtoKey id)
        {
            if (EqualityComparer<TRoleDtoKey>.Default.Equals(id, default)) return NotFound();

            var roleDto = await _identityService.GetRoleAsync(id.ToString());
            if (roleDto == null) return NotFound();

            return Success(roleDto);
        }

        [HttpPost]
        
        public async Task<IActionResult> RoleDelete(TRoleDto role)
        {
            await _identityService.DeleteRoleAsync(role);
            

            return Success(nameof(Roles));
        }

        [HttpPost]
        
        public async Task<IActionResult> UserDelete(TUserDto user)
        {
            await _identityService.DeleteUserAsync(user.Id.ToString(), user);
            

            return Success(nameof(Users));
        }

        [HttpGet]
        public async Task<IActionResult> UserDelete(TUserDtoKey id)
        {
            if (EqualityComparer<TUserDtoKey>.Default.Equals(id, default)) return NotFound();

            var user = await _identityService.GetUserAsync(id.ToString());
            if (user == null) return NotFound();

            return Success(user);
        }
    }
}