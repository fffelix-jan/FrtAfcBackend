using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace FrtAfcBackend
{
    /// <summary>
    /// Authorization filter that checks if user has required permissions
    /// </summary>
    public class RequirePermissionAttribute : Attribute, IAuthorizationFilter
    {
        private readonly ApiPermissions _requiredPermission;
        private readonly bool _requireAll;

        public RequirePermissionAttribute(ApiPermissions requiredPermission, bool requireAll = true)
        {
            _requiredPermission = requiredPermission;
            _requireAll = requireAll;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;

            // Check if user is authenticated
            if (!user.Identity?.IsAuthenticated ?? true)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // Get user permissions from claims
            var permissionsClaim = user.FindFirst("UserPermissions");
            if (permissionsClaim == null || !int.TryParse(permissionsClaim.Value, out var userPermissions))
            {
                context.Result = new ForbidResult("User permissions not found");
                return;
            }

            // Check permissions
            bool hasPermission = _requireAll 
                ? PermissionHelper.HasPermission(userPermissions, _requiredPermission)
                : PermissionHelper.HasAnyPermission(userPermissions, _requiredPermission);

            if (!hasPermission)
            {
                var requiredPerms = PermissionHelper.GetPermissionNames((int)_requiredPermission);
                var userPerms = PermissionHelper.GetPermissionNames(userPermissions);
                
                context.Result = new ObjectResult(new
                {
                    error = "Insufficient permissions",
                    required = requiredPerms,
                    userHas = userPerms,
                    message = $"This operation requires: {string.Join(", ", requiredPerms)}"
                })
                {
                    StatusCode = 403
                };
            }
        }
    }

    /// <summary>
    /// Base controller with permission checking helpers
    /// </summary>
    public abstract class PermissionControllerBase : ControllerBase
    {
        protected int GetUserPermissions()
        {
            var claim = User.FindFirst("UserPermissions");
            return claim != null && int.TryParse(claim.Value, out var permissions) ? permissions : 0;
        }

        protected bool HasPermission(ApiPermissions permission)
        {
            return PermissionHelper.HasPermission(GetUserPermissions(), permission);
        }

        protected bool HasAnyPermission(params ApiPermissions[] permissions)
        {
            return PermissionHelper.HasAnyPermission(GetUserPermissions(), permissions);
        }

        protected string GetUsername()
        {
            return User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
        }

        protected int GetUserId()
        {
            var claim = User.FindFirst("UserId");
            return claim != null && int.TryParse(claim.Value, out var userId) ? userId : 0;
        }
    }
}