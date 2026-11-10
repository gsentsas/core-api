<?php

namespace Fleetbase\Http\Middleware;

use Fleetbase\Attributes\SkipAuthorizationCheck;
use Fleetbase\Support\Auth;
use Fleetbase\Support\ControllerResolver;
use Fleetbase\Traits\CustomMiddleware;

class AuthorizationGuard
{
    use CustomMiddleware;

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     */
    public function handle($request, \Closure $next)
    {
        $requiredPermissions = Auth::resolvePermissionsFromRequest($request);
        $user                = Auth::getUserFromSession($request);
        // A protected endpoint may resolve zero permissions if an action is
        // missing from the catalog. Zero is not an authorization grant.
        // Preserve explicit SkipAuthorizationCheck endpoints and controllers
        // for resources that are intentionally not role-guarded. Orders are
        // always guarded, including when their entire catalog disappears.
        if ($user->isNotAdmin() && !ControllerResolver::methodHasAttribute($request, SkipAuthorizationCheck::class)) {
            $controller = $request->getController();
            if (method_exists($controller, 'getResourceSingularName')) {
                $resource = Auth::getPermissionResourceFromController($controller);
                $guarded = $resource === 'order' || Auth::isResourceGuarded($resource);
                if ($guarded && $requiredPermissions->isEmpty()) {
                    return response()->authorizationError();
                }
            }
        }

        if ($user->isNotAdmin() && $requiredPermissions->isNotEmpty() && $user->doesntHavePermissions($requiredPermissions)) {
            return response()->authorizationError();
        }

        return $next($request);
    }
}
