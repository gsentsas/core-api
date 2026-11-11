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
        // Every resource controller behind fleetbase.protected is
        // permission-guarded by default. A missing/incomplete catalog must
        // never silently turn a resource route into an open endpoint.
        // Only an explicit method-level SkipAuthorizationCheck is exempt.
        // Controllers without a resource contract retain their existing
        // behavior until they can be classified and audited separately.
        if ($user->isNotAdmin() && $requiredPermissions->isEmpty()) {
            $controller = $request->getController();
            if (method_exists($controller, 'getResourceSingularName')
                && !ControllerResolver::methodHasAttribute($request, SkipAuthorizationCheck::class)) {
                return response()->authorizationError();
            }
        }

        if ($user->isNotAdmin() && $requiredPermissions->isNotEmpty() && $user->doesntHavePermissions($requiredPermissions)) {
            return response()->authorizationError();
        }

        return $next($request);
    }
}
